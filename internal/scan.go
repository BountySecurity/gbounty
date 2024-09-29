package scan

import (
	"context"
	stdurl "net/url"
	"strings"
	"sync"
	"time"

	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/platform/metrics"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/logger"
	"github.com/bountysecurity/gbounty/kit/panics"
	"github.com/bountysecurity/gbounty/kit/syncutil"
)

// LineOfWork is the aggregation for all the Task, for a given Template.
// In other words:
// - There is a LineOfWork for each request to be scanned:
//   - For which we identify all the Entrypoints,
//   - and combine with profile.Profile, to generate all starting possible combinations:
//   - For every combination of entrypoint.Entrypoint (see Task.EntrypointIdx)
//   - with every payload (see Task.PayloadIdx).
//     [Rough estimate: #profiles x #payloads x #entrypoints]
//
// =
//   - Then, during the execution of the scan, more Task can be created, because
//     one Task can be forked into more than one (for each step). So, every Task
//     represents a path of steps, where every other step (except the current)
//     did match.
type LineOfWork struct {
	Template    Template
	Entrypoints []entrypoint.Entrypoint
	Tasks       []*Task

	sync.RWMutex
	Matches map[string]struct{}
}

func (low *LineOfWork) appendEntrypoints(entrypoints []entrypoint.Entrypoint) {
	low.Entrypoints = append(low.Entrypoints, entrypoints...)
}

func (low *LineOfWork) registerMatch(matchId string) {
	low.Lock()
	defer low.Unlock()
	low.Matches[matchId] = struct{}{}
}

func (low *LineOfWork) isThereAnyEquivalentMatch(matchId string) bool {
	low.RLock()
	defer low.RUnlock()
	_, ok := low.Matches[matchId]
	return ok
}

// Consider: Moving these labels to the to `scan`  package (entrypoints might be independent of the label itself).
const (
	bhLabel     = "{BH}"
	ihLabel     = "{IH}"
	legacyLabel = "{BC}"
	emailLabel  = "{EMAIL}"
)

func (low *LineOfWork) prepareTasks(
	ctx context.Context,
	prof *profile.Active,
	blindHostDefined bool,
	emailAddressDefined bool,
) (totalTasks int, skipped bool) {
	// We first check if the profile should be skipped.
	// For instance, in case any of its steps is a raw request that contains an undefined label.
	if profileShouldBeSkipped(ctx, prof, blindHostDefined, emailAddressDefined) {
		return 0, true
	}

	// At this point, there must always be at least one step.
	// Otherwise, the profile is invalid. So, it should be validated before reaching this point.
	const sIdx = 0
	step := prof.Steps[sIdx]

	// If it is a raw request, then we just add one task.
	if step.RequestType.RawRequest() {
		low.Tasks = append(low.Tasks, &Task{Profile: prof, StepIdx: sIdx, PayloadIdx: -1, LoW: low})
		return 1, false
	}

	// Otherwise, there'll be one for each payload in the first step of the profile,
	// and for each LineOfWork entrypoint, plus the ones entrypoint.From step.
	stepEntrypoints := entrypoint.From(step)

	for pIdx := range step.Payloads {
		enabled, payload, err := step.PayloadAt(pIdx)
		if err != nil {
			logger.For(ctx).Errorf(
				"Error while parsing payload (idx=%d) from step (idx=%d) from profile (name=%s): %s",
				pIdx, sIdx, prof.Name, err.Error(),
			)
			continue
		}

		if !enabled {
			logger.For(ctx).Debugf(
				"Payload (idx=%d) from step (idx=%d) from profile (name=%s) is disabled",
				pIdx, sIdx, prof.Name,
			)
			continue
		}

		if ((strings.Contains(payload, bhLabel) || strings.Contains(payload, ihLabel) || strings.Contains(payload, legacyLabel)) && !blindHostDefined) ||
			(strings.Contains(payload, emailLabel) && !emailAddressDefined) {
			skipped = true
			continue // Skipping
		}

		for idx, ep := range low.Entrypoints {
			if step.InsertionPointEnabled(ep.InsertionPointType(), low.Template.Method) {
				totalTasks++
				low.Tasks = append(low.Tasks, &Task{Profile: prof, StepIdx: sIdx, PayloadIdx: pIdx, LoW: low, EntrypointIdx: idx})
			}
		}

		for _, ep := range stepEntrypoints {
			totalTasks++
			low.Tasks = append(low.Tasks, &Task{Profile: prof, StepIdx: sIdx, PayloadIdx: pIdx, LoW: low, Entrypoint: ep})
		}
	}

	return totalTasks, skipped
}

// profileShouldBeSkipped checks if the profile should be skipped.
// Conditions checked:
// - Any step is a raw request that contains an undefined label ({IH}, {BC}, {EMAIL}).
func profileShouldBeSkipped(
	_ context.Context,
	prof *profile.Active,
	blindHostDefined bool,
	emailAddressDefined bool,
) bool {
	// Any step is a raw request that contains an undefined label ({IH}, {BC}, {EMAIL}).
	for _, step := range prof.Steps {
		if step.RequestType.RawRequest() {
			if ((strings.Contains(step.RawRequest, bhLabel) || strings.Contains(step.RawRequest, ihLabel) || strings.Contains(step.RawRequest, legacyLabel)) && !blindHostDefined) ||
				(strings.Contains(step.RawRequest, emailLabel) && !emailAddressDefined) {
				return true // Skipping
			}
		}
	}

	return false
}

//nolint:nolintlint,gocyclo
func (low *LineOfWork) executeTasks(
	ctx context.Context,
	fn RequesterBuilder,
	bhPoller BlindHostPoller,
	onRequestsScheduled, onRequestsSkipped func(int),
	onUpdate func(bool, bool, bool),
	onErrorFn onErrorFunc,
	onMatchFn onMatchFunc,
	onTaskFn onTaskFunc,
	rps int,
	saveAllRequests, saveResponses, saveAllResponses bool,
	baseModifiers []Modifier,
	passiveReqProfiles []*profile.Request,
	passiveResProfiles []*profile.Response,
	customTokens CustomTokens,
	payloadStrategy PayloadStrategy,
) {
	// We set the throttle to the desired rate of requests per second.
	// It is important to prevent flooding the endpoint.
	throttle := time.NewTicker(time.Duration(1e6/(rps)) * time.Microsecond) //nolint:mnd
	defer throttle.Stop()

	var (
		wg   = syncutil.NewWaitGroupWithCount()
		from int
	)

	for {
		if from > len(low.Tasks) {
			panic("How is it possible?")
		}
		// If we reached the end of the list of tasks
		// and no one is running, we can stop.
		// Otherwise, we need to pause for a bit.
		if from == len(low.Tasks) {
			if wg.Count() == 0 {
				break
			}
			const shortPause = 10 * time.Millisecond
			time.Sleep(shortPause)
			continue
		}

		task := low.Tasks[from]
		wg.Add(1)
		from++

		go func() {
			// Prevent any panic caused during the task execution
			// from escalating outside the goroutine.
			defer panics.Log(ctx)

			// Make sure that the task is marked as done,
			// whatever that causes it to finish.
			defer wg.Done()

			// Before starting the task execution,
			// we double-check the context cancellation.
			// If the context has already been cancelled,
			// then we prevent the execution even from starting.
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Wait for the throttle to allow the task to be executed.
			// This is a blocking operation, and what ensure an approximate
			// rate of max(rps) requests per second.
			//
			// If the context is cancelled while waiting, then again
			// we prevent the task execution even from starting.
			select {
			case <-throttle.C:
			case <-ctx.Done():
				return
			}

			// Account the number of concurrent tasks.
			// We only account them once reached the throttle.
			metrics.OngoingTasks.Inc()
			defer func() { metrics.OngoingTasks.Dec() }()

			// Finally, we actually trigger the task execution.
			// Which might be either a base request, or an injected request.
			task.run(
				ctx,
				low.Template,
				fn,
				bhPoller,
				onRequestsScheduled,
				onRequestsSkipped,
				onMatchFn,
				onErrorFn,
				onTaskFn,
				onUpdate,
				saveAllRequests,
				saveResponses,
				saveAllResponses,
				baseModifiers,
				passiveReqProfiles,
				passiveResProfiles,
				customTokens,
				payloadStrategy,
			)
		}()
	}

	wg.Wait()
}

func (low *LineOfWork) reset() {
	for _, task := range low.Tasks {
		task.reset()
	}
}

func (low *LineOfWork) numOfMatches() (n int) {
	for _, t := range low.Tasks {
		if t.Match {
			n++
		}
	}

	return
}

func (low *LineOfWork) numOfFailedTasks() (n int) {
	for _, t := range low.Tasks {
		if t.Error != nil && t.Performed {
			n++
		}
	}

	return
}

func (low *LineOfWork) numOfSucceedTasks() (n int) {
	for _, t := range low.Tasks {
		if t.Error == nil && t.Performed {
			n++
		}
	}

	return
}

func shouldFollowRedirect(ctx context.Context, req *request.Request, res *response.Response) bool {
	if ctx.Err() != nil {
		return false
	}

	// Initial request is always true
	if req.FollowedRedirects == 0 {
		req.FollowedRedirects++
		return true
	}

	loc := res.Location()

	// Three conditions needs to be satisfied
	shouldFollowRedirect := statusCodeRedirect(res.Code) &&
		req.FollowedRedirects < req.MaxRedirects &&
		redirectTypeActive(req.RedirectType, loc)

	if !shouldFollowRedirect {
		return false
	}

	req.FollowedRedirects++

	if strings.HasPrefix(loc, "/") {
		req.Path = loc
		return true
	}

	if !strings.Contains(loc, "://") {
		loc = "http://" + loc
	}

	req.URL = loc
	req.Path = ""

	u, err := stdurl.ParseRequestURI(loc)
	if err != nil {
		logger.For(ctx).Errorf("Error while parsing request uri: %s", err)
	}

	if u != nil {
		req.Headers["Host"] = []string{u.Host}
	}

	return true
}

func statusCodeRedirect(statusCode int) bool {
	return statusCode >= 300 && statusCode < 400
}

func redirectTypeActive(redirectType profile.Redirect, location string) bool {
	return redirectType.Always() ||
		(redirectType.OnSite() && strings.HasPrefix(location, "/"))
}

func rawRequestFromStep(tpl Template, step profile.Step) request.Request {
	req, err := request.ParseRequest([]byte(step.RawRequest), tpl.URL)
	if err != nil {
		return request.Request{}
	}

	req.URL = tpl.URL

	return req
}
