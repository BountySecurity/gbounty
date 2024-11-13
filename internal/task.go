package scan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/match"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/logger"
	"github.com/bountysecurity/gbounty/kit/panics"
	"github.com/bountysecurity/gbounty/kit/strings/occurrence"
)

// Task is an atomic unit of work within a `scan`, which is what composes a [Template].
type Task struct {
	// IsBase is true if the task is a base task.
	// In such case, the task is not associated to a profile.
	// Thus, does not have a step nor a payload, nor an entrypoint.
	IsBase bool

	// Profile is the profile associated with the task. If defined, always as profile.ActiveProfile.
	Profile *profile.Active
	// StepIdx is the index of the step within the Profile steps the task is at.
	StepIdx int
	// PayloadIdx is the index of the payload within the Profile payloads the task is associated to.
	// It is equal to -1 when it is profile.RawRequestV2, or it is not associated to any Profile.
	PayloadIdx int

	Requests    []*request.Request
	Responses   []*response.Response
	Occurrences [][]occurrence.Occurrence
	Performed   bool
	Match       bool
	Error       error

	// LoW is an internal reference to the LineOfWork
	// it belongs to. It must be non-nil.
	LoW *LineOfWork
	// EntrypointIdx is the index of the entrypoint within the LineOfWork entrypoints the task is associated to.
	// It is equal to -1 when it is not associated to any LineOfWork entrypoint. If so, use Entrypoint instead.
	EntrypointIdx int
	// Entrypoint is an entrypoint.Entrypoint not included within the LineOfWork entrypoints.
	// Only used when it is not associated to any LineOfWork entrypoint. By the default, use EntrypointIdx.
	Entrypoint entrypoint.Entrypoint
}

func (t *Task) matchId() string {
	return fmt.Sprintf("%s/%d/%d", t.Profile.Name, t.StepIdx, t.EntrypointIdx)
}

func (t *Task) clone() *Task {
	requests := make([]*request.Request, len(t.Requests))
	copy(requests, t.Requests)

	responses := make([]*response.Response, len(t.Responses))
	copy(responses, t.Responses)

	occurrences := make([][]occurrence.Occurrence, 0, len(t.Occurrences))
	for _, occ := range t.Occurrences {
		occurrences = append(occurrences, append([]occurrence.Occurrence{}, occ...))
	}

	return &Task{
		IsBase:        t.IsBase,
		Profile:       t.Profile,
		StepIdx:       t.StepIdx,
		PayloadIdx:    t.PayloadIdx,
		Requests:      requests,
		Responses:     responses,
		Occurrences:   occurrences,
		Performed:     t.Performed,
		Match:         t.Match,
		Error:         t.Error,
		LoW:           t.LoW,
		EntrypointIdx: t.EntrypointIdx,
		Entrypoint:    t.Entrypoint,
	}
}

func (t *Task) payloadEncoded() string {
	_, payload, _ := t.Profile.Steps[t.StepIdx].PayloadAtEncoded(t.PayloadIdx)

	return payload
}

func (t *Task) payloadDecoded() string {
	_, payload, _ := t.Profile.Steps[t.StepIdx].PayloadAt(t.PayloadIdx)

	return payload
}

//nolint:nolintlint,gocyclo
func (t *Task) run(
	ctx context.Context,
	tpl Template,
	reqBuilder RequesterBuilder,
	bhPoller BlindHostPoller,
	onRequestsScheduled, onRequestsSkipped func(int),
	onMatchFn onMatchFunc,
	onErrorFn onErrorFunc,
	onTaskFn onTaskFunc,
	onUpdate func(bool, bool, bool),
	saveAllRequests, saveResponses, saveAllResponses bool,
	baseModifiers []Modifier,
	passiveReqProfiles []*profile.Request,
	passiveResProfiles []*profile.Response,
	customTokens CustomTokens,
	payloadStrategy PayloadStrategy,
) {
	// Do we really need to run the task? Eventually, a task could be "skipped" because
	// there's already an equivalent match (same profile, step and entrypoint) with a
	// different payload. It depends on the PayloadStrategy given.
	if payloadStrategy.IsOnlyOnce() && t.LoW.isThereAnyEquivalentMatch(t.matchId()) {
		logger.For(ctx).Infof(
			"Skipping task, payload strategy is 'only_once' and we already found an equivalent match: %s",
			t.matchId(),
		)
		onRequestsSkipped(1)
		return
	}

	// If it is a base task, we run the base task.
	// Base tasks only perform passive scans on request & response,
	// so there's no much to do beyond running the passive scans.
	if t.IsBase {
		t.runBase(ctx, tpl, onMatchFn, onUpdate, passiveReqProfiles, passiveResProfiles, customTokens)
		return
	}

	// Otherwise, we run the corresponding step.
	req, res, isMatch, occ, err := t.runStep(ctx, tpl, reqBuilder, bhPoller, baseModifiers, onMatchFn, onUpdate, passiveReqProfiles, passiveResProfiles, customTokens)
	if err != nil {
		// If the step failed, we log the error.
		// However, we log it as .Warn because a failed step is not necessarily an execution error.
		// If the step failed because of a manual interruption, we log it as .Debug.
		var log = logger.For(ctx).Warnf
		if errors.Is(err, ErrManuallyInterrupted) {
			log = logger.For(ctx).Debugf
		}
		log(
			"Step failed: step %d out of %d, method=%s, host=%s, path=%s, err=%s",
			t.StepIdx, len(t.Profile.Steps), req.Method, req.URL, req.Path, err,
		)
	}

	// In case of match, we report it to the LineOfWork (see PayloadStrategy)
	if payloadStrategy.IsOnlyOnce() && isMatch {
		logger.For(ctx).Infof(
			"Registering match (for future equivalents): profile=%s, stepIdx=%d, entrypointIdx=%d, payloadIdx=%d",
			t.Profile.Name, t.StepIdx, t.EntrypointIdx, t.PayloadIdx,
		)
		t.LoW.registerMatch(t.matchId())
	}

	// We update the task with the request & response, depending on the result.
	if (saveAllRequests || saveAllResponses) || isMatch || err != nil {
		if saveAllRequests || isMatch || err != nil {
			t.Requests = append(t.Requests, &req)
		}

		if saveAllResponses || ((isMatch || err != nil) && saveResponses) {
			t.Responses = append(t.Responses, &res)
			t.Occurrences = append(t.Occurrences, occ)
		}
	}
	t.Performed = true
	t.Match = isMatch
	t.Error = err

	var matched bool

	// Finally, we act according to the results of the step execution.
	switch {
	// The current step is a match:
	// - We report the match if it's marked to be shown.
	// - We schedule the next step if there are more steps to take.
	case err == nil && isMatch:
		//nolint:godox
		// We only report the issue if it's marked to be shown.
		// TODO: Handle only once per domain
		// TODO: Use 'show_alert' for passive profiles
		if t.Profile.Steps[t.StepIdx].ShowAlert.Enabled() {
			matched = true
			onUpdate(true, false, false) // Report the match, the request will be reported later.
			if onMatchFn != nil {
				onMatchFn(ctx, tpl.OriginalURL, t.Requests, t.Responses, t.Profile, t.Profile.Steps[t.StepIdx], entrypoint.Entrypoint(nil), t.payloadEncoded(), t.Occurrences)
			}
		}

		// If there are more steps to take, we schedule them:
		if t.StepIdx < len(t.Profile.Steps)-1 {
			t.scheduleNextStep(ctx, onRequestsScheduled)
		}
	// The current step isn't a match:
	// - We do nothing. Nothing to report, nor to schedule.
	case err == nil && !isMatch:
	// The current step is an error:
	// - We report the error.
	case err != nil:
		if onErrorFn != nil {
			onErrorFn(ctx, tpl.OriginalURL, t.Requests, t.Responses, err)
		}
	// There shouldn't exist any other scenario, if so, we just panic.
	// In the worst case, it will be caught and reported by the runner.
	default:
		logger.For(ctx).Errorf("Unknown status after step execution: step %d of %d, isMatch=%t, err=%s", t.StepIdx, len(t.Profile.Steps), isMatch, err)
		panic("scan: unknown status after step execution")
	}

	// We report the request, either successful or not.
	onUpdate(false, err == nil, err != nil)

	// If there's no more requests to do:
	// - isMatch and last step (matched!)
	// - !isMatch (don't continue)
	// - err != nil (failed)
	if (matched || !isMatch || err != nil) && onTaskFn != nil {
		onTaskFn(ctx, tpl.OriginalURL, t.Requests, t.Responses)
	}
}

func (t *Task) runBase(
	ctx context.Context,
	tpl Template,
	onMatchFn onMatchFunc,
	onUpdate func(bool, bool, bool),
	passiveReqProfiles []*profile.Request,
	passiveResProfiles []*profile.Response,
	customTokens CustomTokens,
) {
	// We prepare a [sync.WaitGroup] to wait for the passive scans to finish.
	wg := new(sync.WaitGroup)

	// Then, we trigger the passive request scan.
	// Only when the request is non-empty.
	if !tpl.Request.IsEmpty() {
		wg.Add(1)
		notifyReqMatch := func(prof *profile.Request, occ []occurrence.Occurrence) {
			onUpdate(true, false, false)
			if onMatchFn != nil {
				onMatchFn(ctx, tpl.OriginalURL, []*request.Request{&tpl.Request}, nil, prof, prof, nil, "", [][]occurrence.Occurrence{occ})
			}
		}
		go func() {
			defer panics.Log(ctx)
			defer wg.Done()
			passiveRequestScan(ctx, passiveReqProfiles, &tpl.Request, notifyReqMatch, customTokens)
		}()
	}

	// And, we trigger the passive response scan.
	// Only when the response is non-empty.
	if tpl.Response != nil && !tpl.Response.IsEmpty() {
		wg.Add(1)
		notifyResMatch := func(prof *profile.Response, occ []occurrence.Occurrence) {
			var reqs []*request.Request
			if !tpl.Request.IsEmpty() {
				reqs = []*request.Request{&tpl.Request}
			}

			onUpdate(true, false, false)
			if onMatchFn != nil {
				onMatchFn(ctx, tpl.OriginalURL, reqs, []*response.Response{tpl.Response}, prof, prof, nil, "", [][]occurrence.Occurrence{occ})
			}
		}
		go func() {
			defer panics.Log(ctx)
			defer wg.Done()
			passiveResponseScan(ctx, passiveResProfiles, &tpl.Request, tpl.Response, notifyResMatch, customTokens)
		}()
	}

	// Before returning, we wait for both passive scans to finish.
	wg.Wait()
}

func (t *Task) runStep(
	ctx context.Context,
	tpl Template,
	reqBuilder RequesterBuilder,
	bhPoller BlindHostPoller,
	baseModifiers []Modifier,
	onMatchFn onMatchFunc,
	onUpdate func(bool, bool, bool),
	passiveReqProfiles []*profile.Request,
	passiveResProfiles []*profile.Response,
	customTokens CustomTokens,
) (injectedReq request.Request, res response.Response, isMatch bool, occ []occurrence.Occurrence, err error) {
	// We prepare a [sync.WaitGroup] to wait for the passive scans to finish.
	wg := new(sync.WaitGroup)
	//

	step := t.Profile.Steps[t.StepIdx]
	ep := t.Entrypoint

	switch {
	// If the current step is a raw request, we just use the raw
	// request from the step definition.
	case step.RequestType.RawRequest():
		injectedReq = rawRequestFromStep(tpl, step)

	// Otherwise, we inject the payload to the entrypoint, which might be
	// - the entrypoint attached to the task
	// - the entrypoint referred from the LineOfWork
	default:
		if ep == nil {
			ep = t.LoW.Entrypoints[t.EntrypointIdx]
		}

		injectedReq = ep.InjectPayload(
			tpl.Request,
			step.PayloadPosition,
			t.payloadEncoded(),
		)
	}

	// Now, we prepare the modifiers, and modify the injected request
	// accordingly. This makes it possible to customize the template clone.
	modifiers := setUpModifiers(baseModifiers, ep)
	for _, modifier := range modifiers {
		injectedReq = modifier.Modify(&step, tpl, injectedReq)
	}

	// Finally, we set the redirection details into the injected request,
	// and we start the active scan.
	injectedReq.RedirectType = step.RedirectType()
	injectedReq.MaxRedirects = step.MaxRedirects()

	// We trigger the passive request scan.
	{
		wg.Add(1)
		notifyReqMatch := func(prof *profile.Request, occ []occurrence.Occurrence) {
			onUpdate(true, false, false)
			if onMatchFn != nil {
				onMatchFn(ctx, tpl.OriginalURL, []*request.Request{&injectedReq}, nil, prof, prof, nil, "", [][]occurrence.Occurrence{occ})
			}
		}
		go func() {
			defer panics.Log(ctx)
			defer wg.Done()
			passiveRequestScan(ctx, passiveReqProfiles, &injectedReq, notifyReqMatch, customTokens)
		}()
	}

	req := injectedReq.Clone()
	for shouldFollowRedirect(ctx, &req, &res) {
		if err != nil {
			return
		}

		var requester Requester
		if requester, err = reqBuilder(&req); err != nil {
			return
		}

		res, err = requester.Do(ctx, &req)
		if errors.Is(err, context.Canceled) {
			return
		}

		isMatch, occ = isActiveMatch(ctx, t, step, req, res, bhPoller, customTokens)
		if isMatch {
			break
		}
	}

	// We trigger the passive response scan.
	{
		wg.Add(1)
		notifyResMatch := func(prof *profile.Response, occ []occurrence.Occurrence) {
			onUpdate(true, false, false)
			if onMatchFn != nil {
				onMatchFn(ctx, tpl.OriginalURL, []*request.Request{&req}, []*response.Response{&res}, prof, prof, nil, "", [][]occurrence.Occurrence{occ})
			}
		}
		go func() {
			defer panics.Log(ctx)
			defer wg.Done()
			passiveResponseScan(ctx, passiveResProfiles, &req, &res, notifyResMatch, customTokens)
		}()
	}

	// Before returning, we wait for both passive scans to finish.
	wg.Wait()

	return
}

func (t *Task) scheduleNextStep(ctx context.Context, onRequestsScheduled func(int)) {
	next := t.Profile.Steps[t.StepIdx+1]

	if next.InsertionPoint.Same() {
		t.scheduleNextStepSame(ctx, next, onRequestsScheduled)
	} else {
		t.scheduleNextStepAny(ctx, next, onRequestsScheduled)
	}
}

func (t *Task) scheduleNextStepSame(ctx context.Context, s profile.Step, onRequestsScheduled func(int)) {
	tt := t.clone()
	tt.StepIdx++

	var scheduled int
	for pIdx := range s.Payloads {
		enabled, _, err := s.PayloadAt(pIdx)
		if err != nil {
			logger.For(ctx).Errorf(
				"Error while parsing payload (idx=%d) from step (idx=%d) from profile (name=%s): %s",
				pIdx, tt.StepIdx, t.Profile.Name, err.Error(),
			)
			continue
		}

		if !enabled {
			logger.For(ctx).Debugf(
				"Payload (idx=%d) from step (idx=%d) from profile (name=%s) is disabled",
				pIdx, tt.StepIdx, t.Profile.Name,
			)
			continue
		}

		newT := tt.clone()
		newT.PayloadIdx = pIdx

		scheduled++
		t.LoW.Tasks = append(t.LoW.Tasks, newT)
	}

	onRequestsScheduled(scheduled)
}

func (t *Task) scheduleNextStepAny(ctx context.Context, s profile.Step, onRequestsScheduled func(int)) {
	tt := t.clone()
	tt.StepIdx++

	var scheduled int
	for pIdx := range s.Payloads {
		enabled, _, err := s.PayloadAt(pIdx)
		if err != nil {
			logger.For(ctx).Errorf(
				"Error while parsing payload (idx=%d) from step (idx=%d) from profile (name=%s): %s",
				pIdx, tt.StepIdx, t.Profile.Name, err.Error(),
			)
			continue
		}

		if !enabled {
			logger.For(ctx).Debugf(
				"Payload (idx=%d) from step (idx=%d) from profile (name=%s) is disabled",
				pIdx, tt.StepIdx, t.Profile.Name,
			)
			continue
		}

		for idx, ep := range t.LoW.Entrypoints {
			if s.InsertionPointEnabled(ep.InsertionPointType(), t.LoW.Template.Method) {
				newT := tt.clone()
				newT.PayloadIdx = pIdx
				newT.EntrypointIdx = idx

				scheduled++
				t.LoW.Tasks = append(t.LoW.Tasks, newT)
			}
		}

		for _, ep := range entrypoint.From(s) {
			newT := tt.clone()
			newT.PayloadIdx = pIdx
			newT.Entrypoint = ep
			newT.EntrypointIdx = -1

			scheduled++
			t.LoW.Tasks = append(t.LoW.Tasks, newT)
		}
	}

	onRequestsScheduled(scheduled)
}

func (t *Task) reset() {
	t.Requests = nil
	t.Responses = nil
	t.Performed = false
	t.Match = false
	t.Error = nil
}

func setUpModifiers(baseModifiers []Modifier, entrypoint entrypoint.Entrypoint) []Modifier {
	modifiers := make([]Modifier, 0, len(baseModifiers))

	for _, modifier := range baseModifiers {
		c, ok := modifier.(Customizable)
		if !ok || entrypoint == nil {
			modifiers = append(modifiers, modifier)

			continue
		}

		c.Customize(entrypoint)

		m, ok := c.(Modifier)
		if ok {
			modifiers = append(modifiers, m)
		}
	}

	return modifiers
}

// isActiveMatch returns whether the active profile associated to the task
// has a configured matcher that reports positive (a match).
func isActiveMatch(ctx context.Context, task *Task, step profile.Step, req request.Request, res response.Response, bhPoller BlindHostPoller, customTokens CustomTokens) (bool, []occurrence.Occurrence) {
	payload := applyReplacements(task.payloadEncoded(), req.Modifications)
	payloadEncode := applyReplacements(task.payloadDecoded(), req.Modifications)

	var (
		isMatch, isInteraction bool
		occ                    = make([]occurrence.Occurrence, 0)
		wg                     = &sync.WaitGroup{}
	)

	wg.Add(1)
	go func() {
		defer wg.Done()
		isMatch, occ = match.Match(
			ctx,
			match.Data{
				Profile:       task.Profile,
				Step:          step,
				Payload:       &payload,
				PayloadDecode: &payloadEncode,
				Original:      &task.LoW.Template.Request,
				Request:       &req,
				Response:      &res,
				CustomTokens:  customTokens,
			},
		)
	}()

	if req.UID != "" && step.HasBHGrepType() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ch := make(chan bool, 1)

			// We wait up to 5 seconds waiting for interactions
			const maxWait = 5 * time.Second
			timer := time.NewTimer(maxWait)
			defer timer.Stop()

			// We look for interactions every 500ms
			const frequency = 500 * time.Millisecond
			ticker := time.NewTicker(frequency)
			defer ticker.Stop()

			for tick := ticker.C; ; {
				select {
				case <-ctx.Done():
					return
				case <-timer.C:
					return
				case <-tick:
					tick = nil
					go func() { ch <- bhPoller.Search(req.UID) != nil }()
				case v := <-ch:
					if v {
						isInteraction = true
						return
					}
					tick = ticker.C
				}
			}
		}()
	}

	wg.Wait()
	return isMatch || isInteraction, occ
}

func applyReplacements(payload string, replacements map[string]string) string {
	for label, replacement := range replacements {
		payload = strings.ReplaceAll(payload, label, replacement)
	}

	return payload
}
