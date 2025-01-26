package match

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/BountySecurity/gbounty/kit/logger"
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
	"github.com/BountySecurity/gbounty/platform/http/client"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

// Data is a data transfer object (DTO) used as the
// input payload for the Match function. It contains
// all the necessary data to check for match.
type Data struct {
	Step          profile.Step
	Profile       profile.Profile
	Payload       *string
	PayloadDecode *string
	Original      *request.Request
	Request       *request.Request
	Response      *response.Response
	CustomTokens  map[string]string
}

// Match checks whether there's a match for the given Data,
// and in such case it returns all the [occurrence.Occurrence].
//
// Note: not all matches are accompanied by occurrences.
func Match(ctx context.Context, d Data) (bool, []occurrence.Occurrence) {
	if d.Profile == nil {
		return false, []occurrence.Occurrence{}
	}

	var (
		ok     bool
		ngreps int
		x      interface {
			GrepAt(idx int, rr map[string]string) (profile.Grep, error)
		}
	)
	switch d.Profile.GetType() {
	case profile.TypeActive:
		ngreps = len(d.Step.Greps)
		x = d.Step
	case profile.TypePassiveReq:
		var prof *profile.Request
		prof, ok = d.Profile.(*profile.Request)
		if !ok {
			logger.For(ctx).Errorf("Invalid profile: non-valid passive_request")
			return false, []occurrence.Occurrence{}
		}

		x = prof
		ngreps = len(prof.Greps)
	case profile.TypePassiveRes:
		var prof *profile.Response
		prof, ok = d.Profile.(*profile.Response)
		if !ok {
			logger.For(ctx).Errorf("Invalid profile: non-valid passive_response")
			return false, []occurrence.Occurrence{}
		}

		x = prof
		ngreps = len(prof.Greps)
	}

	// Safety check, we might need to revisit this.
	// Its main purpose is for interactions with blind host.
	if ngreps == 0 {
		return false, []occurrence.Occurrence{}
	}

	booleans := make([]bool, 0, ngreps)
	operators := make([]profile.GrepOperator, 0, ngreps-1)
	occurrences := make([]occurrence.Occurrence, 0)

	for idx := 0; idx < ngreps; idx++ {
		// It must never fail here.
		// Any error must be caught by the profile validation.
		g, err := x.GrepAt(idx, d.CustomTokens)
		if err != nil {
			logger.For(ctx).Warnf(
				"Grep (idx=%d) from profile (name='%s') could not be checked: %s",
				idx, d.Profile.GetName(), err,
			)
			continue
		}
		if !g.Enabled {
			continue
		}

		var (
			ok  bool
			occ []occurrence.Occurrence
		)

		// We intentionally omit [profile.GrepTypeBlindHost].
		//nolint:exhaustive
		switch g.Type {
		case profile.GrepTypeSimpleString:
			ok, occ = matchSimpleString(g, d.Request, d.Response)
		case profile.GrepTypeRegex:
			ok, occ = matchRegex(g, d.Request, d.Response)
		case profile.GrepTypeStatusCode:
			ok, occ = matchStatusCode(g, d.Response)
		case profile.GrepTypeTimeDelay:
			ok, occ = matchTimeDelay(g, d.Response)
		case profile.GrepTypeContentType:
			ok, occ = matchContentType(g, d.Response)
		case profile.GrepTypeContentLength:
			ok, occ = matchContentLength(g, d.Response)
		case profile.GrepTypeContentLengthDiff:
			ok, occ = matchContentLengthDiff(ctx, g, d.Original, d.Response)
		case profile.GrepTypeURLExtension:
			ok, occ = matchURLExtension(g, d.Request)
		case profile.GrepTypePayload:
			ok, occ = matchPayload(g, d.Request, d.Response, d.Payload)
		case profile.GrepTypePreEncodedPayload:
			ok, occ = matchPayload(g, d.Request, d.Response, d.PayloadDecode)
		}

		// We append the occurrences to the global list,
		// if any.
		occurrences = append(occurrences, occ...)

		// If it is the first grep,
		// we ignore the operator.
		if len(booleans) == 0 {
			booleans = append(booleans, ok)
			continue
		}

		// Otherwise, we consider both, the boolean
		// and the operator, like: ...AND/OR grep.
		booleans = append(booleans, ok)
		operators = append(operators, g.Operator)
	}

	return evaluate(booleans, operators), occurrences
}

func evaluate(booleans []bool, operators []profile.GrepOperator) bool {
	// None of the greps were enabled, thus there's no match.
	if len(booleans) == 0 {
		return false
	}

	result := booleans[0]
	// Only one of the greps was enabled, thus it determines whether is match.
	if len(booleans) == 1 {
		return result
	}

	// Otherwise, we evaluate the result of each grep
	for i, op := range operators {
		result = op.Match(result, booleans[i+1])
	}

	return result
}

func matchSimpleString(g profile.Grep, req *request.Request, res *response.Response) (bool, []occurrence.Occurrence) {
	offset, findIn := bytesToFindIn(g, req, res)

	var (
		occurrences []occurrence.Occurrence
		grepValue   = g.Value.AsString()
	)

	if g.Option.CaseSensitive() {
		occurrences = occurrence.Find(string(findIn), grepValue)
	} else {
		occurrences = occurrence.Find(strings.ToLower(string(findIn)), strings.ToLower(grepValue))
	}

	for i := range occurrences {
		occurrences[i][0] += offset
		occurrences[i][1] += offset
	}

	return len(occurrences) > 0, occurrences
}

func matchRegex(g profile.Grep, req *request.Request, res *response.Response) (bool, []occurrence.Occurrence) {
	offset, findIn := bytesToFindIn(g, req, res)

	value := g.Value.AsRegex()
	if !g.Option.CaseSensitive() {
		value = "(?i)" + value
	}

	occurrences := occurrence.FindRegexp(string(findIn), value)
	for i := range occurrences {
		occurrences[i][0] += offset
		occurrences[i][1] += offset
	}

	return len(occurrences) > 0, occurrences
}

func matchStatusCode(g profile.Grep, res *response.Response) (bool, []occurrence.Occurrence) {
	for _, code := range g.Value.AsStatusCodes() {
		if res.Code == code {
			return true, occurrence.FindStatusCode(string(res.Bytes()), res.Code)
		}
	}
	return false, []occurrence.Occurrence{}
}

// matchTimeDelay checks if the response time, minus the connection time, cast to an integer,
// is equals to the time specified in the profile, with a margin of up to two seconds.
func matchTimeDelay(g profile.Grep, res *response.Response) (bool, []occurrence.Occurrence) {
	const margin = 2
	delay := g.Value.AsTimeDelaySeconds()
	responseTime := res.Time - res.ConnTime
	return delay <= int(responseTime.Seconds()) && int(responseTime.Seconds()) <= delay+margin, []occurrence.Occurrence{}
}

func matchContentType(g profile.Grep, res *response.Response) (bool, []occurrence.Occurrence) {
	for _, contentType := range g.Value.AsContentTypes() {
		if strings.EqualFold(contentType, res.ContentType()) {
			return true, []occurrence.Occurrence{}
		}
	}
	return false, []occurrence.Occurrence{}
}

func matchContentLength(g profile.Grep, res *response.Response) (bool, []occurrence.Occurrence) {
	// We calculate a 20% of margin
	const (
		twenty  = 20
		percent = 100
	)

	length := g.Value.AsContentLength()
	margin := length * twenty / percent
	return length-margin <= res.Length() && res.Length() <= length+margin, []occurrence.Occurrence{}
}

func matchContentLengthDiff(
	ctx context.Context,
	g profile.Grep,
	origReq *request.Request,
	res *response.Response,
) (bool, []occurrence.Occurrence) {
	// First, we need to get the original response
	// in order to compare the lengths.
	origRes, err := originalResponse(ctx, origReq)
	if err != nil {
		// In case of error, we cannot check the response's length.
		// So, we log the error (to notice the user), and return false.
		logger.For(ctx).Errorf("Couldn't check response's length: couldn't get original response: %s", err.Error())
		return false, []occurrence.Occurrence{}
	}

	// Then, we calculate the absolute difference.
	diff := res.Length() - origRes.Length()
	if diff < 0 {
		diff *= -1
	}

	// Finally, we consider that there is a "match", if the
	// difference is greater or equal than the value specified in the profile.
	return diff >= g.Value.AsContentLength(), []occurrence.Occurrence{}
}

func originalResponse(ctx context.Context, orig *request.Request) (response.Response, error) {
	// First, we clone the original request to avoid side effects.
	req := orig.Clone()

	// Then, we set the timeout to 10 seconds.
	// If the original request has a greater timeout, then we leave it.
	const timeout = 10 * time.Second
	if req.Timeout < timeout {
		req.Timeout = timeout
	}

	// Finally, we perform the request.
	httpClient := client.New()
	return httpClient.Do(ctx, orig)
}

func matchURLExtension(g profile.Grep, req *request.Request) (bool, []occurrence.Occurrence) {
	requestURLExtension := filepath.Ext(req.Path)
	for _, urlExtension := range g.Value.AsURLExtensions() {
		if strings.EqualFold(urlExtension, requestURLExtension) {
			return true, []occurrence.Occurrence{}
		}
	}
	return false, []occurrence.Occurrence{}
}

func matchPayload(g profile.Grep, req *request.Request, res *response.Response, payload *string) (bool, []occurrence.Occurrence) {
	_, findIn := bytesToFindIn(g, req, res)

	if g.Option.CaseSensitive() {
		return strings.Contains(string(findIn), *payload), []occurrence.Occurrence{}
	}

	return strings.Contains(strings.ToLower(string(findIn)), strings.ToLower(*payload)), []occurrence.Occurrence{}
}
