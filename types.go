package gbounty

import (
	"context"
	"net/url"
	"time"

	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/kit/strings/occurrence"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
	"github.com/bountysecurity/gbounty/response"
)

// CustomTokens is a type that represents a collection of pairs (key, value)
// that can be used to replace certain tokens (i.e. placeholders) in a [request.Request].
type CustomTokens = map[string]string

// TaskSummary represents a summary of a [scan] task, which corresponds to one of the
// iterations where one (or multiple) requests are targeted against a URL, and some
// checks are performed over the responses, looking for one (or multiple) [Match].
type TaskSummary struct {
	URL       string
	Requests  []*request.Request
	Responses []*response.Response
}

func (ts TaskSummary) Domain() string {
	u, err := url.Parse(ts.URL)
	if err != nil {
		return ts.URL
	}

	return u.Scheme + "://" + u.Hostname()
}

// Match represents a match found during a [scan], containing the URL,
// the requests and responses that were made, and some other details associated
// with the match, like the profile's name and some information about the issue.
//
// There can be multiple [Match] per scan.
// See the `internal/match` package for further details.
type Match struct {
	URL                   string
	Requests              []*request.Request
	Responses             []*response.Response
	ProfileName           string
	ProfileTags           []string
	IssueName             string
	IssueSeverity         string
	IssueConfidence       string
	IssueDetail           string
	IssueBackground       string
	RemediationDetail     string
	RemediationBackground string
	IssueParam            string
	ProfileType           string
	Payload               string
	Occurrences           [][]occurrence.Occurrence
	Grep                  string
	At                    time.Time
}

func (m Match) Domain() string {
	u, err := url.Parse(m.URL)
	if err != nil {
		return m.URL
	}

	return u.Scheme + "://" + u.Hostname()
}

// Error represents an error that occurred during a [scan], containing the URL,
// the requests and responses that were made, and the error message.
//
// There can be multiple [Error] per scan.
type Error struct {
	URL       string
	Requests  []*request.Request
	Responses []*response.Response
	Err       string
}

func (e Error) Domain() string {
	u, err := url.Parse(e.URL)
	if err != nil {
		return e.URL
	}

	return u.Scheme + "://" + u.Hostname()
}

// RequesterBuilder is a function that returns a [Requester] instance.
type RequesterBuilder func(req *request.Request) (Requester, error)

type (
	onMatchFunc func(context.Context, string, []*request.Request, []*response.Response, profile.Profile, profile.IssueInformation, entrypoint.Entrypoint, string, [][]occurrence.Occurrence)
	onErrorFunc func(context.Context, string, []*request.Request, []*response.Response, error)
	onTaskFunc  func(context.Context, string, []*request.Request, []*response.Response)
)

type update struct {
	newMatch   bool
	newSuccess bool
	newErr     bool
}
