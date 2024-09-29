package scan

import (
	"context"
	"time"

	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/strings/occurrence"
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

// RequesterBuilder is a function that returns a [Requester] instance.
type RequesterBuilder func() (Requester, error)

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
