package scan

import (
	"context"
	"time"

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

// FileSystem defines the behavior expected from a [scan] file system,
// used to store and retrieve [Match], [Error], and [TaskSummary] instances.
type FileSystem interface {
	FileSystemStats
	FileSystemErrors
	FileSystemMatches
	FileSystemSummaries
	FileSystemTemplates
	Cleanup(ctx context.Context) error
}

// FileSystemStats defines the behavior expected from a [scan] file system
// to store and retrieve [Stats] instances.
type FileSystemStats interface {
	StoreStats(ctx context.Context, stats *Stats) error
	LoadStats(ctx context.Context) (*Stats, error)
}

// FileSystemErrors defines the behavior expected from a [scan] file system
// to store and retrieve [Error] instances.
type FileSystemErrors interface {
	StoreError(ctx context.Context, err Error) error
	LoadErrors(ctx context.Context) ([]Error, error)
	ErrorsIterator(ctx context.Context) (chan Error, CloseFunc, error)
}

// FileSystemMatches defines the behavior expected from a [scan] file system
// to store and retrieve [Match] instances.
type FileSystemMatches interface {
	StoreMatch(ctx context.Context, match Match) error
	LoadMatches(ctx context.Context) ([]Match, error)
	MatchesIterator(ctx context.Context) (chan Match, CloseFunc, error)
}

// FileSystemSummaries defines the behavior expected from a [scan] file system
// to store and retrieve [TaskSummary] instances.
type FileSystemSummaries interface {
	StoreTaskSummary(ctx context.Context, ts TaskSummary) error
	LoadTasksSummaries(ctx context.Context) ([]TaskSummary, error)
	TasksSummariesIterator(ctx context.Context) (chan TaskSummary, CloseFunc, error)
}

// FileSystemTemplates defines the behavior expected from a [scan] file system
// to store and retrieve [Template] instances.
type FileSystemTemplates interface {
	StoreTemplate(ctx context.Context, tpl Template) error
	LoadTemplates(ctx context.Context) ([]Template, error)

	// TemplatesIterator returns a channel of Template (or an error),
	// so the channel can be used as an iterator.
	// The returned channel is closed when the iterator is done (no more elements)
	// or when the context is canceled.
	// Thus, the context cancellation can also be used to stop the iteration.
	TemplatesIterator(ctx context.Context) (chan Template, error)
}

// CloseFunc is a function that can be used to close something that's open.
// For instance, a channel, a socket or a file descriptor.
//
// Internal details will vary depending on the function that returns it.
type CloseFunc func()

// Writer defines the behavior expected from a [scan] writer, used to write
// [Config], [Stats], [Match], [Error], and [TaskSummary] instances to a
// specific output (e.g. stdout or file) in a specific format (e.g. JSON).
type Writer interface {
	WriteConfig(ctx context.Context, cfg Config) error

	WriteStats(ctx context.Context, fs FileSystem) error
	WriteMatchesSummary(ctx context.Context, fs FileSystem) error

	WriteError(ctx context.Context, err Error) error
	WriteErrors(ctx context.Context, fs FileSystem) error

	WriteMatch(ctx context.Context, match Match, includeResponse bool) error
	WriteMatches(ctx context.Context, fs FileSystem, includeResponses bool) error

	WriteTasks(ctx context.Context, fs FileSystem, allRequests, allResponses bool) error
}
