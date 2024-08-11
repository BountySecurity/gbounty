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
	Cleanup(context.Context) error
}

// FileSystemStats defines the behavior expected from a [scan] file system
// to store and retrieve [Stats] instances.
type FileSystemStats interface {
	StoreStats(context.Context, *Stats) error
	LoadStats(context.Context) (*Stats, error)
}

// FileSystemErrors defines the behavior expected from a [scan] file system
// to store and retrieve [Error] instances.
type FileSystemErrors interface {
	StoreError(context.Context, Error) error
	LoadErrors(context.Context) ([]Error, error)
	ErrorsIterator(context.Context) (chan Error, CloseFunc, error)
}

// FileSystemMatches defines the behavior expected from a [scan] file system
// to store and retrieve [Match] instances.
type FileSystemMatches interface {
	StoreMatch(context.Context, Match) error
	LoadMatches(context.Context) ([]Match, error)
	MatchesIterator(context.Context) (chan Match, CloseFunc, error)
}

// FileSystemSummaries defines the behavior expected from a [scan] file system
// to store and retrieve [TaskSummary] instances.
type FileSystemSummaries interface {
	StoreTaskSummary(context.Context, TaskSummary) error
	LoadTasksSummaries(context.Context) ([]TaskSummary, error)
	TasksSummariesIterator(context.Context) (chan TaskSummary, CloseFunc, error)
}

// FileSystemTemplates defines the behavior expected from a [scan] file system
// to store and retrieve [Template] instances.
type FileSystemTemplates interface {
	StoreTemplate(context.Context, Template) error
	LoadTemplates(context.Context) ([]Template, error)

	// TemplatesIterator returns a channel of Template (or an error),
	// so the channel can be used as an iterator.
	// The returned channel is closed when the iterator is done (no more elements)
	// or when the context is canceled.
	// Thus, the context cancellation can also be used to stop the iteration.
	TemplatesIterator(context.Context) (chan Template, error)
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
	WriteConfig(context.Context, Config) error

	WriteStats(context.Context, FileSystem) error
	WriteMatchesSummary(context.Context, FileSystem) error

	WriteError(context.Context, Error) error
	WriteErrors(context.Context, FileSystem) error

	WriteMatch(context.Context, Match, bool) error
	WriteMatches(context.Context, FileSystem, bool) error

	WriteTasks(context.Context, FileSystem, bool, bool) error
}
