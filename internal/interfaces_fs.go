package scan

import "context"

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
