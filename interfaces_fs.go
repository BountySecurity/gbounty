package gbounty

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
	ErrorsIterator(ctx context.Context) (chan Error, CloseFunc, error)
	CloseErrors(ctx context.Context) error
}

// FileSystemMatches defines the behavior expected from a [scan] file system
// to store and retrieve [Match] instances.
type FileSystemMatches interface {
	StoreMatch(ctx context.Context, match Match) error
	MatchesIterator(ctx context.Context) (chan Match, CloseFunc, error)
	CloseMatches(ctx context.Context) error
}

// FileSystemSummaries defines the behavior expected from a [scan] file system
// to store and retrieve [TaskSummary] instances.
type FileSystemSummaries interface {
	StoreTaskSummary(ctx context.Context, ts TaskSummary) error
	TasksSummariesIterator(ctx context.Context) (chan TaskSummary, CloseFunc, error)
	CloseTasksSummaries(ctx context.Context) error
}

// FileSystemTemplates defines the behavior expected from a [scan] file system
// to store and retrieve [Template] instances.
type FileSystemTemplates interface {
	StoreTemplate(ctx context.Context, tpl Template) error
	TemplatesIterator(ctx context.Context) (chan Template, CloseFunc, error)
	CloseTemplates(ctx context.Context) error
}

// CloseFunc is a function that can be used to close something that's open.
// For instance, a channel, a socket or a file descriptor.
//
// Internal details will vary depending on the function that returns it.
type CloseFunc func()
