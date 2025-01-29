package gbounty

import (
	"context"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/kit/blindhost"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

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

// Modifier defines the behavior of a request modifier, which is a component
// capable of modifying the given request based on certain given requirements.
type Modifier interface {
	Modify(step *profile.Step, tpl Template, req request.Request) request.Request
}

// Customizable defines the behavior of any object that can be customized with an `entrypoint`.
type Customizable interface {
	Customize(ep entrypoint.Entrypoint)
}

// Requester defines the behavior expected from a requester, capable to
// perform an HTTP [request.Request] and return the [response.Response] got.
type Requester interface {
	Do(ctx context.Context, req *request.Request) (response.Response, error)
}

// BlindHostPoller defines the behavior expected from an agent
// that can continuously poll a `blindhost` looking for [blindhost.Interaction] instances.
type BlindHostPoller interface {
	Search(substr string) *blindhost.Interaction
	BruteSearch(substr string) *blindhost.Interaction
}
