package gbounty

import (
	"context"
	"errors"
	"time"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/kit/logger"
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

var (
	// ErrMissingProfiles is the error returned when the `scan` cannot be started because there are no profiles.
	ErrMissingProfiles = errors.New("missing profiles")
	// ErrMissingEntryPoints is the error returned when the `scan` cannot be started because there are no entry point finders.
	ErrMissingEntryPoints = errors.New("missing entry point finders")
	// ErrMissingRequestBuilder is the error returned when the `scan` cannot be started because there is no request builder configured.
	ErrMissingRequestBuilder = errors.New("missing requester builder")
	// ErrMissingFileSystemAbstraction is the error returned when the `scan` cannot be started because there is no file system abstraction configured.
	ErrMissingFileSystemAbstraction = errors.New("missing file system abstraction")
	// ErrMissingContext is the error returned when the `scan` cannot be started because there is no [context.Context].
	ErrMissingContext = errors.New("missing context")
)

// RunnerOpts is the structure that holds the configuration for the [Runner] to start a `scan`.
type RunnerOpts struct {
	ctx                context.Context
	activeProfiles     []*profile.Active
	passiveReqProfiles []*profile.Request
	passiveResProfiles []*profile.Response
	entrypointFinders  []entrypoint.Finder
	modifiers          []Modifier
	cfg                Config
	reqBuilder         RequesterBuilder
	bhPoller           BlindHostPoller
	onUpdatedFn        func(*Stats)
	onErrorFn          onErrorFunc
	onMatchFn          onMatchFunc
	onTaskFn           onTaskFunc
	onFinishedFn       func(*Stats, error)
	saveAllRequests    bool
	saveResponses      bool
	saveAllResponses   bool
	fileSystem         FileSystem

	templatesIt      chan Template
	closeTemplatesIt CloseFunc
}

// DefaultRunnerOpts constructs an empty instance of [RunnerOpts].
func DefaultRunnerOpts() *RunnerOpts {
	return &RunnerOpts{
		ctx: context.Background(),
	}
}

// WithContext sets the given context to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithContext(ctx context.Context) *RunnerOpts {
	opts.ctx = ctx
	return opts
}

// WithActiveProfiles sets the given active profiles to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithActiveProfiles(activeProfiles []*profile.Active) *RunnerOpts {
	opts.activeProfiles = activeProfiles
	return opts
}

// WithPassiveReqProfiles sets the given passive request profiles to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithPassiveReqProfiles(passiveReqProfiles []*profile.Request) *RunnerOpts {
	opts.passiveReqProfiles = passiveReqProfiles
	return opts
}

// WithPassiveResProfiles sets the given passive response profiles to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithPassiveResProfiles(passiveResProfiles []*profile.Response) *RunnerOpts {
	opts.passiveResProfiles = passiveResProfiles
	return opts
}

// WithEntrypointFinders sets the given entrypoint finders to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithEntrypointFinders(finders []entrypoint.Finder) *RunnerOpts {
	opts.entrypointFinders = finders
	return opts
}

// WithModifiers sets the given modifiers to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithModifiers(modifiers []Modifier) *RunnerOpts {
	opts.modifiers = modifiers
	return opts
}

// WithConfiguration sets the given `scan` configuration to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithConfiguration(cfg Config) *RunnerOpts {
	opts.cfg = cfg
	return opts
}

// WithRequesterBuilder sets the given request builder to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithRequesterBuilder(reqBuilder RequesterBuilder) *RunnerOpts {
	opts.reqBuilder = reqBuilder
	return opts
}

// WithBlindHostPoller sets the given blind host poller to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithBlindHostPoller(bhPoller BlindHostPoller) *RunnerOpts {
	opts.bhPoller = bhPoller
	return opts
}

// WithOnUpdated sets the given `onUpdated` callback to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithOnUpdated(fn func(*Stats)) *RunnerOpts {
	opts.onUpdatedFn = fn
	return opts
}

// WithOnError sets the given `onError` callback to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithOnError(fn onErrorFunc) *RunnerOpts {
	opts.onErrorFn = fn
	return opts
}

// WithOnMatch sets the given `onMatch` callback to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithOnMatch(fn onMatchFunc) *RunnerOpts {
	opts.onMatchFn = fn
	return opts
}

// WithOnTask sets the given `onTask` callback to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithOnTask(fn onTaskFunc) *RunnerOpts {
	opts.onTaskFn = fn
	return opts
}

// WithOnFinished sets the given `onFinished` callback to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithOnFinished(fn func(*Stats, error)) *RunnerOpts {
	opts.onFinishedFn = fn
	return opts
}

// WithSaveAllRequests sets the given `saveAllRequests` boolean to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithSaveAllRequests(saveAllRequests bool) *RunnerOpts {
	opts.saveAllRequests = saveAllRequests
	return opts
}

// WithSaveResponses sets the given `saveResponses` boolean to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithSaveResponses(saveResponses bool) *RunnerOpts {
	opts.saveResponses = saveResponses
	return opts
}

// WithSaveAllResponses sets the given `saveAllResponses` boolean to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithSaveAllResponses(saveAllResponses bool) *RunnerOpts {
	opts.saveAllResponses = saveAllResponses
	return opts
}

// WithFileSystem sets the given file system abstraction to the [RunnerOpts] instance.
func (opts *RunnerOpts) WithFileSystem(fileSystem FileSystem) *RunnerOpts {
	opts.fileSystem = fileSystem
	return opts
}

func (opts *RunnerOpts) prepare() error {
	logger.For(opts.ctx).Debug("Validating scan options...")
	if err := opts.validate(); err != nil {
		return err
	}

	if err := opts.setupTemplatesIt(); err != nil {
		return err
	}

	opts.setupOnErrorFn()
	opts.setupOnMatchFn()
	opts.setupOnTaskFn()

	return nil
}

func (opts *RunnerOpts) validate() error {
	if opts.ctx == nil {
		return ErrMissingContext
	}

	if len(opts.activeProfiles) == 0 &&
		len(opts.passiveReqProfiles) == 0 &&
		len(opts.passiveResProfiles) == 0 {
		return ErrMissingProfiles
	}

	if len(opts.entrypointFinders) == 0 {
		return ErrMissingEntryPoints
	}

	if opts.reqBuilder == nil {
		return ErrMissingRequestBuilder
	}

	if opts.fileSystem == nil {
		return ErrMissingFileSystemAbstraction
	}

	return nil
}

func (opts *RunnerOpts) setupTemplatesIt() error {
	it, closeIt, err := opts.fileSystem.TemplatesIterator(opts.ctx)
	if err != nil {
		return err
	}

	opts.templatesIt = it
	opts.closeTemplatesIt = closeIt
	return nil
}

func (opts *RunnerOpts) setupOnErrorFn() {
	onErrorFn := opts.onErrorFn
	opts.onErrorFn = func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response, err error) {
		storeErr := opts.fileSystem.StoreError(ctx, Error{
			URL:       url,
			Requests:  reqs,
			Responses: res,
			Err:       err.Error(),
		})

		if storeErr != nil {
			logger.For(ctx).Errorf("Error while storing scan error: %s", storeErr.Error())
		}

		if onErrorFn != nil {
			onErrorFn(ctx, url, reqs, res, err)
		}
	}
}

func (opts *RunnerOpts) setupOnMatchFn() {
	onMatchFn := opts.onMatchFn
	opts.onMatchFn = func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response, prof profile.Profile, issue profile.IssueInformation, ep entrypoint.Entrypoint, payload string, occ [][]occurrence.Occurrence) {
		if len(issue.GetIssueName()) == 0 {
			logger.For(ctx).Warn("Your profile has an issue without a name. This issue might be ignored")
		}

		if len(issue.GetIssueSeverity()) == 0 {
			logger.For(ctx).Warn("Your profile has an issue without severity. This issue might be ignored")
		}

		if len(issue.GetIssueConfidence()) == 0 {
			logger.For(ctx).Warn("Your profile has an issue without confidence. This issue might be ignored")
		}

		var param string
		if ep != nil {
			param = ep.Param(payload)
		}

		err := opts.fileSystem.StoreMatch(ctx, Match{
			URL:                   url,
			Requests:              reqs,
			Responses:             res,
			ProfileName:           prof.GetName(),
			ProfileTags:           prof.GetTags(),
			IssueName:             issue.GetIssueName(),
			IssueSeverity:         issue.GetIssueSeverity(),
			IssueConfidence:       issue.GetIssueConfidence(),
			IssueDetail:           issue.GetIssueDetail(),
			IssueBackground:       issue.GetIssueBackground(),
			RemediationDetail:     issue.GetRemediationDetail(),
			RemediationBackground: issue.GetRemediationBackground(),
			IssueParam:            param,
			ProfileType:           prof.GetType().String(),
			Payload:               payload,
			Occurrences:           occ,
			At:                    time.Now().UTC(),
		})
		if err != nil {
			logger.For(ctx).Errorf("Error while storing scan match: %s", err.Error())
		}

		if onMatchFn != nil {
			onMatchFn(ctx, url, reqs, res, prof, issue, ep, payload, occ)
		}
	}
}

func (opts *RunnerOpts) setupOnTaskFn() {
	onTaskFn := opts.onTaskFn
	opts.onTaskFn = func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response) {
		err := opts.fileSystem.StoreTaskSummary(ctx, TaskSummary{
			URL:       url,
			Requests:  reqs,
			Responses: res,
		})
		if err != nil {
			logger.For(ctx).Errorf("Error while storing scan task summary: %s", err.Error())
		}

		if onTaskFn != nil {
			onTaskFn(ctx, url, reqs, res)
		}
	}
}
