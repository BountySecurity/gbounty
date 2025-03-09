package gbounty

import (
	"context"
	"errors"
	"sync"

	"github.com/BountySecurity/gbounty/internal/platform/metrics"
	"github.com/BountySecurity/gbounty/kit/logger"
	"github.com/BountySecurity/gbounty/kit/panics"
	"github.com/BountySecurity/gbounty/kit/pool"
)

// Runner is the main component responsible for orchestrating `scan` executions.
type Runner struct {
	opts  *RunnerOpts
	stats *Stats
}

// NewRunner constructs a new [Runner] instance.
func NewRunner(opts *RunnerOpts) *Runner {
	if opts == nil {
		opts = DefaultRunnerOpts()
	}

	if opts.ctx == nil {
		opts.ctx = context.Background()
	}

	return &Runner{
		opts:  opts,
		stats: NewStats(),
	}
}

// Start starts the `scan` execution.
func (r *Runner) Start() (err error) {
	logger.For(r.opts.ctx).Info("Starting scan execution...")

	defer func() {
		if err != nil && !errors.Is(err, context.Canceled) {
			logger.For(r.opts.ctx).Errorf("Scan execution failed: %s", err.Error())
		}
	}()

	if r.opts.onFinishedFn != nil {
		defer func() {
			logger.For(r.opts.ctx).Info("Running 'on finished' function...")
			r.opts.onFinishedFn(r.stats, err)
		}()
	}

	defer func() {
		if err == nil || errors.Is(err, context.Canceled) {
			err2 := r.opts.fileSystem.StoreStats(r.opts.ctx, r.stats)
			if err2 != nil {
				err = err2
			}
		}
	}()

	logger.For(r.opts.ctx).Debug("Starting scan execution, preparing...")
	if err = r.opts.prepare(); err != nil {
		return err
	}

	err = r.run()

	return
}

// run is the main function to trigger the scan execution.
// It should never return an error, other than [context.Canceled]
// in case the ctx ([context.Context]) from Runner.opts is cancelled.
func (r *Runner) run() error {
	// Global execution variables
	var (
		p  = pool.New(r.opts.ctx, r.opts.cfg.Concurrency)
		ch = make(chan update)
	)

	logger.For(r.opts.ctx).Info("Launching stats collector...")
	wg := r.launchStatsCollector(r.opts.ctx, ch)

	logger.For(r.opts.ctx).Info("Loading scan stats from a previous execution...")
	if stats, err := r.opts.fileSystem.LoadStats(r.opts.ctx); err == nil && stats != nil {
		r.stats = stats
		logger.For(r.opts.ctx).Info("Scan stats from a previous execution loaded successfully")
	} else {
		logger.For(r.opts.ctx).Info("Dispatching scan tasks calculation...")
		go r.calculateTasks(r.opts.ctx)
	}

	defer r.opts.closeTemplatesIt()
	for tpl := range r.opts.templatesIt {
		// Check for context cancellation
		select {
		case <-r.opts.ctx.Done():
			logger.For(r.opts.ctx).Debugf("Scan template (idx=%d): context cancelled", tpl.Idx)
			continue
		default:
		}

		// Check for finished templates
		if r.stats.isTemplateEnded(tpl) {
			logger.For(r.opts.ctx).Debugf("Skipping (ended) template with idx: %d", tpl.Idx)
			continue
		}

		tpl := tpl

		// This is a blocking operation, based on the maximum concurrency set
		// at the pool.Pool initialization. It will block until a worker is
		// available, or just early return if the given context is cancelled.
		//
		// However, note that its execution does not necessarily mean that the
		// given function has finished, just that it has been taken by a worker.
		//
		// In order to ensure that all the tasks are finished, we need to call
		// p.Close() and wait for the internal WaitGroup to be done.
		p.BareRun(r.opts.ctx, func() {
			defer panics.Log(r.opts.ctx)

			// Account the number of concurrent templates.
			metrics.ConcurrentTemplates.Inc()
			defer func() { metrics.ConcurrentTemplates.Dec() }()

			logger.For(r.opts.ctx).Debugf("Starting scan template with idx: %d", tpl.Idx)

			// Initialize line of work.
			lineOfWork := &LineOfWork{Template: tpl, Matches: make(map[string]struct{})}

			// Find and update entrypoints.
			// ONLY for those templates with no response.
			if tpl.Response == nil {
				for _, f := range r.opts.entrypointFinders {
					entrypointsFound := f.Find(lineOfWork.Template.Request)
					lineOfWork.appendEntrypoints(entrypointsFound)
				}
			}

			// Prepare tasks within the line of work.
			if tpl.Response == nil {
				// Prepare tasks for all active profiles.
				// ONLY for those templates with no response.
				for _, prof := range r.opts.activeProfiles {
					_, _ = lineOfWork.prepareTasks(
						r.opts.ctx,
						prof,
						len(r.opts.cfg.BlindHost) > 0,
						r.opts.cfg.EmailAddress,
					)
				}
			} else {
				// Prepare a single task.
				// ONLY for those templates with response.
				lineOfWork.Tasks = append(lineOfWork.Tasks, &Task{IsBase: true, StepIdx: -1, PayloadIdx: -1, LoW: lineOfWork})
			}

			// Execute all the tasks within the line of work
			r.performRequests(ch, lineOfWork)

			// If it hasn't been cancelled, mark it as finished
			// Otherwise, undo it and update stats accordingly.
			if r.opts.ctx.Err() == nil {
				r.stats.markTemplateAsEnded(tpl.Idx)
			} else {
				lineOfWork.reset()
				r.stats.incrementMatches(-lineOfWork.numOfMatches())
				r.stats.incrementFailedRequests(-lineOfWork.numOfFailedTasks())
				r.stats.incrementSucceedRequests(-lineOfWork.numOfSucceedTasks())
			}
		}, func() { logger.For(r.opts.ctx).Debugf("Scan template (idx=%d) discarded: context cancelled", tpl.Idx) })
	}

	logger.For(r.opts.ctx).Info("The scan templates iteration has reached its latest template")
	logger.For(r.opts.ctx).Info("So, waiting for all the remaining templates to finish its execution...")

	// This operation is blocking, so after this line, all the templates have been finished.
	// Any additional operation, that requires the scan to have been completed, has to be executed
	// after this line. Otherwise, it will be executed before the scan has been finished.
	p.Close()

	close(ch)
	wg.Wait()

	return r.opts.ctx.Err()
}

// launchStatsCollector is a function that launches a stats collector, which is a goroutine
// that loops on updates sent over a channel, and updates the stats struct accordingly.
// These stats are being updated on every task execution.
func (r *Runner) launchStatsCollector(ctx context.Context, ch chan update) *sync.WaitGroup {
	wg := &sync.WaitGroup{}
	wg.Add(1)

	go func() {
		defer panics.Log(ctx)
		r.statsCollector(ch, r.opts.onUpdatedFn)
		logger.For(ctx).Info("Stats collector stopped...")
		wg.Done()
	}()

	return wg
}

func (r *Runner) performRequests(ch chan update, lineOfWork *LineOfWork) {
	lineOfWork.executeTasks(
		r.opts.ctx, r.opts.reqBuilder, r.opts.bhPoller,
		func(n int) { r.stats.incrementTotalRequests(n) },
		func(n int) {
			r.stats.incrementTotalRequests(-n)
			r.stats.incrementSkippedRequests(n)
		},
		func(matched, success, failed bool) {
			select {
			case <-r.opts.ctx.Done():
				return
			default:
			}

			select {
			case <-r.opts.ctx.Done():
			case ch <- update{
				newMatch:   matched,
				newSuccess: success,
				newErr:     failed,
			}:
			}
		},
		r.opts.onErrorFn, r.opts.onMatchFn, r.opts.onTaskFn,
		r.opts.cfg.RPS,
		r.opts.saveAllRequests,
		r.opts.saveResponses,
		r.opts.saveAllResponses,
		r.opts.modifiers,
		r.opts.passiveReqProfiles,
		r.opts.passiveResProfiles,
		r.opts.cfg.CustomTokens,
		r.opts.cfg.PayloadStrategy,
	)
}

func (r *Runner) statsCollector(ch chan update, onUpdatedFn func(*Stats)) {
	for tr := range ch {
		logger.For(r.opts.ctx).Debugf("New scan stats update: %+v", tr)

		if tr.newMatch {
			r.stats.incrementMatches(1)
		}

		if tr.newErr {
			r.stats.incrementFailedRequests(1)
		}

		if tr.newSuccess {
			r.stats.incrementSucceedRequests(1)
		}

		if onUpdatedFn == nil {
			continue
		}

		onUpdatedFn(&Stats{
			NumOfTotalRequests:     r.stats.NumOfTotalRequests,
			NumOfPerformedRequests: r.stats.NumOfPerformedRequests,
			NumOfSucceedRequests:   r.stats.NumOfSucceedRequests,
			NumOfFailedRequests:    r.stats.NumOfFailedRequests,
			TemplatesEnded:         r.stats.TemplatesEnded,
			NumOfEntrypoints:       r.stats.NumOfEntrypoints,
			NumOfMatches:           r.stats.NumOfMatches,
		})
	}
}

func (r *Runner) calculateTasks(ctx context.Context) {
	defer panics.Log(ctx)

	wg := new(sync.WaitGroup)
	once := new(sync.Once)

	templates, closeIt, err := r.opts.fileSystem.TemplatesIterator(ctx)
	if err != nil {
		logger.For(ctx).Errorf("Error while reading templates to calculate the total amount of tasks: %s", err)
		return
	}
	defer closeIt()

	for tpl := range templates {
		tpl := tpl
		if tpl.Response != nil { // Is passive? (analyze only)
			if !tpl.Request.IsEmpty() {
				r.stats.incrementRequestsToAnalyze(1)
			}
			if !tpl.Response.IsEmpty() {
				r.stats.incrementResponsesToAnalyze(1)
			}
			continue
		}

		wg.Add(1)

		go func() {
			defer panics.Log(ctx)

			lineOfWork := &LineOfWork{Template: tpl, Matches: make(map[string]struct{})}

			for _, finder := range r.opts.entrypointFinders {
				entrypointsFound := finder.Find(lineOfWork.Template.Request)

				logger.For(ctx).Debugf(
					"Entrypoints found for template (idx=%d) and finder(%T): %d",
					tpl.Idx, finder, len(entrypointsFound),
				)

				lineOfWork.appendEntrypoints(entrypointsFound)
				r.stats.incrementEntrypoints(len(entrypointsFound))
			}

			for _, prof := range r.opts.activeProfiles {
				numTasksPrepared, skipped := lineOfWork.prepareTasks(
					ctx,
					prof,
					len(r.opts.cfg.BlindHost) > 0,
					r.opts.cfg.EmailAddress,
				)

				if skipped {
					once.Do(func() {
						// Q: Do we really want this???
						// fmt.Println() //nolint:forbidigo
						// pterm.Warning.Println("Some requests have been skipped because they contain one of the following labels: {BH}, {EMAIL}.")
						// pterm.Warning.Println("But either no blind host or email have been defined.")
						// pterm.Warning.Println("Please, try again with the --blind-host/-bh and --email-address/email flags.")
						logger.For(ctx).Warn("Some requests have been skipped because they contain one of the following labels: {BH}, {EMAIL}.")
						logger.For(ctx).Warn("But either no blind host or email have been defined.")
						logger.For(ctx).Warn("Please, try again with the --blind-host/-bh and --email-address/email flags.")
					})
				}

				logger.For(ctx).Debugf("Tasks prepared for template (idx=%d): %d", tpl.Idx, numTasksPrepared)

				r.stats.incrementTotalRequests(numTasksPrepared)
			}

			wg.Done()
		}()
	}

	wg.Wait()
}
