package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pterm/pterm"
	"github.com/spf13/afero"
	"golang.org/x/sync/errgroup"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/internal/platform/cli"
	"github.com/BountySecurity/gbounty/internal/platform/writer"
	"github.com/BountySecurity/gbounty/kit/blindhost"
	"github.com/BountySecurity/gbounty/kit/logger"
	"github.com/BountySecurity/gbounty/kit/panics"
	"github.com/BountySecurity/gbounty/kit/progressbar"
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
	"github.com/BountySecurity/gbounty/kit/ulid"
	"github.com/BountySecurity/gbounty/modifier"
	"github.com/BountySecurity/gbounty/platform/filesystem"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
	"github.com/BountySecurity/gbounty/response"
)

const (
	debugServerAddr         = "localhost:6060"
	debugServerShutdownTime = 5 * time.Second
)

// Run is the main entrypoint of the `gbounty` command-line interface.
func Run() error {
	cfg, err := parseCLIArgs()
	if err != nil || cfg.ShowHelp || cfg.AnyUpdate() {
		return err
	}

	var logWriter io.WriteCloser
	if len(cfg.Verbosity.Output) > 0 {
		logWriter, err = os.Create(cfg.Verbosity.Output)
		if err != nil {
			return fmt.Errorf("cannot write to log output(%s): %w", cfg.Verbosity.Output, err)
		}

		defer func() { logWriter.Close() }()
	}

	ctx := initCtxWithLogger(cfg, logWriter)
	ctx = gracefulContext(ctx)
	defer panics.Log(ctx)

	logger.For(ctx).Infof("Reading profiles from: %s", cfg.ProfilesPath.String())
	profilesProvider, err := profile.NewFileProvider(cfg.ProfilesPath...)
	if err != nil {
		logger.For(ctx).Errorf("Could not load profiles: %s", err)
		return fmt.Errorf("could not load profiles: %w", err)
	}

	if cfg.PrintTags {
		logger.For(ctx).Info("Print tags (--print-tags) flag is enabled...")

		tags := strings.Join(profilesProvider.Tags(), ", ")

		logger.For(ctx).Infof("Available profile tags: %s", tags)
		pterm.Success.Printf("Available profile tags: %s\n", tags)

		return nil
	}

	updatesChan := make(chan *gbounty.Stats)

	pbPrinter := progressbar.NewPrinter()

	initBar := func() error {
		var err error

		pbPrinter.ProgressbarPrinter = pterm.DefaultProgressbar.
			WithBarStyle(pterm.NewStyle(pterm.FgLightCyan)).
			WithTitleStyle(pterm.NewStyle(pterm.FgLightMagenta)).
			WithRemoveWhenDone(true)

		if cfg.OnlyProofOfConcept {
			pbPrinter.ProgressbarPrinter = pbPrinter.WithWriter(io.Discard)
		} else {
			pbPrinter.ProgressbarPrinter, err = pbPrinter.
				Start()
		}

		return err
	}

	// We set everything up,
	// ready for the scan to start.
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(printUpdates(gCtx, updatesChan, pbPrinter, initBar))
	g.Go(runScan(gCtx, cfg, profilesProvider, updatesChan, pbPrinter))
	debugSrv := initDebugServer(ctx)

	// Wait for the scan to happen,
	// or for the execution to be cancelled.
	err = g.Wait()

	// Everything has finished, time to shut down the debugging server.
	// We give it a few seconds to shut down gracefully.
	errDebugSrvShutdownTimeout := fmt.Errorf("server could not be shut down in %s", debugServerShutdownTime.String()) //nolint:goerr113
	debugSrvCtx, debugSrvCancel := context.WithTimeoutCause(context.Background(), debugServerShutdownTime, errDebugSrvShutdownTimeout)
	defer debugSrvCancel()
	if err := debugSrv.Shutdown(debugSrvCtx); err != nil {
		logger.For(ctx).Debugf("Debug server shutdown error: %s", err.Error())
	}

	if errors.Is(err, context.Canceled) {
		return nil
	}

	return err
}

func initCtxWithLogger(cfg cli.Config, logWriter io.Writer) context.Context {
	ctx := context.Background()
	ctx = logger.Annotate(ctx, nil)

	log := logger.For(ctx)
	log.SetLevel(cfg.Verbosity.Level())

	if logWriter != nil {
		log.SetWriter(logWriter)
		log.Infof("Logger writer is ready, path=%s", cfg.Verbosity.Output)
	}

	log.Infof("Logger is ready, level=%s", cfg.Verbosity.Level())

	return ctx
}

func parseCLIArgs() (cli.Config, error) {
	cliConfig, err := cli.Parse(os.Args)
	if err != nil {
		return cli.Config{}, err
	}

	if len(cliConfig.ProfilesPath) == 0 {
		if defaultPath := defaultProfilesLocation(); len(defaultPath) > 0 {
			cliConfig.ProfilesPath = []string{defaultPath}
		}
	}

	if cliConfig.ShowHelp || cliConfig.PrintTags || cliConfig.AnyUpdate() {
		return cliConfig, nil
	}

	if err := cliConfig.Validate(); err != nil {
		return cli.Config{}, err
	}

	return cliConfig, nil
}

func printUpdates(
	ctx context.Context,
	updatesChan chan *gbounty.Stats,
	pbPrinter *progressbar.Printer,
	initBar func() error,
) func() error {
	return func() error {
		defer panics.Log(ctx)

		for {
			select {
			case stats, ok := <-updatesChan:
				// Channel closed, no more updates
				if !ok {
					return nil
				}

				// Bar not initialized yet (first update)
				if !pbPrinter.IsActive {
					if err := initBar(); err != nil {
						return err
					}
				}

				// Regular update, just update the bar
				total := stats.NumOfTotalRequests
				if total < stats.NumOfPerformedRequests {
					total = stats.NumOfPerformedRequests
				}

				pbPrinter.Title = fmt.Sprintf("Scanning... [%d / %d]", stats.NumOfPerformedRequests, total)
				pbPrinter.Total = total
				pbPrinter.ShowCount = false
				pbPrinter.Current = stats.NumOfPerformedRequests
				pbPrinter.Add(0) // force print

			case <-ctx.Done():
				return nil
			}
		}
	}
}

//nolint:funlen
func runScan(
	ctx context.Context,
	cfg cli.Config,
	profilesProvider profile.Provider,
	updatesChan chan *gbounty.Stats,
	pbPrinter *progressbar.Printer,
) func() error {
	return func() error {
		defer panics.Log(ctx)

		actives, passiveReqs, passiveRes := loadProfiles(ctx, cfg, profilesProvider)

		id := ulid.New()
		if len(cfg.Continue) > 0 {
			id = cfg.Continue
			logger.For(ctx).Infof("Continue is enabled and continue code is %s", id)
		}

		var aferoFS afero.Fs

		if cfg.InMemory {
			logger.For(ctx).Infof("Using in-memory storage for scan metadata")

			aferoFS = afero.NewMemMapFs()
		} else {
			logger.For(ctx).Infof("Using disk storage for scan metadata")

			aferoFS = afero.NewOsFs()
		}

		fs, err := filesystem.New(aferoFS, filepath.Join(os.TempDir(), id))
		if err != nil {
			close(updatesChan)
			logger.For(ctx).Errorf("Could not initialize filesystem storage for scan metadata: %s", err)

			return err
		}

		// Initialize scan configuration from CLI arguments.
		scanCfg := configFromArgs(cfg)

		// Set up modifiers (including blind host interactions).
		var (
			bhPoller  gbounty.BlindHostPoller
			modifiers = make([]gbounty.Modifier, 0)
		)
		if len(cfg.BlindHost) > 0 {
			bhClient, err := blindhost.NewClient(cfg.BlindHost)
			if err != nil {
				logger.For(ctx).Errorf("Could not initialize the blind host client: %s", err)
			} else {
				bhPoller, err = blindhost.NewPoller(bhClient, blindhost.WithContext(ctx))
				if err != nil {
					logger.For(ctx).Errorf("Could not initialize blind host poller: %s", err)
				} else {
					hid := bhPoller.HostIdentifier()
					modifiers = append(modifiers, modifier.NewInteractionHost(cfg.BlindHost, hid))
					scanCfg.BlindHostId = hid.ID()
					scanCfg.BlindHostDomain = hid.HostBaseURL(cfg.BlindHost)
					scanCfg.BlindHostPrivateKey = hid.PrivateKey()
					logger.For(ctx).Infof("Blind host is set to: %s", scanCfg.BlindHostDomain)
				}
			}
		}
		modifiers = modifiersFromConfig(ctx, cfg, modifiers)
		// End of modifiers section

		runnerOpts := new(gbounty.RunnerOpts).
			WithContext(ctx).
			WithConfiguration(scanCfg).
			WithEntrypointFinders(entrypoint.Finders()).
			WithModifiers(modifiers).
			WithBlindHostPoller(bhPoller).
			WithActiveProfiles(actives).
			WithPassiveReqProfiles(passiveReqs).
			WithPassiveResProfiles(passiveRes).
			WithRequesterBuilder(setupScanRequester(ctx, cfg)).
			WithOnUpdated(func(stats *gbounty.Stats) { updatesChan <- stats }).
			WithOnFinished(finalizeScan(ctx, updatesChan, pbPrinter, scanCfg, fs, id)).
			WithSaveAllRequests(cfg.ShowAll || cfg.ShowAllRequests).
			WithSaveResponses(cfg.ShowResponses).
			WithSaveAllResponses(cfg.ShowAll || cfg.ShowAllResponses).
			WithFileSystem(fs)

		var w gbounty.Writer
		if cfg.OnlyProofOfConcept {
			w = writer.NewPlain(os.Stdout, writer.WithProofOfConceptEnabled(cfg.OnlyProofOfConcept))
		} else {
			w = writer.NewConsole(os.Stdout)
		}

		if cfg.StreamErrors && !cfg.Silent {
			logger.For(ctx).Info("Errors streaming enabled")

			runnerOpts.WithOnError(func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response, err error) {
				if writeErr := w.WriteError(
					ctx,
					gbounty.Error{
						URL:       url,
						Requests:  reqs,
						Responses: res,
						Err:       err.Error(),
					},
				); writeErr != nil {
					logger.For(ctx).Errorf("Error while streaming scan error: %s", writeErr.Error())
				}
			})
		}

		if cfg.StreamMatches && !cfg.Silent {
			logger.For(ctx).Info("Matches streaming enabled")

			runnerOpts.WithOnMatch(func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response, prof profile.Profile, issue profile.IssueInformation, ep entrypoint.Entrypoint, payload string, occ [][]occurrence.Occurrence) {
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

				if err = w.WriteMatch(
					ctx,
					gbounty.Match{
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
						Payload:               payload,
						Occurrences:           occ,
						ProfileType:           prof.GetType().String(),
						At:                    time.Now().UTC(),
					}, cfg.ShowResponses,
				); err != nil {
					logger.For(ctx).Errorf("Error while streaming scan match: %s", err.Error())
				}
			})
		}

		if len(cfg.Continue) == 0 {
			err = cli.PrepareTemplates(ctx, fs, cfg)
			if err != nil {
				logger.For(ctx).Errorf("Error while preparing scan templates: %s", err.Error())
				close(updatesChan)
				return err
			}
		}

		if err := writeConfig(ctx, w, scanCfg); err != nil {
			logger.For(ctx).Errorf("Error while writing config to output: %s", err.Error())

			close(updatesChan)
			return err
		}

		return gbounty.NewRunner(runnerOpts).Start()
	}
}

func modifiersFromConfig(ctx context.Context, cfg cli.Config, given []gbounty.Modifier) []gbounty.Modifier {
	modifiers := modifier.Modifiers()
	modifiers = append(modifiers, given...)

	if len(cfg.EmailAddress) > 0 {
		modifiers = append(modifiers, modifier.NewEmail(cfg.EmailAddress))
		logger.For(ctx).Infof("Email address request modifier is set to: %s", cfg.EmailAddress)
	}

	if len(cfg.CustomTokens) > 0 {
		modifiers = append(modifiers, modifier.NewCustomTokens(cfg.CustomTokens))
		logger.For(ctx).Infof("Custom tokens configured: %v", cfg.CustomTokens)
	}

	return modifiers
}

func gracefulContext(ctx context.Context) context.Context {
	done := make(chan os.Signal, 1)

	signal.Notify(done, listenFor()...)

	ctx, cancel := context.WithCancelCause(ctx)

	go func() {
		sign := <-done
		logger.For(ctx).Infof("Scan interrupted manually, signal: %s", sign.String())
		cancel(fmt.Errorf("%w, signal: %s", gbounty.ErrManuallyInterrupted, sign.String())) //nolint:goerr113
	}()

	return ctx
}

func configFromArgs(cfg cli.Config) gbounty.Config {
	payloadStrategy := gbounty.PayloadStrategyOnlyOnce
	if !cfg.StopAtFirstMatch {
		payloadStrategy = gbounty.PayloadStrategyAll
	}

	return gbounty.Config{
		RPS:             cfg.Rps,
		Concurrency:     cfg.Concurrency,
		Version:         gbounty.Version,
		SaveOnStop:      cfg.SaveOnStop,
		InMemory:        cfg.InMemory,
		EmailAddress:    len(cfg.EmailAddress) > 0,
		PayloadStrategy: payloadStrategy,

		Silent:             cfg.Silent,
		StreamErrors:       cfg.StreamErrors,
		StreamMatches:      cfg.StreamMatches,
		ShowResponses:      cfg.ShowResponses,
		ShowErrors:         cfg.ShowErrors,
		ShowAll:            cfg.ShowAll,
		ShowAllRequests:    cfg.ShowAllRequests,
		ShowAllResponses:   cfg.ShowAllResponses,
		OutPath:            cfg.OutPath,
		OutFormat:          cfg.OutFormat,
		OnlyProofOfConcept: cfg.OnlyProofOfConcept,
	}
}

func loadProfiles(
	ctx context.Context,
	cfg cli.Config,
	provider profile.Provider,
) ([]*profile.Active, []*profile.Request, []*profile.Response) {
	var (
		actives     []*profile.Active
		passiveReqs []*profile.Request
		passiveRes  []*profile.Response
	)

	if cfg.OnlyActive || cfg.ScanAllProfiles() {
		actives = provider.ActivesEnabled()
	}

	if cfg.OnlyPassive || cfg.OnlyPassiveReq || cfg.ScanAllProfiles() {
		passiveReqs = provider.PassiveReqsEnabled()
	}

	if cfg.OnlyPassive || cfg.OnlyPassiveRes || cfg.ScanAllProfiles() {
		passiveRes = provider.PassiveResEnabled()
	}

	logger.For(ctx).Infof("Loaded %d enabled active profile(s) successfully", len(actives))
	logger.For(ctx).Infof("Loaded %d enabled passive request profile(s) successfully", len(passiveReqs))
	logger.For(ctx).Infof("Loaded %d enabled passive response profile(s) successfully", len(passiveRes))

	loadingFrom := provider.From()
	if !cfg.OnlyProofOfConcept {
		if len(loadingFrom) == 1 {
			pterm.Info.Printf("Loading profiles from: %s\n", loadingFrom[0])
		} else {
			pterm.Info.Printf(
				`Loading profiles from... 
	- %s
`, strings.Join(provider.From(), "\n\t- "))
		}
	}

	if !cfg.OnlyProofOfConcept {
		pterm.Success.Printf(
			"Profiles loaded successfully... active(s): %d, passive request(s): %d, passive response(s): %d\n",
			len(actives), len(passiveReqs), len(passiveRes),
		)
	}

	if len(cfg.FilterTags) > 0 {
		logger.For(ctx).Infof("Filtering loaded profiles by tag: %s", cfg.FilterTags.String())

		actives = filter(ctx, actives, cfg.FilterTags)
		passiveReqs = filter(ctx, passiveReqs, cfg.FilterTags)
		passiveRes = filter(ctx, passiveRes, cfg.FilterTags)

		logger.For(ctx).Infof("Active profile(s) remaining after filtering by tag: %d", len(actives))
		logger.For(ctx).Infof("Passive request profile(s) remaining after filtering by tag: %d", len(passiveReqs))
		logger.For(ctx).Infof("Passive response profile(s) remaining after filtering by tag: %d", len(passiveRes))

		if !cfg.OnlyProofOfConcept {
			pterm.Success.Printf(
				"Profiles filtered (%s) successfully, remaining... active(s): %d, passive request(s): %d, passive response(s): %d\n",
				cfg.FilterTags.String(), len(actives), len(passiveReqs), len(passiveRes),
			)
		}
	}

	return actives, passiveReqs, passiveRes
}

func filter[P profile.Profile](ctx context.Context, profiles []P, tags []string) []P {
	filtered := make([]P, 0, len(profiles))
	for _, p := range profiles {
		ok := shouldBeIncluded(p, tags)
		if ok {
			filtered = append(filtered, p)
		}

		logger.For(ctx).Debugf("Profile loaded successfully, name=%s, type=%s skipped=%t", p.GetName(), p.GetType(), !ok)
	}

	return filtered
}

// shouldBeIncluded could be easily improved by using maps instead
// of slices, but it should impact the performance of the executions.
func shouldBeIncluded[P profile.Profile](prof P, tags []string) bool {
	for _, t0 := range prof.GetTags() {
		for _, t1 := range tags {
			if strings.EqualFold(t0, t1) {
				return true
			}
		}
	}

	return false
}

func finalizeScan(
	ctx context.Context,
	updatesChan chan *gbounty.Stats,
	pbPrinter *progressbar.Printer,
	cfg gbounty.Config,
	fs gbounty.FileSystem,
	id string,
) func(*gbounty.Stats, error) {
	return func(stats *gbounty.Stats, err error) {
		logger.For(ctx).Info("Finalizing scan...")

		var stopped bool

		defer func() {
			if cfg.SaveOnStop && stopped {
				logger.For(ctx).Info("Scan stopped with 'save on stop' enabled, not cleaning up...")
				return
			}

			logger.For(ctx).Info("Cleaning up scan temporary files...")
			err := fs.Cleanup(ctx)
			if err != nil {
				logger.For(ctx).Errorf("Error while cleaning up scan temporary files: %s", err.Error())
				if !cfg.OnlyProofOfConcept {
					pterm.Error.WithShowLineNumber(false).Printf(`Error while cleaning up temporary files: %s`, err)
				}
			}
		}()

		close(updatesChan)
		time.Sleep(time.Millisecond)

		// Before we actually start the finalization, we first stop
		// the progress bar printer, if it's not nil, to clean up screen.
		if pbPrinter != nil {
			_, _ = pbPrinter.Stop()
		}

		if errors.Is(err, context.Canceled) && cfg.SaveOnStop {
			logger.For(ctx).Info("Scan stopped and 'save on stop' is enabled, saving data...")
			err2 := fs.StoreStats(ctx, stats)
			if err2 != nil {
				logger.For(ctx).Errorf("Error while saving scan data: %s", err.Error())
				if !cfg.OnlyProofOfConcept {
					pterm.Error.WithShowLineNumber(false).Printf(`Error while stopping scan: %s`, err)
				}
			}

			stopped = true

			if !cfg.OnlyProofOfConcept {
				pterm.Success.Printf("Scan paused successfully, to continue use: %s\n", id)
			}

			return
		}

		if stats == nil || (err != nil && !errors.Is(err, context.Canceled)) {
			logger.For(ctx).Errorf("Unexpected error: %s", err.Error())
			return
		}

		// We declare the console writer that
		// will (most likely) be used below later.
		var consoleWriter gbounty.Writer
		if cfg.OnlyProofOfConcept {
			consoleWriter = writer.NewPlain(os.Stdout, writer.WithProofOfConceptEnabled(cfg.OnlyProofOfConcept))
		} else {
			consoleWriter = writer.NewConsole(os.Stdout)
		}

		// We write the results to the specified output.
		if len(cfg.OutPath) > 0 {
			logger.For(ctx).Infof("Storing scan output to: %s", cfg.OutPath)
			storeOutput(ctx, cfg, fs)

			// If no silent, we print the summary as well.
			if !cfg.Silent || !cfg.OnlyProofOfConcept {
				if err := consoleWriter.WriteStats(ctx, fs); err != nil {
					pterm.Error.WithShowLineNumber(false).Printf(`Error while printing scan stats: %s`, err)
					logger.For(ctx).Errorf("Error while printing scan stats: %s", err)
				}

				if err := consoleWriter.WriteMatchesSummary(ctx, fs); err != nil {
					pterm.Error.WithShowLineNumber(false).Printf(`Error while printing matches summary: %s`, err)
					logger.For(ctx).Errorf("Error while printing matches summary: %s", err)
				}
			}
			// Otherwise, in case there's no output nor
			// silent mode, we print the results in the console.
		} else if !cfg.Silent {
			err := writeScanFromFs(ctx, consoleWriter, cfg, fs)
			if err != nil {
				pterm.Error.WithShowLineNumber(false).Printf(`Error while printing scan results: %s`, err)
				logger.For(ctx).Errorf("Error while printing scan results: %s", err)
			}
		}
	}
}

func storeOutput(ctx context.Context, cfg gbounty.Config, fs gbounty.FileSystem) {
	logger.For(ctx).Debugf("Creating file to save scan output: %s", cfg.OutPath)
	file, err := os.Create(cfg.OutPath)
	if err != nil {
		logger.For(ctx).Errorf("Error while creating file to save scan output: %s", err.Error())
		handleStoreOutputErr(cfg, err)
		return
	}

	logger.For(ctx).Infof("Storing scan output in %s format", cfg.OutFormat)

	switch cfg.OutFormat {
	case "json":
		logger.For(ctx).Debug("Storing scan output as json")
		err = storeJSONOutput(ctx, cfg, fs, file)
	case "markdown":
		logger.For(ctx).Debug("Storing scan output as markdown")
		err = writeScanFromFs(ctx, writer.NewMarkdown(file), cfg, fs)
	default:
		logger.For(ctx).Debug("Storing scan output as plain text")
		err = writeScanFromFs(ctx, writer.NewPlain(file), cfg, fs)
	}

	if err != nil {
		logger.For(ctx).Errorf("Error while storing scan output: %s", err.Error())
		handleStoreOutputErr(cfg, err)
	}
}

func storeJSONOutput(ctx context.Context, cfg gbounty.Config, fs gbounty.FileSystem, to io.Writer) error {
	_, err := fmt.Fprintf(to, "{")
	if err != nil {
		return err
	}

	err = writeScanFromFs(ctx, writer.NewJSON(to), cfg, fs)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(to, `
}`)

	return err
}

func writeScanFromFs(ctx context.Context, w gbounty.Writer, cfg gbounty.Config, fs gbounty.FileSystem) error {
	_, isConsole := w.(*writer.Console)
	if !isConsole {
		_, isPlain := w.(*writer.Plain)
		isConsole = isPlain && len(cfg.OutPath) == 0
	}

	if !isConsole {
		err := writeConfig(ctx, w, cfg)
		if err != nil {
			return err
		}
	}

	err := w.WriteStats(ctx, fs)
	if err != nil {
		return err
	}

	err = w.WriteMatchesSummary(ctx, fs)
	if err != nil {
		return err
	}

	if cfg.ShowErrors && !(isConsole && cfg.StreamErrors) {
		err = w.WriteErrors(ctx, fs)
		if err != nil {
			return err
		}
	}

	if !(isConsole && cfg.StreamMatches) {
		err = w.WriteMatches(ctx, fs, cfg.ShowResponses)
		if err != nil {
			return err
		}
	}

	if cfg.ShowAll || cfg.ShowAllRequests || cfg.ShowAllResponses {
		err = w.WriteTasks(ctx, fs, cfg.ShowAllRequests, cfg.ShowAllResponses)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeConfig(ctx context.Context, writer gbounty.Writer, cfg gbounty.Config) error {
	if cfg.OnlyProofOfConcept {
		logger.For(ctx).Debug("OnlyProofOfConcept mode enabled: scan configuration not displayed in the output")
		return nil
	}

	if cfg.Silent {
		logger.For(ctx).Debug("Silent mode enabled: scan configuration not displayed in the output")
		return nil
	}

	logger.For(ctx).Debug("Writing scan configuration")
	return writer.WriteConfig(ctx, cfg)
}

func handleStoreOutputErr(cfg gbounty.Config, err error) {
	var pathErr *os.PathError

	if errors.As(err, &pathErr) {
		pterm.Error.WithShowLineNumber(false).Printf(
			`Error while storing output(%s): %s`, cfg.OutPath, pathErr.Err,
		)

		return
	}

	pterm.Error.WithShowLineNumber(false).Printf(
		`Error while storing output(%s): %s`, cfg.OutPath, err,
	)
}

//nolint:nolintlint,gosec
func initDebugServer(ctx context.Context) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/debug/pprof/", pprof.Index)

	srv := &http.Server{Addr: debugServerAddr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.For(ctx).Debugf("Debug server error: %s", err.Error())
		} else {
			logger.For(ctx).Debug("Debug server shut down successfully")
		}
	}()

	return srv
}
