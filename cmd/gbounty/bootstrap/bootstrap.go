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
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/pterm/pterm"
	"github.com/spf13/afero"
	"golang.org/x/sync/errgroup"

	"github.com/bountysecurity/gbounty"
	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/modifier"
	"github.com/bountysecurity/gbounty/internal/platform/cli"
	"github.com/bountysecurity/gbounty/internal/platform/filesystem"
	"github.com/bountysecurity/gbounty/internal/platform/http/client"
	"github.com/bountysecurity/gbounty/internal/platform/writer"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/blindhost"
	"github.com/bountysecurity/gbounty/kit/logger"
	"github.com/bountysecurity/gbounty/kit/panics"
	"github.com/bountysecurity/gbounty/kit/strings/occurrence"
	"github.com/bountysecurity/gbounty/kit/ulid"
)

const (
	debugServerAddr         = "localhost:6060"
	debugServerShutdownTime = 5 * time.Second
)

var (
	PocEnabled = isPocEnabled()
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

	updatesChan := make(chan *scan.Stats)

	// We set everything up,
	// ready for the scan to start.
	g, gCtx := errgroup.WithContext(ctx)
	g.Go(printUpdates(gCtx, updatesChan))
	g.Go(runScan(gCtx, cfg, profilesProvider, updatesChan))
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

func isPocEnabled() bool {
	cfg, _ := parseCLIArgs()

	if cfg.Poc {
		return true
	}

	return false
}

func printUpdates(ctx context.Context, updatesChan chan *scan.Stats) func() error {
	return func() error {
		defer panics.Log(ctx)

		var p *pterm.ProgressbarPrinter

		initBar := func() error {
			var err error

			p, err = pterm.DefaultProgressbar.
				WithBarStyle(pterm.NewStyle(pterm.FgLightCyan)).
				WithTitleStyle(pterm.NewStyle(pterm.FgLightMagenta)).
				WithRemoveWhenDone(true).
				Start()

			return err
		}

		for {
			select {
			case stats, ok := <-updatesChan:
				// Channel closed, no more updates
				if !ok {
					return nil
				}

				// Bar not initialized yet (first update)
				if p == nil {
					if err := initBar(); err != nil {
						return err
					}
				}

				// Regular update, just update the bar
				total := stats.NumOfTotalRequests
				if total < stats.NumOfPerformedRequests {
					total = stats.NumOfPerformedRequests
				}

				p.Title = fmt.Sprintf("Scanning... [%d / %d]", stats.NumOfPerformedRequests, total)
				p.Total = total
				p.ShowCount = false
				p.Current = stats.NumOfPerformedRequests
				p.Add(0) // force print

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
	updatesChan chan *scan.Stats,
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

		var opts []client.Opt

		if len(cfg.ProxyAddress) > 0 {
			opts = append(opts, client.WithProxyAddr(cfg.ProxyAddress))
			logger.For(ctx).Debugf("The HTTP client is using a proxy address: %s", cfg.ProxyAddress)
		}

		if len(cfg.ProxyAuth) > 0 {
			opts = append(opts, client.WithProxyAuth(cfg.ProxyAuth))
			logger.For(ctx).Debugf("The HTTP client is using a proxy auth: %s", cfg.ProxyAuth)
		}

		maxConcurrentRequests := 1_000
		if stringVal, defined := os.LookupEnv("GBOUNTY_MAX_CONCURRENT_REQUESTS"); defined {
			if n, err := strconv.ParseInt(stringVal, 10, 32); err == nil {
				maxConcurrentRequests = int(n)
			}
		}
		getClient := client.NewPool(ctx, uint32(maxConcurrentRequests), opts...)
		newClientFn := func() (scan.Requester, error) { return getClient() }

		// Initialize scan configuration from CLI arguments.
		scanCfg := configFromArgs(cfg)

		// Set up modifiers (including blind host interactions).
		var (
			bhPoller  scan.BlindHostPoller
			modifiers = make([]scan.Modifier, 0)
		)
		if len(cfg.BlindHost) > 0 {
			hid := blindhost.RandomHostIdentifier()
			bhClient, err := blindhost.NewClient(cfg.BlindHost)
			if err != nil {
				logger.For(ctx).Errorf("Could not initialize blind host client: %s", err)
			} else {
				bhPoller, err = blindhost.NewPoller(bhClient, blindhost.WithContext(ctx), blindhost.WithHostIdentifier(hid))
				if err != nil {
					logger.For(ctx).Errorf("Could not initialize blind host poller: %s", err)
				} else {
					modifiers = append(modifiers, modifier.NewInteractionHost(cfg.BlindHost, hid))
					scanCfg.BlindHost = hid.HostBaseURL(cfg.BlindHost)
					scanCfg.BlindHostKey = hid.PrivateKey()
					logger.For(ctx).Infof("Blind host is set to: %s", scanCfg.BlindHost)
				}
			}
		}
		modifiers = modifiersFromConfig(ctx, cfg, modifiers)
		// End of modifiers section

		runnerOpts := new(scan.RunnerOpts).
			WithContext(ctx).
			WithConfiguration(scanCfg).
			WithEntrypointFinders(entrypoint.Finders()).
			WithModifiers(modifiers).
			WithBlindHostPoller(bhPoller).
			WithActiveProfiles(actives).
			WithPassiveReqProfiles(passiveReqs).
			WithPassiveResProfiles(passiveRes).
			WithRequesterBuilder(newClientFn).
			WithOnUpdated(func(stats *scan.Stats) { updatesChan <- stats }).
			WithOnFinished(finalizeScan(ctx, updatesChan, scanCfg, fs, id)).
			WithSaveAllRequests(cfg.ShowAll || cfg.ShowAllRequests).
			WithSaveResponses(cfg.ShowResponses).
			WithSaveAllResponses(cfg.ShowAll || cfg.ShowAllResponses).
			WithFileSystem(fs)

		w := writer.NewConsole(os.Stdout)

		if cfg.StreamErrors && !cfg.Silent {
			logger.For(ctx).Info("Errors streaming enabled")

			runnerOpts.WithOnError(func(ctx context.Context, url string, reqs []*request.Request, res []*response.Response, err error) {
				if writeErr := w.WriteError(
					ctx,
					scan.Error{
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
					scan.Match{
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
					}, cfg.ShowResponses, PocEnabled,
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

		return scan.NewRunner(runnerOpts).Start()
	}
}

func modifiersFromConfig(ctx context.Context, cfg cli.Config, given []scan.Modifier) []scan.Modifier {
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
		cancel(fmt.Errorf("scan interrupted manually, signal: %s", sign.String())) //nolint:goerr113
	}()

	return ctx
}

func configFromArgs(cfg cli.Config) scan.Config {
	return scan.Config{
		RPS:          cfg.Rps,
		Concurrency:  cfg.Concurrency,
		Version:      gbounty.Version,
		SaveOnStop:   cfg.SaveOnStop,
		InMemory:     cfg.InMemory,
		EmailAddress: len(cfg.EmailAddress) > 0,

		Silent:           cfg.Silent,
		StreamErrors:     cfg.StreamErrors,
		StreamMatches:    cfg.StreamMatches,
		ShowResponses:    cfg.ShowResponses,
		ShowErrors:       cfg.ShowErrors,
		ShowAll:          cfg.ShowAll,
		ShowAllRequests:  cfg.ShowAllRequests,
		ShowAllResponses: cfg.ShowAllResponses,
		OutPath:          cfg.OutPath,
		OutFormat:        cfg.OutFormat,
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
	if len(loadingFrom) == 1 {
		if !PocEnabled {
			pterm.Info.Printf("Loading profiles from: %s\n", loadingFrom[0])
		}
	} else {
		pterm.Info.Printf(
			`Loading profiles from... 
	- %s
`, strings.Join(provider.From(), "\n\t- "))
	}

	if !PocEnabled {
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

		pterm.Success.Printf(
			"Profiles filtered (%s) successfully, remaining... active(s): %d, passive request(s): %d, passive response(s): %d\n",
			cfg.FilterTags.String(), len(actives), len(passiveReqs), len(passiveRes),
		)
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

func finalizeScan(ctx context.Context, updatesChan chan *scan.Stats, cfg scan.Config, fs scan.FileSystem, id string) func(*scan.Stats, error) {
	return func(stats *scan.Stats, err error) {
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
				pterm.Error.WithShowLineNumber(false).Printf(`Error while cleaning up temporary files: %s`, err)
			}
		}()

		close(updatesChan)
		time.Sleep(time.Millisecond)

		if errors.Is(err, context.Canceled) && cfg.SaveOnStop {
			logger.For(ctx).Info("Scan stopped and 'save on stop' is enabled, saving data...")
			err2 := fs.StoreStats(ctx, stats)
			if err2 != nil {
				logger.For(ctx).Errorf("Error while saving scan data: %s", err.Error())
				pterm.Error.WithShowLineNumber(false).Printf(`Error while stopping scan: %s`, err)
			}

			stopped = true

			pterm.Success.Printf("Scan paused successfully, to continue use: %s\n", id)

			return
		}

		if stats == nil || (err != nil && !errors.Is(err, context.Canceled)) {
			logger.For(ctx).Errorf("Unexpected error: %s", err.Error())
			return
		}

		// We declare the console writer that
		// will (most likely) be used below later.
		consoleWriter := writer.NewConsole(os.Stdout)

		// We write the results to the specified output.
		if len(cfg.OutPath) > 0 {
			logger.For(ctx).Infof("Storing scan output to: %s", cfg.OutPath)
			storeOutput(ctx, cfg, fs)

			// If no silent, we print the summary as well.
			if !cfg.Silent || !PocEnabled {
				if err := consoleWriter.WriteStats(ctx, fs); err != nil {
					pterm.Error.WithShowLineNumber(false).Printf(`Error while printing scan stats: %s`, err)
					logger.For(ctx).Errorf("Error while printing scan stats: %s", err)
				}

				if err := consoleWriter.WriteMatchesSummary(ctx, fs, PocEnabled); err != nil {
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

func storeOutput(ctx context.Context, cfg scan.Config, fs scan.FileSystem) {
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

func storeJSONOutput(ctx context.Context, cfg scan.Config, fs scan.FileSystem, to io.Writer) error {
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

func writeScanFromFs(ctx context.Context, w scan.Writer, cfg scan.Config, fs scan.FileSystem) error {
	_, isConsole := w.(writer.Console)
	if !isConsole {
		err := writeConfig(ctx, w, cfg)
		if err != nil {
			return err
		}
	}

	var err error

	if !PocEnabled {
		err = w.WriteStats(ctx, fs)
	}
	if err != nil {
		return err
	}

	if !PocEnabled {
		err = w.WriteMatchesSummary(ctx, fs, PocEnabled)
	}
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

func writeConfig(ctx context.Context, writer scan.Writer, cfg scan.Config) error {
	if PocEnabled {
		return nil
	}
	if cfg.Silent {
		logger.For(ctx).Debug("Silent mode enabled: scan configuration not displayed in the output")
		return nil
	}

	logger.For(ctx).Debug("Writing scan configuration")
	return writer.WriteConfig(ctx, cfg)
}

func handleStoreOutputErr(cfg scan.Config, err error) {
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
