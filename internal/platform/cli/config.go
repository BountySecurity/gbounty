package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/bountysecurity/gbounty/kit/blindhost"
	"github.com/bountysecurity/gbounty/kit/logger"
	"github.com/bountysecurity/gbounty/kit/url"
)

const (
	defaultParamsSplit  = 10
	defaultParamsMethod = http.MethodGet
	defaultParamsEncode = "url"
)

// Verbosity is a structure used to capture the corresponding [logger.Level]
// from configuration (command-line) options, including whether it's
// [logger.LevelDebug], [logger.LevelInfo], [logger.LevelWarn] or disabled.
type Verbosity struct {
	Debug  bool
	Info   bool
	Warn   bool
	Output string
}

// Level returns the corresponding [logger.Level] from a [Verbosity] instance.
func (v Verbosity) Level() logger.Level {
	switch {
	case v.Debug:
		return logger.LevelDebug
	case v.Info:
		return logger.LevelInfo
	case v.Warn:
		return logger.LevelWarn
	}

	return logger.LevelDisabled
}

// Config is the set of the different command-line configuration options.
type Config struct {
	// SaveOnStop determines whether the scan will be saved when stopped.
	SaveOnStop bool
	// Continue contains the scan's identifier to be used to continue.
	Continue string
	// URLS specifies the list of URLs used to define the scan.
	URLS MultiValue
	// URLSFile specifies the path to the URLs file to define the scan.
	URLSFile string
	// RequestsFile specifies the path to the request(s) file to define the scan.
	RequestsFile string
	// RawRequests specifies the path(s) to the raw request file(s) to define the scan.
	RawRequests MultiValue
	// ParamsFile specifies the path to the paths file to define the scan.
	ParamsFile string
	// ParamsSplit determines the size of the params groups the params from file will be
	// grouped into.
	ParamsSplit int
	// ParamsMethod determines the HTTP method that will be used to inject the params
	// into the request.
	ParamsMethod string
	// ParamsEncoding specifies the encoding that will be used to inject the params
	// into the request.
	ParamsEncoding string
	// Method specifies the HTTP method used to define the scan's requests.
	Method string
	// Headers specifies the HTTP header(s) used to define the scan's requests.
	Headers MultiValue
	// Data specifies the body's data used to define the scan's requests.
	Data MultiValue
	// ProfilesPath specifies the paths to the directories/files containing profiles.
	ProfilesPath MultiValue
	// Concurrency determines the amount of URLs scanned at the same time (concurrently).
	Concurrency int
	// RPS determines the maximum amount of requests per second per each URL.
	RPS int
	// OnlyActive determines whether the scan will only use active profiles.
	OnlyActive bool
	// OnlyPassive determines whether the scan will only use passive profiles.
	OnlyPassive bool
	// OnlyPassiveReq determines whether the scan will only use passive request profiles.
	OnlyPassiveReq bool
	// OnlyPassiveRes determines whether the scan will only use passive response profiles.
	OnlyPassiveRes bool
	// OutPath specifies the path where the scan output will be written to.
	OutPath string
	// OutFormat specifies the format the scan output will be written.
	OutFormat string
	// Silent determines whether the scan summary will be printed.
	Silent bool
	// ShowAll determines whether all the scan tasks will be printed.
	ShowAll bool
	// ShowAllRequests determines whether the scan details will include all requests.
	ShowAllRequests bool
	// ShowAllResponses determines whether the scan details will include all responses.
	ShowAllResponses bool
	// ShowErrors determines whether errors happened will be printed.
	ShowErrors bool
	// ShowResponses determines whether matches responses will be printed.
	ShowResponses bool
	// StreamErrors determines whether errors happened will be streamed.
	StreamErrors bool
	// StreamMatches determines whether matches found will be streamed.
	StreamMatches bool
	// ShowHelp determines whether the help flag has been provided.
	ShowHelp bool
	// PrintTags determines whether the show tags flag has been provided.
	PrintTags bool
	// InMemory determines whether the scan uses memory as storage.
	InMemory bool
	// FilterTags determines whether enabled profiles will be filtered by provided tags.
	FilterTags MultiValue
	// BlindHost determines the host that will be used for interactions.
	BlindHost string
	// EmailAddress determines the email address that will be used during the scan.
	EmailAddress string
	// CustomTokens can be used to replace certain tokens or labels (like {MY_TOKEN}) with
	// user-configured values.
	CustomTokens map[string]string
	// ProxyAddress determines the proxy host and port that will be used during the scan.
	ProxyAddress string
	// ProxyAuth determines the proxy auth that will be used during the scan.
	ProxyAuth string
	// Verbosity determines the level of verbosity for the internal logger.
	Verbosity Verbosity
	// Update determines whether both app and profiles will be updated.
	Update bool
	// UpdateApp determines whether the app will be updated.
	UpdateApp bool
	// UpdateProfiles determines whether profiles will be updated.
	UpdateProfiles bool
}

// ScanAllProfiles returns true if [Config] is set to return a subset of any specific
// type of [profile], either [profile.Active], [profile.Request] or [profile.Response].
func (cfg Config) ScanAllProfiles() bool {
	return !cfg.OnlyActive && !cfg.OnlyPassive && !cfg.OnlyPassiveReq && !cfg.OnlyPassiveRes
}

// GetRPS returns the value set as the RPS (request per second).
func (cfg Config) GetRPS() int {
	return cfg.RPS
}

// AnyUpdate returns true if [Config] is set to perform any kind of update.
func (cfg Config) AnyUpdate() bool {
	return cfg.Update || cfg.UpdateApp || cfg.UpdateProfiles
}

// AppUpdate returns true if [Config] is set to perform an application update.
func (cfg Config) AppUpdate() bool {
	return cfg.Update || cfg.UpdateApp
}

// ProfUpdate returns true if [Config] is set to perform a profiles update.
func (cfg Config) ProfUpdate() bool {
	return cfg.Update || cfg.UpdateProfiles
}

// Validate validates the [Config] and returns an [error] if it isn't valid.
func (cfg Config) Validate() error {
	validations := []func() error{
		cfg.checkProfilesPathFound,
		cfg.checkInmemoryIncompatible,
		cfg.checkOnlyOneExecutionEntry,
		cfg.checkOnlyOneAllOption,
		cfg.checkExecutionEntryAcceptParams,
		cfg.checkValidURLS,
		cfg.checkValidConcurrency,
		cfg.checkValidRPS,
		cfg.checkOutputForAnyAllFlag,
		cfg.checkValidOutput,
		cfg.checkValidParamsFlag,
		cfg.checkInteractionHostIsValid,
	}

	for _, validation := range validations {
		if err := validation(); err != nil {
			return err
		}
	}

	return nil
}

func (cfg Config) checkProfilesPathFound() error {
	if len(cfg.ProfilesPath) == 0 || (len(cfg.ProfilesPath) == 1 && len(cfg.ProfilesPath[0]) == 0) {
		return errors.New(
			"no profiles path (-p/--profiles) specified nor default one found",
		)
	}

	return nil
}

func (cfg Config) checkInmemoryIncompatible() error {
	if cfg.SaveOnStop && cfg.InMemory {
		return errors.New(
			"you cannot use -sos/--save-on-stop on memory-only (-m/--inmem) executions",
		)
	}

	return nil
}

func (cfg Config) checkOnlyOneExecutionEntry() error {
	if cfg.rawURLSAndFileDefined() || cfg.multipleFilesDefined() || cfg.noEntriesDefined() {
		return errors.New(
			"you must specify either URL(s) (-u/--url), a URLs file (-uf/--urls-file), a request(s) file (-rf/--requests-file) or some raw request file(s) (-rr/--raw-request)",
		)
	}

	return nil
}

func (cfg Config) checkOnlyOneAllOption() error {
	if (cfg.ShowAll && cfg.ShowAllRequests) || (cfg.ShowAll && cfg.ShowAllResponses) ||
		(cfg.ShowAllRequests && cfg.ShowAllResponses) {
		return errors.New(
			"you must specify either show all requests and responses (-a/--all), or more specifically all requests (-areq/--all-requests) or all responses (-ares/--all-responses), but not both",
		)
	}

	return nil
}

func (cfg Config) checkExecutionEntryAcceptParams() error {
	if cfg.requestsFileDefined() && cfg.requestOptsDefined() {
		return errors.New(
			"you must specify either URL(s) (with -u/--url, or with -uf/--urls-file) with some options (-X, -H, -d) or a request(s) file (-rf/--requests-file) or some raw request file(s) (-rr/--raw-request)",
		)
	}

	return nil
}

func (cfg Config) checkValidConcurrency() error {
	if !(cfg.Concurrency > 0) {
		return errors.New("you must specify a concurrency (-c/--concurrency) higher than zero")
	}

	return nil
}

func (cfg Config) checkValidRPS() error {
	if !(cfg.RPS > 0) {
		return errors.New(
			"you must specify an amount of req/s (-r/--rps) higher than zero",
		)
	}

	return nil
}

func (cfg Config) checkValidURLS() error {
	if len(cfg.URLS) == 0 {
		return nil
	}

	for idx := range cfg.URLS {
		err := url.Validate(&cfg.URLS[idx])
		if err != nil {
			return err
		}
	}

	return nil
}

func (cfg Config) checkOutputForAnyAllFlag() error {
	if (cfg.ShowAll || cfg.ShowAllRequests || cfg.ShowAllResponses) && len(cfg.OutPath) == 0 {
		return errors.New(
			"to include all requests and/or all responses within results, you must specify an output file path (-o/--output <path>)",
		)
	}

	return nil
}

func (cfg Config) checkValidOutput() error {
	if len(cfg.OutPath) == 0 {
		return nil
	}

	f, err := os.Create(cfg.OutPath)
	if err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok {
			return fmt.Errorf(`invalid output path: "%s" - %s`, cfg.OutPath, pathErr.Err)
		}

		return fmt.Errorf(`invalid output path: "%s" - %s`, cfg.OutPath, err)
	}

	f.Close()

	return nil
}

func (cfg Config) checkValidParamsFlag() error {
	// Case insensitiveness
	cfg.ParamsMethod = strings.ToUpper(cfg.ParamsMethod)
	cfg.ParamsEncoding = strings.ToLower(cfg.ParamsEncoding)

	// No params file defined
	if len(cfg.ParamsFile) == 0 {
		// No default (10), therefore explicitly defined
		if cfg.ParamsSplit != defaultParamsSplit {
			return errors.New(
				"you must specify a parameters file (with -pf/--params-file) to make use of the parameters split (-ps/--params-split)",
			)
		}
		// No default (GET), therefore explicitly defined
		if cfg.ParamsMethod != defaultParamsMethod {
			return errors.New(
				"you must specify a parameters file (with -pf/--params-file) to make use of the parameters method (-pm/--params-method)",
			)
		}
		// No default (url), therefore explicitly defined
		if cfg.ParamsEncoding != defaultParamsEncode {
			return errors.New(
				"you must specify a parameters file (with -pf/--params-file) to make use of the parameters method (-pe/--params-encoding)",
			)
		}
		// All defaults, nothing to check
		return nil
	}

	// Not any of the supported values
	if cfg.ParamsMethod != http.MethodGet && cfg.ParamsMethod != http.MethodPost {
		return fmt.Errorf(`the provided parameters method (-pm/--params-method) is invalid: "%s" - only "GET and "POST" are supported"`, cfg.ParamsMethod)
	}

	// Not any of the supported values
	if cfg.ParamsEncoding != "url" && cfg.ParamsEncoding != "json" {
		return fmt.Errorf(`the provided parameters encoding (-pe/--params-encoding) is invalid: "%s" - only "url and "json" are supported"`, cfg.ParamsMethod)
	}

	info, err := os.Stat(cfg.ParamsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf(`the provided parameters file does not exist: "%s"`, cfg.ParamsFile)
		}

		return fmt.Errorf(`the provided parameters file is invalid: "%s" - %s`, cfg.OutPath, err.Error())
	}

	if info.IsDir() {
		return fmt.Errorf(`the provided parameters file is a directory: "%s"`, cfg.ParamsFile)
	}

	return nil
}

func (cfg Config) checkInteractionHostIsValid() error {
	if len(cfg.BlindHost) > 0 {
		_, err := blindhost.NewClient(cfg.BlindHost)
		if err != nil {
			return err
		}
	}
	return nil
}

func (cfg Config) rawURLSAndFileDefined() bool {
	return cfg.rawURLSDefined() && cfg.eitherFileDefined()
}

func (cfg Config) noEntriesDefined() bool {
	return !cfg.eitherFileDefined() && !cfg.rawURLSDefined()
}

func (cfg Config) eitherFileDefined() bool {
	return cfg.urlsFileDefined() || cfg.requestsFileDefined() || cfg.rawRequestsFilesDefined()
}

func (cfg Config) multipleFilesDefined() bool {
	return (cfg.urlsFileDefined() && cfg.requestsFileDefined() && cfg.rawRequestsFilesDefined()) ||
		(cfg.urlsFileDefined() && cfg.requestsFileDefined()) ||
		(cfg.urlsFileDefined() && cfg.rawRequestsFilesDefined()) ||
		(cfg.requestsFileDefined() && cfg.rawRequestsFilesDefined())
}

func (cfg Config) urlsFileDefined() bool {
	return len(cfg.URLSFile) > 0
}

func (cfg Config) requestsFileDefined() bool {
	return len(cfg.RequestsFile) > 0
}

func (cfg Config) rawRequestsFilesDefined() bool {
	return len(cfg.RawRequests) > 0
}

func (cfg Config) rawURLSDefined() bool {
	return len(cfg.URLS) > 0
}

func (cfg Config) requestOptsDefined() bool {
	return cfg.Method != "" || len(cfg.Headers) > 0 || len(cfg.Data) > 0
}
