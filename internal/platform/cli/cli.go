package cli

import (
	"flag"
	"io"
	"os"

	"github.com/BountySecurity/gbounty/kit/getopt"
)

const (
	target     = "target"
	targetOpts = "target-opts"
	profile    = "profile"
	runtime    = "runtime"
	output     = "output"
	debug      = "debug"
)

// Parse parses a slice of strings as a list of arguments (e.g. [os.Args]), and
// constructs a [Config] based on those. If any error occurs during parsing,
// it is returned, and in such case the returned [Config] is empty.
func Parse(args []string) (Config, error) {
	config := Config{}

	fs := getopt.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// No group
	fs.BoolVar("", &config.ShowHelp, "help", false, "Show help")
	fs.Alias("h", "help")

	fs.BoolVar("", &config.Update, "update", false, "Update the binary and profiles to the latest version")
	fs.BoolVar("", &config.UpdateApp, "update-app", false, "Update the binary to the latest version")
	fs.BoolVar("", &config.UpdateProfiles, "update-profiles", false, "Update profiles to the latest version")
	fs.BoolVar("", &config.ForceUpdateProfiles, "force-update-profiles", false, "Re-download the latest version of profiles")
	fs.BoolVar("", &config.CheckUpdates, "check-updates", false, "Check for available updates forcefully\n\tBy default, available updates are checked only once a day")

	// Target
	fs.InitGroup(target, "TARGET INPUT:")
	fs.Var(target, &config.URLS, "url", "If specified, it will be used as a target url\n\tCan be used more than once: -u url1 -u url2")
	fs.Alias("u", "url")
	fs.StringVar(target, &config.UrlsFile, "urls-file", "", "If specified, each line present on the file will be used as a target urls")
	fs.Alias("uf", "urls-file")
	fs.StringVar(target, &config.RequestsFile, "requests-file", "", "If specified, each file present on the compressed file will be used as a target url and request template\n\tOnly zipped (.zip) requests files are supported")
	fs.Alias("rf", "requests-file")
	fs.Var(target, &config.RawRequests, "raw-request", "If specified, contents on given path will be used as a target url and request template\n\tCan be used more than once: --raw-request path/requests/req1.txt --raw-request path/requests/req2.txt\n\tThe host address must be in the first line before the raw request. Otherwise, the 'Host' header will be used")
	fs.Alias("rr", "raw-request")
	fs.StringVar(target, &config.ParamsFile, "params-file", "", "If specified, each line present on the file will be used as a request parameter\n\tUsed in combination with --params-split")
	fs.Alias("pf", "params-file")
	fs.IntVar(target, &config.ParamsSplit, "params-split", defaultParamsSplit, "Determines the amount of parameters (-pf/--params-file) included into each group (default: 10)\n\tUse one (1) to scan every param individually")
	fs.Alias("ps", "params-split")
	fs.StringVar(target, &config.ParamsMethod, "params-method", defaultParamsMethod, "Determines the HTTP method the params (-pf/--params-file) will be included into (default: \"GET\")\n\tSupported methods are: \"GET\" (url) and \"POST\" (www/url-encoded, body)")
	fs.Alias("pm", "params-method")
	fs.StringVar(target, &config.ParamsEncoding, "params-encoding", defaultParamsEncode, "Determines the encoding the params (-pf/--params-file) will be included into (default: \"url\")\n\tSupported encodings are: \"url\" (application/x-www-form-urlencoded) and \"json\" (application/json)\n\tOnly used when --params-method/-pm is set to \"POST\"")
	fs.Alias("pe", "params-encoding")
	fs.BoolVar(target, &config.ForceHTTP2, "http2", false, "Forces HTTP/2. If enabled, the proto from the request template, if present, will be ignored")
	fs.Alias("h2", "http2")

	// TargetOpts
	fs.InitGroup(targetOpts, "Options for --url (-u) and --urls-file:")
	fs.StringVar(targetOpts, &config.Method, "method", "", "If specified, it will be used as the HTTP method for request templates")
	fs.Alias("X", "method")
	fs.Var(targetOpts, &config.Headers, "header", "If specified, it will be used as the HTTP header(s) for request templates\n\tCan be used more than once: -H \"Accept: application/json\" -H \"Content-Type: application/json\"")
	fs.Alias("H", "header")
	fs.Var(targetOpts, &config.Data, "data", "If specified, it will be used as the HTTP body data for request templates")
	fs.Alias("d", "data")

	// Profile
	fs.InitGroup(profile, "PROFILE OPTIONS:")
	fs.Var(profile, &config.ProfilesPath, "profiles", "Determines the path where profile file(s) will be read from (default: \"./profiles/\")\n\tIt can also be used with the path to a specific profile file\n\tCan be used more than once: -p profiles/XSS.bb2 -p profiles/SQLi.bb2")
	fs.Alias("p", "profiles")
	fs.Var(profile, &config.FilterTags, "tag", "If specified, only profiles tagged with provided tags will be used\n\tCan be used more than once: -t tag1 -t tag2")
	fs.Alias("t", "tag")
	fs.BoolVar(profile, &config.OnlyActive, "only-active", false, "If specified, only active profiles will be analyzed during the scan")
	fs.Alias("active", "only-active")
	fs.BoolVar(profile, &config.OnlyPassive, "only-passive", false, "If specified, only passive profiles will be analyzed during the scan")
	fs.Alias("passive", "only-passive")
	fs.BoolVar(profile, &config.OnlyPassiveReq, "only-passive-req", false, "If specified, only passive request profiles will be analyzed during the scan")
	fs.Alias("psreq", "only-passive-req")
	fs.BoolVar(profile, &config.OnlyPassiveRes, "only-passive-res", false, "If specified, only passive response profiles will be analyzed during the scan")
	fs.Alias("psres", "only-passive-res")
	fs.BoolVar(profile, &config.PrintTags, "print-tags", false, "Print available profile tags\n\tUsed in combination with --tag")
	fs.Alias("tags", "print-tags")

	// Runtime
	fs.InitGroup(runtime, "RUNTIME OPTIONS:")
	const defaultConcurrency = 10
	fs.IntVar(runtime, &config.Concurrency, "concurrency", defaultConcurrency, "Determines how many target URL(s) will be scanned concurrently (default: 10)")
	fs.Alias("c", "concurrency")
	const defaultRps = 10
	fs.IntVar(runtime, &config.Rps, "rps", defaultRps, "Determines the limit of requests per second (per URL) (default: 10)")
	fs.Alias("r", "rps")
	fs.BoolVar(runtime, &config.StopAtFirstMatch, "stop-at-first-match", true, "If specified, the scan will stop at the first match found for each combination of\n\t(a) profile, (b) step and (c) entrypoint\n\tEnabled by default, can be disabled with --stop-at-first-match=false or -safm=false")
	fs.Alias("safm", "stop-at-first-match")
	fs.BoolVar(runtime, &config.Silent, "silent", false, "If specified, no results will be printed to stdout")
	fs.Alias("s", "silent")
	fs.StringVar(runtime, &config.BlindHost, "blind-host", "", "If specified, the blind host will be injected into {BH} labels")
	fs.Alias("bh", "blind-host")
	fs.StringVar(runtime, &config.EmailAddress, "email-address", "", "If specified, the email address will be injected into {EMAIL} labels")
	fs.Alias("email", "email-address")
	fs.StringVar(runtime, &config.ProxyAddress, "proxy-address", "", "If specified, requests are proxied to the given address\n\tTo specify host and port use 'host:port'")
	fs.StringVar(runtime, &config.ProxyAuth, "proxy-auth", "", "If specified, proxied requests will include authentication details")
	fs.BoolVar(runtime, &config.InMemory, "in-memory", false, "Use memory (only) as storage for intermediate scan results.\n\tOtherwise, it will use the filesystem (default)")
	fs.Alias("m", "in-memory")
	fs.BoolVar(runtime, &config.SaveOnStop, "save-on-stop", false, "Save the scan's status, when manually interrupted\n\tThe scan's identifier will be printed, to be used in combination with --from")
	fs.Alias("sos", "save-on-stop")
	fs.StringVar(runtime, &config.Continue, "from", "", "Scan's identifier to be used to continue from")
	fs.Alias("f", "from")

	// Output
	fs.InitGroup(output, "OUTPUT OPTIONS:")
	fs.StringVar(output, &config.OutPath, "output", "", "Determine the path where the output file will be stored to\n\tBy default, the output file is formatted as plain text")
	fs.Alias("o", "output")
	json := fs.Bool(output, "json", false, "If specified, the output file will be JSON-formatted\n\tBy default, the output file is formatted as plain text")
	fs.Alias("j", "json")
	markdown := fs.Bool(output, "markdown", false, "If specified, the output file will be Markdown-formatted\n\tBy default, the output file is formatted as plain text")
	fs.Alias("md", "markdown")
	fs.BoolVar(output, &config.ShowAll, "all", false, "If specified, results will include all requests and responses\n\tBy default, only those requests that caused a match are included in results\n\tAs it causes a noisy output, must be used in combination with -o/--output flag")
	fs.Alias("a", "all")
	fs.BoolVar(output, &config.ShowAllRequests, "all-requests", false, "If specified, results will include all requests\n\tBy default, only those requests that caused a match are included in results\n\tAs it causes a noisy output, must be used in combination with -o/--output flag")
	fs.Alias("areq", "all-requests")
	fs.BoolVar(output, &config.ShowAllResponses, "all-responses", false, "If specified, results will include all responses\n\tBy default, only those requests that caused a match, and no response, are included in results\n\tAs it causes a noisy output, must be used in combination with -o/--output flag")
	fs.Alias("ares", "all-responses")
	fs.BoolVar(output, &config.ShowErrors, "show-errors", false, "If specified, failed requests are included in results")
	fs.Alias("se", "show-errors")
	fs.BoolVar(output, &config.ShowResponses, "show-responses", false, "If specified, those requests that caused a match are printed with the corresponding response")
	fs.Alias("sr", "show-responses")
	fs.BoolVar(output, &config.StreamErrors, "stream-errors", false, "If specified, failed requests are printed to stdout during the scan (live)\n\tBy default, they are only printed at the end, only when the -se/--show-errors flag is provided")
	fs.Alias("ste", "stream-errors")
	fs.BoolVar(output, &config.StreamMatches, "stream-matches", true, "If specified, those requests that caused a match are printed to stdout during the scan (live)\n\tEnabled by default, can be disabled with --stream-matches=false or -stm=false")
	fs.Alias("stm", "stream-matches")
	fs.BoolVar(profile, &config.OnlyProofOfConcept, "only-poc", false, "If specified, only matched requests will be printed, nothing else.")
	fs.Alias("poc", "only-poc")

	// Debug
	fs.InitGroup(debug, "DEBUG OPTIONS:")
	fs.BoolVar(debug, &config.Verbosity.Warn, "verbose", false, "If specified, the internal logger will write warning and error log messages")
	fs.Alias("v", "verbose")
	fs.BoolVar(debug, &config.Verbosity.Info, "verbose-extra", false, "If specified, the internal logger will write info, warning and error log messages")
	fs.Alias("vv", "verbose-extra")
	fs.BoolVar(debug, &config.Verbosity.Debug, "verbose-all", false, "If specified, the internal logger will write debug, info, warning and error log messages")
	fs.Alias("vvv", "verbose-all")
	fs.StringVar(debug, &config.Verbosity.Output, "verbose-output", "", "If specified, the internal logger will write the log messages to a file\n\tBy default, those are printed to stdout")
	fs.Alias("vout", "verbose-output")

	fs.SetUsage(`
Usage:
  gbounty [flags]

Flags:`)

	fs.SetExamples(`EXAMPLES:
gbounty -u https://example.org -X POST -d "param1=value1&param2=value2" -t XSS -r 20 -a -o /tmp/results.json --json
gbounty --urls-file domains.txt -c 200 -r 10 -p /tmp/gbounty-profiles --silent --markdown -o /tmp/results.md
gbounty --requests-file requests.zip -r 150 --proxy-address=127.0.0.1:8080 -o /tmp/results.txt --all
gbounty --raw-request 1.txt --raw-request 2.txt --blind-host burpcollaborator.net`)

	if err := fs.Parse(os.Args[1:]); err != nil {
		return Config{}, err
	}

	if config.ShowHelp {
		fs.SetOutput(os.Stdout)
		fs.PrintDefaults()
	}

	switch {
	case *json:
		config.OutFormat = "json"
	case *markdown:
		config.OutFormat = "markdown"
	default:
		config.OutFormat = "plain"
	}

	return config, nil
}
