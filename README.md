<h1 align="center">
  <br>
  <a href="https://gbounty.bountysecurity.ai/">
        <img src="static/gbounty-logo.png" width="400px" alt="GBounty">
  </a>
</h1>

<h4 align="center">Fast, reliable, and highly customizable website vulnerability scanner.</h4>

<p align="center">
<a href="https://twitter.com/GBountySecurity"><img src="https://img.shields.io/twitter/follow/GBountySecurity.svg?logo=twitter"></a>
</p>

<p align="center">
  •
  <a href="#install-gbounty">Install</a> •
  <a href="https://gbounty.bountysecurity.ai" target="_blank">Documentation</a> •
</p>

---
[![Downloads](https://img.shields.io/github/downloads/bountysecurity/gbounty/total.svg)](https://github.com/bountysecurity/gbounty/releases)
[![Contributors](https://img.shields.io/github/contributors/bountysecurity/gbounty.svg)](https://github.com/bountysecurity/gbounty/graphs/contributors)

Multi-step website vulnerability scanner designed to help pentesters and bug hunters identify potential vulnerabilities in web applications.

We have a [dedicated repository](https://github.com/bountysecurity/gbounty-profiles) that houses various type of
web vulnerability profiles contributed by security researchers and engineers.

> [!WARNING]  
> **This project is in active development.** Expect breaking changes with releases. 
> Review the release changelog before updating.

> [!CAUTION]  
> This project was primarily built to be used as a standalone CLI tool. 
> **Running `gbounty` as a service may pose security risks.** 
> It's recommended to use with caution and additional security measures.

# Getting started 

## Install GBounty

To start using GBounty, you can either install it using [Go](https://go.dev/), or download one of the pre-compiled 
binaries from [GitHub Releases](https://github.com/BountySecurity/gbounty/releases).

### Installation with Go

GBounty requires **Go v1.21** to install successfully. Run the following command to install the latest 
version under development:

```sh
go install -v github.com/bountysecurity/gbounty/cmd/gbounty@main
```

### Installation with GitHub Releases

Navigate to the [GitHub Releases page](https://github.com/BountySecurity/gbounty/releases) and download the pre-compiled
binary of the latest version (or any other) for the operating system (Linux, macOS, or Windows) and architecture 
(amd64, arm64, 386...) of your preference.

### Other installation mechanism

Unfortunately, currently we don't have support for other installation mechanisms, like [Homebrew](https://brew.sh/),
[Snap](https://snapcraft.io/), [Choco](https://chocolatey.org/) or [Docker](https://www.docker.com/), but contributions
are welcome! _See [#1](https://github.com/BountySecurity/gbounty/issues/1), for instance._

### Usage

```sh
gbounty -h
```

This will display help for the tool.


```console
 INFO  GBounty is a multi-step web scanner that uses web vulnerability profiles
 INFO  GBounty profiles can be found at: https://github.com/BountySecurity/gbounty-profiles


Usage:
  gbounty [flags]

Flags:
  -h, --help
    	Show help
  --update
    	Update app and profiles
  --update-app
    	Update app
  --update-profiles
    	Update profiles
  --force-update-profiles
    	Update profiles forcefully

TARGET INPUT:
  -u, --url value
    	If specified, it will be used as the target url
	Can be used more than once: -u url1 -u url2
  -uf, --urls-file string
    	If specified, each line present on the file will be used as the target urls
  -rf, --requests-file string
    	If specified, each file present on the requests file will be used as the target url and request template
	Only zipped (.zip) requests files are supported
  -rr, --raw-request value
    	If specified, contents on given path will be used as the target url and request template
	Can be used more than once: --raw-request path/requests/req1.txt --raw-request path/requests/req2.txt
  -pf, --params-file string
    	If specified, each line present on the file will be used as a request parameter
	Used in combination with --params-split
  -ps, --params-split int
    	Determines the amount of parameters (-pf/--params-file) included into each group (default: 10)
	Use one (1) to scan every param individually
  -pm, --params-method string
    	Determines the HTTP method the params (-pf/--params-file) will be included into (default: "GET")
	Supported methods are: "GET" (url) and "POST" (www/url-encoded, body)
  -pe, --params-encoding string
    	Determines the encoding the params (-pf/--params-file) will be included into (default: "url")
	Supported encodings are: "url" (application/x-www-form-urlencoded) and "json" (application/json)
	Only used when --params-method/-pm is set to "POST"

Options for --url (-u) and --urls-file:
  -X, --method string
    	If specified, it will be used as default HTTP method for request templates
  -H, --header value
    	If specified, they will be used as the default HTTP header(s) for request templates
	Can be used more than once: -H "Accept: application/json" -H "Content-Type: application/json"
  -d, --data value
    	If specified, it will be used as the default HTTP body data for request templates

PROFILE OPTIONS:
  -p, --profiles value
    	Determines the path where profile file(s) will be read from (default: "./profiles/")
	It can also be used with the path to a specific profile file
	Can be used more than once: -p profiles/XSS.bb -p profiles/SQLi.bb
  -t, --tag value
    	If specified, only profiles tagged with provided tags will be used
	Can be used more than once: -t tag1 -t tag2
  -active, --only-active
    	If specified, only active profiles will be analyzed during the scan
  -passive, --only-passive
    	If specified, only passive profiles will be analyzed during the scan
  -psreq, --only-passive-req
    	If specified, only passive request profiles will be analyzed during the scan
  -psres, --only-passive-res
    	If specified, only passive response profiles will be analyzed during the scan
  -tags, --print-tags
    	Print available profile tags

RUNTIME OPTIONS:
  -c, --concurrency int
    	Determines how many target URL(s) will be scanned concurrently (default: 10)
  -r, --rps int
    	Determines the limit of requests per second (per URL) (default: 10)
  -s, --silent
    	If specified, no results will be printed to stdout
  -sos, --save-on-stop
    	Saves the scan's status when stopped
  -f, --from string
    	Scan's identifier to be used to continue
  -m, --in-memory
    	Use memory (only) as scan storage
  -ih, --interaction-host string
    	(Deprecated) If specified, the interaction host is injected into {IH}, {BH} and {BC} labels
  -bh, --blind-host string
    	If specified, the interaction host is injected into {IH}, {BH} and {BC} labels
  -email, --email-address string
    	If specified, the email address is injected into {EMAIL} labels
  --proxy-address string
    	If specified, requests are proxied to the given address
	To specify host and port use host:port
  --proxy-auth string
    	If specified, proxied requests will include authentication details

OUTPUT OPTIONS:
  -o, --output string
    	Determines the path where the output file will be stored to
	By default, the output file is formatted as plain text
  -j, --json
    	If specified, the output file will be JSON-formatted
	By default, the output file is formatted as plain text
  -md, --markdown
    	If specified, the output file will be Markdown-formatted
	By default, the output file is formatted as plain text
  -a, --all
    	If specified, results will include all requests and responses
	By default, only those requests that caused a match are included in results
	As it causes a noisy output, must be used in combination with -o/--output flag
  -areq, --all-requests
    	If specified, results will include all requests
	By default, only those requests that caused a match are included in results
	As it causes a noisy output, must be used in combination with -o/--output flag
  -ares, --all-responses
    	If specified, results will include all responses
	By default, only those requests that caused a match are included in results
	As it causes a noisy output, must be used in combination with -o/--output flag
  -se, --show-errors
    	If specified, failed requests are included in results
  -sr, --show-responses
    	If specified, those requests that caused a match are printed with the corresponding response
  -ste, --stream-errors
    	If specified, failed requests are printed to stdout during the scan (live)
	By default, they are only printed at the end, only when the -se/--show-errors flag is provided
  -stm, --stream-matches
    	If specified, those requests that caused a match are printed to stdout during the scan (live)
	Enabled by default, can be disabled with --stream-matches=false or -stm=false

DEBUG OPTIONS:
  -v, --verbose
    	If specified, the internal logger will write warning and error log messages
  -vv, --verbose-extra
    	If specified, the internal logger will write info, warning and error log messages
  -vvv, --verbose-all
    	If specified, the internal logger will write debug, info, warning and error log messages
  -vout, --verbose-output string
    	If specified, the internal logger will write the log messages to a file

EXAMPLES:
gbounty -u https://example.org -X POST -d "param1=value1&param2=value2" -t XSS -r 20 -a -o /tmp/results.json --json
gbounty --urls-file urls.txt -c 200 -r 10 -p /tmp/gbounty-profiles --silent --markdown -o /tmp/results.md
gbounty --raw-request raw_1.txt --raw-request raw_2.txt --blind-host yourblindhost.net
gbounty --requests-file requests.zip -r 150 --proxy-address=127.0.0.1:8080 -o /tmp/results.txt --all
```

### Credits

Please, consider exploring the following comparable open-source projects that might also be beneficial for you:

[FFuF](https://github.com/ffuf/ffuf), [Jaeles](https://github.com/jaeles-project/jaeles),
[Nuclei](https://github.com/projectdiscovery/nuclei), [Qsfuzz](https://github.com/ameenmaali/qsfuzz),
[Inception](https://github.com/proabiral/inception), [Snallygaster](https://github.com/hannob/snallygaster),
[Gofingerprint](https://github.com/Static-Flow/gofingerprint), [Sn1per](https://github.com/1N3/Sn1per/tree/master/templates),
[Google tsunami](https://github.com/google/tsunami-security-scanner),
and [ChopChop](https://github.com/michelin/ChopChop).

### License

GBounty is distributed under [MIT License](./LICENSE)
