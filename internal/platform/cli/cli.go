package cli

import (
	"flag"
	"io"
	"os"

	"github.com/bountysecurity/gbounty/kit/getopt"
)

const (
	Output = "output"
	Debug  = "debug"
)

func Parse(args []string) (Config, error) {
	config := Config{}

	fs := getopt.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	// No group
	fs.BoolVar("", &config.ShowHelp, "help", false, "Show help")
	fs.Alias("h", "help")

	// Output
	fs.InitGroup(Output, "OUTPUT OPTIONS:")
	fs.StringVar(Output, &config.OutPath, "output", "", "Determines the path where the output file will be stored to\n\tBy default, the output file is formatted as plain text")
	fs.Alias("o", "output")
	json := fs.Bool(Output, "json", false, "If specified, the output file will be JSON-formatted\n\tBy default, the output file is formatted as plain text")
	fs.Alias("j", "json")
	markdown := fs.Bool(Output, "markdown", false, "If specified, the output file will be Markdown-formatted\n\tBy default, the output file is formatted as plain text")
	fs.Alias("md", "markdown")

	// Debug
	fs.InitGroup(Debug, "DEBUG OPTIONS:")
	fs.BoolVar(Debug, &config.Verbosity.Warn, "verbose", false, "If specified, the internal logger will write warning and error log messages")
	fs.Alias("v", "verbose")
	fs.BoolVar(Debug, &config.Verbosity.Info, "verbose-extra", false, "If specified, the internal logger will write info, warning and error log messages")
	fs.Alias("vv", "verbose-extra")
	fs.BoolVar(Debug, &config.Verbosity.Debug, "verbose-all", false, "If specified, the internal logger will write debug, info, warning and error log messages")
	fs.Alias("vvv", "verbose-all")
	fs.StringVar(Debug, &config.Verbosity.Output, "verbose-output", "", "If specified, the internal logger will write the log messages to a file")
	fs.Alias("vout", "verbose-output")

	fs.SetUsage(`
Usage:
  gbounty [flags]

Flags:`)

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
