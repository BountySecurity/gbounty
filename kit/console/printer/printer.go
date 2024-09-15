package printer

import (
	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/kit/console/color"
)

// Info returns a [pterm.PrefixPrinter] with the "INFO" prefix.
func Info() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		Prefix: pterm.Prefix{Style: color.BoldYellow(), Text: "   INFO   "},
	}
}

// Error returns a [pterm.PrefixPrinter] with the "ERROR" prefix.
func Error() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Magenta(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "   ERROR  "},
	}
}

// Plain returns a [pterm.PrefixPrinter] with the same prefix as the given [pterm.PrefixPrinter],
// but it sets the [pterm.Prefix.Style] to plain (no style, no colors).
func Plain(pp pterm.PrefixPrinter) pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: &pterm.Style{},
		Prefix: pterm.Prefix{
			Style: &pterm.Style{},
			Text:  pp.Prefix.Text,
		},
		Writer: pp.Writer,
	}
}
