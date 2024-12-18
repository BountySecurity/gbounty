package writer

import (
	"strconv"

	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/kit/console/color"
)

func domainPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Green(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "  DOMAIN  "},
	}
}

func urlsPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Green(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "   URLS   "},
	}
}

func infoPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		Prefix: pterm.Prefix{Style: color.BoldYellow(), Text: "   INFO   "},
	}
}

func issuePrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Magenta(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "   ISSUE  "},
	}
}

func severityPrinter(severity string) pterm.PrefixPrinter {
	var style *pterm.Style

	switch severity {
	case "High":
		style = color.Red()
	case "Medium":
		style = color.Blue()
	case "Low":
		style = color.LightCyan()
	case "Information":
		fallthrough
	default:
		style = color.White()
	}
	return pterm.PrefixPrinter{
		MessageStyle: style,
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: " SEVERITY "},
	}
}

func confidencePrinter(confidence string) pterm.PrefixPrinter {
	var style *pterm.Style

	switch confidence {
	case "Certain":
		style = color.DarkGray()
	case "Firm":
		style = color.Gray()
	case "Tentative":
		fallthrough
	default:
		style = color.White()
	}
	return pterm.PrefixPrinter{
		MessageStyle: style,
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "CONFIDENCE"},
	}
}

func typePrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Blue(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "PROF. TYPE"},
	}
}

func paramPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.LightBlue(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "  PARAM   "},
	}
}

func countPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.BoldGreen(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "   COUNT  "},
	}
}

func requestPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.LightCyan(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: "  REQUEST "},
	}
}

func requestNPrinter(idx int) pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.LightCyan(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: " REQUEST " + strconv.Itoa(idx)},
	}
}

func responsePrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Cyan(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: " RESPONSE "},
	}
}

func durationPrinter() pterm.PrefixPrinter {
	return pterm.PrefixPrinter{
		MessageStyle: color.Cyan(),
		Prefix:       pterm.Prefix{Style: color.BoldYellow(), Text: " DURATION "},
	}
}
