package color

import "github.com/pterm/pterm"

// Cyan returns a pointer to a [pterm.Style] with the foreground cyan color.
func Cyan() *pterm.Style {
	return &pterm.Style{pterm.FgCyan}
}

// LightCyan returns a pointer to a [pterm.Style] with the foreground light cyan color.
func LightCyan() *pterm.Style {
	return &pterm.Style{pterm.FgLightCyan}
}

// Green returns a pointer to a [pterm.Style] with the foreground green color.
func Green() *pterm.Style {
	return &pterm.Style{pterm.FgGreen}
}

// BoldGreen returns a pointer to a [pterm.Style] with the foreground bold green color.
func BoldGreen() *pterm.Style {
	return &pterm.Style{pterm.Bold, pterm.FgGreen}
}

// Magenta returns a pointer to a [pterm.Style] with the foreground light magenta color.
func Magenta() *pterm.Style {
	return &pterm.Style{pterm.FgLightMagenta}
}

// BoldYellow returns a pointer to a [pterm.Style] with the foreground bold yellow color.
func BoldYellow() *pterm.Style {
	return &pterm.Style{pterm.Bold, pterm.FgYellow}
}

// Red returns a pointer to a [pterm.Style] with the foreground red color.
func Red() *pterm.Style {
	return &pterm.Style{pterm.FgRed}
}

// Blue returns a pointer to a [pterm.Style] with the foreground blue color.
func Blue() *pterm.Style {
	return &pterm.Style{pterm.FgBlue}
}

// LightBlue returns a pointer to a [pterm.Style] with the foreground light blue color.
func LightBlue() *pterm.Style {
	return &pterm.Style{pterm.FgLightBlue}
}

// White returns a pointer to a [pterm.Style] with the foreground light white color.
func White() *pterm.Style {
	return &pterm.Style{pterm.FgLightWhite}
}

// Gray returns a pointer to a [pterm.Style] with the foreground gray color.
func Gray() *pterm.Style {
	return &pterm.Style{pterm.FgWhite}
}

// DarkGray returns a pointer to a [pterm.Style] with the foreground dark gray color.
func DarkGray() *pterm.Style {
	return &pterm.Style{pterm.FgDarkGray}
}
