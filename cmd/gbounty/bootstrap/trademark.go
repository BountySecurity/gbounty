package bootstrap

import (
	"fmt"

	"github.com/pterm/pterm"
	"github.com/pterm/pterm/putils"

	"github.com/bountysecurity/gbounty"
)

func PrintAppName() {
	_ = pterm.DefaultBigText.WithLetters(
		putils.LettersFromStringWithStyle("G", &pterm.Style{38, 2, 255, 191, 0}),
		putils.LettersFromStringWithStyle("Bounty", &pterm.Style{38, 2, 0, 78, 112})).
		Render()

	pterm.Info.Printf("GBounty %s\n", gbounty.Version)
	pterm.Info.Println("GBounty is a web scanner that uses Bounty Security web vulnerability profiles.")
	pterm.Warning.Println("By using this tool you are accepting the EULA: https://bountysecurity.ai/pages/eula")
	fmt.Println() //nolint:forbidigo
}
