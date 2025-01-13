package main

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/cmd/gbounty/bootstrap"
	"github.com/bountysecurity/gbounty/kit/slices"
	"github.com/bountysecurity/gbounty/kit/strings/capitalize"
)

func main() {
	// The application's logo is printed only when the --only-poc/-poc flag is not set.
	showAppName := slices.NoneIn(os.Args, []string{"-poc", "--only-poc"})
	if showAppName {
		bootstrap.PrintAppName()
	} else {
		fmt.Println() //nolint:forbidigo
	}

	bootstrap.CheckForUpdates()

	if err := bootstrap.Run(); err != nil {
		pterm.Error.WithShowLineNumber(false).Printf("%s\n", capitalize.First(err.Error()))
		os.Exit(1)
	}
}
