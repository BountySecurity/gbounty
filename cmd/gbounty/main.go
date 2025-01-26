package main

import (
	"fmt"
	"os"

	"github.com/pterm/pterm"

	"github.com/BountySecurity/gbounty/cmd/gbounty/bootstrap"
	"github.com/BountySecurity/gbounty/kit/slices"
	"github.com/BountySecurity/gbounty/kit/strings/capitalize"
)

func main() {
	// The application's logo is printed only when the --only-poc/-poc flag is not set.
	notPoc := slices.NoneIn(os.Args, []string{"-poc", "--only-poc"})
	if notPoc {
		bootstrap.PrintAppName()
		bootstrap.CheckForUpdates()
	} else {
		fmt.Println() //nolint:forbidigo
	}

	if err := bootstrap.Run(); err != nil {
		pterm.Error.WithShowLineNumber(false).Printf("%s\n", capitalize.First(err.Error()))
		os.Exit(1)
	}
}
