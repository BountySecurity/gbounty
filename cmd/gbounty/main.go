package main

import (
	"os"

	"github.com/pterm/pterm"

	"github.com/bountysecurity/gbounty/cmd/gbounty/bootstrap"
	"github.com/bountysecurity/gbounty/kit/strings/capitalize"
)

func main() {
	bootstrap.PrintAppName()
	bootstrap.CheckForUpdates()

	if err := bootstrap.Run(); err != nil {
		pterm.Error.WithShowLineNumber(false).Printf("%s\n", capitalize.First(err.Error()))
		os.Exit(1)
	}
}
