package bootstrap

import (
	"os"

	"github.com/bountysecurity/gbounty/internal/platform/cli"
)

func Run() error {
	cfg, err := parseCLIArgs()
	if err != nil || cfg.ShowHelp {
		return err
	}

	return nil
}

func parseCLIArgs() (cli.Config, error) {
	cliConfig, err := cli.Parse(os.Args)
	if err != nil {
		return cli.Config{}, err
	}

	if cliConfig.ShowHelp {
		return cliConfig, nil
	}

	if err := cliConfig.Validate(); err != nil {
		return cli.Config{}, err
	}

	return cliConfig, nil
}
