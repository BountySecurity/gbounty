package cli

import (
	"net/http"

	"github.com/bountysecurity/gbounty/kit/logger"
)

const (
	defaultParamsSplit  = 10
	defaultParamsMethod = http.MethodGet
	defaultParamsEncode = "url"
)

type Verbosity struct {
	Debug  bool
	Info   bool
	Warn   bool
	Output string
}

func (v Verbosity) Level() logger.Level {
	switch {
	case v.Debug:
		return logger.LevelDebug
	case v.Info:
		return logger.LevelInfo
	case v.Warn:
		return logger.LevelWarn
	}

	return logger.LevelDisabled
}

type Config struct {
	// ShowHelp determines whether
	// the help flag has been provided.
	ShowHelp bool
	// OutPath specifies the path where
	// the scan output will be written to.
	OutPath string
	// OutFormat specifies the format
	// the scan output will be written.
	OutFormat string
	// Verbosity determines the level of
	// verbosity for the internal logger.
	Verbosity Verbosity
}

func (cfg Config) Validate() error {
	for _, validation := range []func() error{} {
		if err := validation(); err != nil {
			return err
		}
	}

	return nil
}
