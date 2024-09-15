package scan

import (
	"encoding/json"
	"io"
	"reflect"
)

// Never obfuscate the Config type.
var _ = reflect.TypeOf(Config{})

// Config defines the configuration used by the scanner to perform a [scan].
// It includes options to control the scanner's behavior, such as the rate of
// requests per second, the concurrency level, and the output format.
type Config struct {
	RPS             int `default:"100"`
	Concurrency     int `default:"100"`
	Version         string
	SaveOnStop      bool
	InMemory        bool
	BlindHost       string
	BlindHostKey    string
	EmailAddress    bool
	CustomTokens    map[string]string
	PayloadStrategy PayloadStrategy

	Silent           bool
	StreamErrors     bool
	StreamMatches    bool
	ShowResponses    bool
	ShowErrors       bool
	ShowAll          bool
	ShowAllRequests  bool
	ShowAllResponses bool

	OutPath   string
	OutFormat string
}

// Clone returns a deep copy of the [Config] instance.
func (c Config) Clone() Config {
	clonedTokens := make(map[string]string)
	for key, value := range c.CustomTokens {
		clonedTokens[key] = value
	}

	return Config{
		RPS:             c.RPS,
		Concurrency:     c.Concurrency,
		Version:         c.Version,
		SaveOnStop:      c.SaveOnStop,
		InMemory:        c.InMemory,
		BlindHost:       c.BlindHost,
		BlindHostKey:    c.BlindHostKey,
		EmailAddress:    c.EmailAddress,
		CustomTokens:    clonedTokens,
		PayloadStrategy: c.PayloadStrategy,

		Silent:           c.Silent,
		StreamErrors:     c.StreamErrors,
		StreamMatches:    c.StreamMatches,
		ShowResponses:    c.ShowResponses,
		ShowErrors:       c.ShowErrors,
		ShowAll:          c.ShowAll,
		ShowAllRequests:  c.ShowAllRequests,
		ShowAllResponses: c.ShowAllResponses,

		OutPath:   c.OutPath,
		OutFormat: c.OutFormat,
	}
}

// BlindHostConfigured returns whether the blind host and its key are configured.
func (c Config) BlindHostConfigured() bool {
	return len(c.BlindHost) > 0 && len(c.BlindHostKey) > 0
}

// CfgOption is a function that modifies a [Config] instance.
// See [WithRPS] and [WithConcurrency] as examples.
type CfgOption func(*Config)

// WithRPS sets the rate of requests per second.
func WithRPS(rps int) CfgOption {
	return func(cfg *Config) {
		cfg.RPS = rps
	}
}

// WithConcurrency sets the concurrency level.
func WithConcurrency(concurrency int) CfgOption {
	return func(cfg *Config) {
		cfg.Concurrency = concurrency
	}
}

// WithBlindHost sets the blind host.
func WithBlindHost(blindHost string) CfgOption {
	return func(cfg *Config) {
		cfg.BlindHost = blindHost
	}
}

// WithBlindHostKey sets the blind host key.
func WithBlindHostKey(blindHostKey string) CfgOption {
	return func(cfg *Config) {
		cfg.BlindHostKey = blindHostKey
	}
}

// WithCustomTokens sets the custom tokens.
func WithCustomTokens(customTokens map[string]string) CfgOption {
	return func(cfg *Config) {
		cfg.CustomTokens = customTokens
	}
}

// WithPayloadStrategy sets the payload strategy.
func WithPayloadStrategy(ps string) CfgOption {
	return func(cfg *Config) {
		// Attention, please.
		// PayloadStrategyFromString defaults to
		// PayloadStrategyAll (performance implications).
		cfg.PayloadStrategy = PayloadStrategyFromString(ps)
	}
}

// CfgOptionsFromJSON parses a JSON document from a [io.Reader],
// and turn its contents into a slice of [CfgOption].
//
// The expected payload is slightly different from [Config] struct.
//
// For instance, it uses pointers to make it easier to determine
// whether a value was set or not.
//
// Also, note that the parameter names is slightly different as well.
// The latter uses long, camel-cased names.
func CfgOptionsFromJSON(r io.Reader) ([]CfgOption, error) {
	var cfg struct {
		Concurrency      *int              `json:"concurrency"`
		RequestPerSecond *int              `json:"requestPerSecond"`
		BlindHost        *string           `json:"blindHost"`
		BlindHostKey     *string           `json:"blindHostKey"`
		CustomTokens     map[string]string `json:"tokens"`
		PayloadStrategy  *string           `json:"payloadStrategy"`
	}

	err := json.NewDecoder(r).Decode(&cfg)
	if err != nil {
		return nil, err
	}

	const totalOpts = 6
	opts := make([]CfgOption, 0, totalOpts)

	if cfg.Concurrency != nil && *cfg.Concurrency > 0 {
		opts = append(opts, WithConcurrency(*cfg.Concurrency))
	}

	if cfg.RequestPerSecond != nil && *cfg.RequestPerSecond > 0 {
		opts = append(opts, WithRPS(*cfg.RequestPerSecond))
	}

	if cfg.BlindHost != nil && len(*cfg.BlindHost) > 0 {
		opts = append(opts, WithBlindHost(*cfg.BlindHost))
	}

	if cfg.BlindHostKey != nil && len(*cfg.BlindHostKey) > 0 {
		opts = append(opts, WithBlindHostKey(*cfg.BlindHostKey))
	}

	if cfg.CustomTokens != nil && len(cfg.CustomTokens) > 0 {
		opts = append(opts, WithCustomTokens(cfg.CustomTokens))
	}

	if cfg.PayloadStrategy != nil && len(*cfg.PayloadStrategy) > 0 {
		opts = append(opts, WithPayloadStrategy(*cfg.PayloadStrategy))
	}

	return opts, nil
}

const (
	PayloadStrategyOnlyOnce PayloadStrategy = "only_once"
	PayloadStrategyAll      PayloadStrategy = "all"
)

// PayloadStrategy represents the strategy used to inject payloads
// during the scan execution. It can be either [PayloadStrategyOnlyOnce]
// or [PayloadStrategyAll].
type PayloadStrategy string

// PayloadStrategyFromString converts a string into a [PayloadStrategy].
func PayloadStrategyFromString(s string) PayloadStrategy {
	switch s {
	case string(PayloadStrategyOnlyOnce):
		return PayloadStrategyOnlyOnce
	default:
		// Use [PayloadStrategyAll] as the default value
		// for every other.
		return PayloadStrategyAll
	}
}

// IsOnlyOnce returns whether the payload strategy is [PayloadStrategyOnlyOnce].
func (ps PayloadStrategy) IsOnlyOnce() bool {
	return ps == PayloadStrategyOnlyOnce
}

// String returns the string representation of the [PayloadStrategy].
func (ps PayloadStrategy) String() string {
	switch ps {
	case PayloadStrategyOnlyOnce:
		return string(PayloadStrategyOnlyOnce)
	case PayloadStrategyAll:
		return string(PayloadStrategyAll)
	default:
		return unknown
	}
}

const unknown = "Unknown"
