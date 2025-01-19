package gbounty

import "github.com/bountysecurity/gbounty/kit/semver"

const (
	Version = "v3.1.0"
)

// We want to make sure [Version] is always valid, following the
// `kit/semver` package rules.
func init() {
	_ = semver.MustParse(Version)
}
