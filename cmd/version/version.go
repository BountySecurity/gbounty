package version

import "github.com/bountysecurity/gbounty/kit/semver"

const (
	Version = "v0.2.0"
)

// We want to make sure [Version] is always valid, following the
// `kit/semver` package rules.
func init() {
	_ = semver.MustParse(Version)
}
