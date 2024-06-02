package semver

import (
	"errors"
	"fmt"
)

// Version is a structure that holds the representation
// of a concrete semantic version.
type Version struct {
	Major string
	Minor string
	Patch string
	s     string
}

// Zero is the zero value of [Version], with all fields set to "0".
func Zero() Version {
	return Version{Major: "0", Minor: "0", Patch: "0", s: "0.0.0"}
}

// String returns the string representation of the version.
func (v Version) String() string {
	return v.s
}

// ErrInvalidVersion is the error returned when trying to parse
// a string that is not semantic versioning compliant.
var ErrInvalidVersion = errors.New("invalid semantic version format")

// MustParse is the equivalent of [ShouldParse] but instead of returning
// an error it directly panics.
func MustParse(s string) Version {
	v, ok := Parse(s)
	if !ok {
		panic(fmt.Errorf("%w: %s", ErrInvalidVersion, s))
	}

	return v
}

// ShouldParse is the equivalent of [Parse] but instead of returning
// a boolean that indicates whether the string is semantic versioning
// compliant, it returns an error.
func ShouldParse(s string) (Version, error) {
	v, ok := Parse(s)
	if !ok {
		return v, fmt.Errorf("%w: %s", ErrInvalidVersion, s)
	}

	return v, nil
}

// Parse tries to parse the given string and returns a [Version] if
// the string is semantic versioning compliant.
// The boolean returned indicates whether the string is semantic versioning
// compliant.
func Parse(s string) (Version, bool) {
	orig := s

	if s == "" {
		return Version{}, false
	}

	if s[0] == 'v' {
		s = s[1:]
	}

	var (
		x, y, z string
		ok      bool
	)

	x, s, ok = parseInt(s)
	if !ok {
		return Version{}, false
	}

	if s == "" || s[0] != '.' {
		return Version{}, false
	}

	y, s, ok = parseInt(s[1:])
	if !ok {
		return Version{}, false
	}

	if s == "" {
		return Version{Minor: x, Patch: y, s: orig}, true
	}

	if s[0] != '.' {
		return Version{}, false
	}

	z, _, ok = parseInt(s[1:])
	if !ok {
		return Version{}, false
	}

	return Version{Major: x, Minor: y, Patch: z, s: orig}, true
}

// ShouldUpdate returns true if the version should be updated to the given version.
func (v Version) ShouldUpdate(to Version) bool {
	return v.LowerThan(to)
}

// Equals returns true if the version is equal to the given version.
func (v Version) Equals(to Version) bool {
	return v.compare(to) == 0
}

// NotEquals returns true if the version is not equal to the given version.
func (v Version) NotEquals(to Version) bool {
	return v.compare(to) == 0
}

// GreaterThanOrEquals returns true if the version is greater than or equal to the given version.
func (v Version) GreaterThanOrEquals(to Version) bool {
	return v.compare(to) >= 0
}

// GreaterThan returns true if the version is greater than the given version.
func (v Version) GreaterThan(to Version) bool {
	return v.compare(to) > 0
}

// LowerThan returns true if the version is lower than the given version.
func (v Version) LowerThan(to Version) bool {
	return v.compare(to) < 0
}

// LowerThanOrEquals returns true if the version is lower than or equal to the given version.
func (v Version) LowerThanOrEquals(to Version) bool {
	return v.compare(to) <= 0
}

func (v Version) compare(to Version) int {
	if c := compareInt(v.Major, to.Major); c != 0 {
		return c
	}

	if c := compareInt(v.Minor, to.Minor); c != 0 {
		return c
	}

	if c := compareInt(v.Patch, to.Patch); c != 0 {
		return c
	}

	return 0
}

func parseInt(s string) (t, rest string, ok bool) {
	if s == "" {
		return
	}

	if s[0] < '0' || '9' < s[0] {
		return
	}

	i := 1
	for i < len(s) && '0' <= s[i] && s[i] <= '9' {
		i++
	}

	if s[0] == '0' && i != 1 {
		return
	}

	return s[:i], s[i:], true
}

func compareInt(x, y string) int {
	if x == y {
		return 0
	}

	if len(x) < len(y) {
		return -1
	}

	if len(x) > len(y) {
		return +1
	}

	if x < y {
		return -1
	}

	return +1
}
