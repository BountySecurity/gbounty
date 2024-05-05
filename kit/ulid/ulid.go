package ulid

import (
	"crypto/rand"
	"time"

	"github.com/oklog/ulid/v2"
)

// New returns a new [ULID](https://github.com/ulid/spec) with the current
// Unix milliseconds timestamp and [rand.Reader] as the entropy source.
//
// It may panic, because it uses [ulid.MustNew] under the hood.
func New() string {
	now := time.Now()
	entropy := ulid.Monotonic(rand.Reader, 0)
	return ulid.MustNew(ulid.Timestamp(now), entropy).String()
}

// IsValid returns true if the given string is
// [ULID](https://github.com/ulid/spec) compliant.
func IsValid(id string) bool {
	_, err := ulid.Parse(id)
	return err == nil
}
