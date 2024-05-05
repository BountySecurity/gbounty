package modifier

import (
	"strings"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/kit/ulid"
)

// Random must implement the [scan.Modifier] interface.
var _ scan.Modifier = Random{}

// Random is a [scan.Modifier] implementation that modifies the request
// by replacing the {RANDOM} placeholder with a lower-cased ULID.
// See the `kit/ulid` package for further details.
type Random struct{}

const randomLabel = "{RANDOM}"

// NewRandom is a constructor function that creates a new instance of
// the [Random] modifier.
func NewRandom() Random {
	return Random{}
}

// Modify modifies the request by replacing the random placeholders.
func (Random) Modify(_ *profile.Step, _ scan.Template, req request.Request) request.Request {
	id := strings.ToLower(ulid.New())
	return replace(req, map[string]string{randomLabel: id})
}
