package modifier

import (
	"strings"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/kit/ulid"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// Random must implement the [gbounty.Modifier] interface.
var _ gbounty.Modifier = Random{}

// Random is a [gbounty.Modifier] implementation that modifies the request
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
func (Random) Modify(_ *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	id := strings.ToLower(ulid.New())
	return replace(req, map[string]string{randomLabel: id})
}
