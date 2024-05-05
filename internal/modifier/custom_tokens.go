package modifier

import (
	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

// CustomTokens must implement the [scan.Modifier] interface.
var _ scan.Modifier = CustomTokens{}

// CustomTokens is a [scan.Modifier] implementation that modifies the request
// with [scan.CustomTokens]. That's it, keys (placeholders) replaced with specific
// values.
type CustomTokens struct {
	ct scan.CustomTokens
}

// NewCustomTokens is a constructor function that creates a new instance of
// the [CustomTokens] modifier with the given [scan.CustomTokens].
func NewCustomTokens(ct scan.CustomTokens) CustomTokens {
	return CustomTokens{
		ct: ct,
	}
}

// Modify modifies the request.
func (m CustomTokens) Modify(_ *profile.Step, _ scan.Template, req request.Request) request.Request {
	return replace(req, m.ct)
}
