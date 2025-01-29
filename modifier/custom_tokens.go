package modifier

import (
	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// CustomTokens must implement the [gbounty.Modifier] interface.
var _ gbounty.Modifier = CustomTokens{}

// CustomTokens is a [gbounty.Modifier] implementation that modifies the request
// with [gbounty.CustomTokens]. That's it, keys (placeholders) replaced with specific
// values.
type CustomTokens struct {
	ct gbounty.CustomTokens
}

// NewCustomTokens is a constructor function that creates a new instance of
// the [CustomTokens] modifier with the given [gbounty.CustomTokens].
func NewCustomTokens(ct gbounty.CustomTokens) CustomTokens {
	return CustomTokens{
		ct: ct,
	}
}

// Modify modifies the request.
func (m CustomTokens) Modify(_ *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	return replace(req, m.ct)
}
