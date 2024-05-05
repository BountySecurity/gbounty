package internal

import (
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

// Modifier defines the behavior of a request modifier, which is a component
// capable of modifying the given request based on certain given requirements.
type Modifier interface {
	Modify(step *profile.Step, tpl Template, req request.Request) request.Request
}
