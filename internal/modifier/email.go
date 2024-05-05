package modifier

import (
	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

// Email must implement the [scan.Modifier] interface.
var _ scan.Modifier = Email{}

// Email is a [scan.Modifier] implementation that modifies the request
// by replacing the {EMAIL} placeholder with the given email address.
type Email struct {
	email string
}

const (
	// {EMAIL} is the label used by GBounty for email address.
	emailLabel = "{EMAIL}"
)

// NewEmail is a constructor function that creates a new instance of
// the [Email] modifier with the given email address.
func NewEmail(email string) Email {
	return Email{
		email: email,
	}
}

// Modify modifies the request by replacing the {EMAIL} placeholder with the given email address.
func (e Email) Modify(_ *profile.Step, _ scan.Template, req request.Request) request.Request {
	return replace(req, map[string]string{emailLabel: e.email})
}
