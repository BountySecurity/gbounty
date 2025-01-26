package modifier

import (
	"github.com/bountysecurity/gbounty"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

// Email must implement the [gbounty.Modifier] interface.
var _ gbounty.Modifier = Email{}

// Email is a [gbounty.Modifier] implementation that modifies the request
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
func (e Email) Modify(_ *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	return replace(req, map[string]string{emailLabel: e.email})
}
