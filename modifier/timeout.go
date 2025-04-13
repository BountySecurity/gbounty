package modifier

import (
	"time"

	"github.com/BountySecurity/gbounty"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// Timeout must implement the [gbounty.Modifier] interface.
var _ gbounty.Modifier = Timeout{}

// Timeout is a [gbounty.Modifier] implementation that modifies the request
// by setting the timeout to the maximum value found in the time delay greps.
type Timeout struct {
	Margin int
}

// NewTimeout is a constructor function that creates a new instance of
// the [Timeout] modifier.
func NewTimeout() Timeout {
	return Timeout{
		Margin: margin,
	}
}

// Modify modifies the request by setting the timeout to the maximum value found in the time delay greps.
func (t Timeout) Modify(s *profile.Step, _ gbounty.Template, req request.Request) request.Request {
	timeout := req.Timeout
	for i := range len(s.Greps) {
		grep, err := s.GrepAt(i, nil)
		if err == nil && // valid grep
			grep.Type.TimeDelay() && // is time delay
			grep.Value.AsTimeDelaySeconds() >= int(timeout.Seconds()) { // higher than request timeout
			timeout = time.Second * time.Duration(grep.Value.AsTimeDelaySeconds()+t.Margin)
		}
	}

	cloned := req.Clone()
	cloned.Timeout = timeout
	return cloned
}

const margin = 10
