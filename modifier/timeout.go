package modifier

import (
	"time"

	scan "github.com/bountysecurity/gbounty"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

// Timeout must implement the [scan.Modifier] interface.
var _ scan.Modifier = Timeout{}

// Timeout is a [scan.Modifier] implementation that modifies the request
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
func (t Timeout) Modify(s *profile.Step, _ scan.Template, req request.Request) request.Request {
	timeout := req.Timeout
	for i := 0; i < len(s.Greps); i++ {
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
