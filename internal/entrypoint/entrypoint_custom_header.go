package entrypoint

import (
	"encoding/gob"
	"fmt"

	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func init() {
	gob.Register(CustomHeader{})
}

// CustomHeader must implement the Entrypoint interface.
var _ Entrypoint = CustomHeader{}

// CustomHeader represents a custom header entrypoint.
// It is used to inject new headers into the request.
type CustomHeader struct {
	HeaderKey string
	baseEntrypoint
}

func newCustomHeader(headerKey string) CustomHeader {
	return CustomHeader{
		HeaderKey:      headerKey,
		baseEntrypoint: baseEntrypoint{IPT: profile.HeaderNew},
	}
}

func (e CustomHeader) Param(_ string) string {
	return fmt.Sprintf("%s (header)", e.HeaderKey)
}

func (e CustomHeader) InjectPayload(req request.Request, _ profile.PayloadPosition, payload string) request.Request {
	clone := req.Clone()
	clone.Headers[e.HeaderKey] = append(clone.Headers[e.HeaderKey], payload)

	return clone
}
