package entrypoint

import (
	"encoding/gob"
	"fmt"

	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func init() {
	gob.Register(Header{})
}

// Header must implement the Entrypoint interface.
var _ Entrypoint = Header{}

// Header represents a header entrypoint.
// It is used to inject payloads into the request's headers.
type Header struct {
	HeaderKey string
	baseEntrypoint
}

func newHeader(ipt profile.InsertionPointType, headerKey string) Header {
	return Header{
		HeaderKey:      headerKey,
		baseEntrypoint: baseEntrypoint{IPT: ipt},
	}
}

func (e Header) Param(_ string) string {
	return fmt.Sprintf("%s (header)", e.HeaderKey)
}

func (e Header) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	clone := req.Clone()
	clone.Headers[e.HeaderKey] = e.inject(clone.Headers[e.HeaderKey], pos, payload)

	return clone
}

func (e Header) inject(values []string, pos profile.PayloadPosition, payload string) []string {
	switch pos {
	case profile.Replace:
		return e.replace(values, payload)
	case profile.Append:
		return e.append(values, payload)
	case profile.Insert:
		return e.insert(values, payload)
	default:
		return values
	}
}

func (e Header) replace(values []string, payload string) []string {
	for i := range values {
		values[i] = payload
	}

	return values
}

func (e Header) append(values []string, payload string) []string {
	for i, val := range values {
		values[i] = val + payload
	}

	return values
}

func (e Header) insert(values []string, payload string) []string {
	for i, val := range values {
		mid := len(val) / 2
		values[i] = val[:mid] + payload + val[mid:]
	}

	return values
}
