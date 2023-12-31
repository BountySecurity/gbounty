package entrypoint

import (
	"encoding/gob"

	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func init() {
	gob.Register(Path{})
}

// Path must implement the Entrypoint interface.
var _ Entrypoint = Path{}

// Path represents a path entrypoint.
// It is used to inject payloads into the request's path.
type Path struct {
	Prefix string
	baseEntrypoint
}

func newSinglePath(prefix, value string) Path {
	return newPath(profile.SinglePathDiscovery, prefix, value)
}

func newPath(ipt profile.InsertionPointType, prefix, value string) Path {
	return Path{
		Prefix:         prefix,
		baseEntrypoint: baseEntrypoint{V: value, IPT: ipt},
	}
}

func (e Path) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	req.Path = e.inject(pos, payload)

	return req
}

func (e Path) inject(pos profile.PayloadPosition, payload string) string {
	switch pos {
	case profile.Replace:
		return e.replace(payload)
	case profile.Append:
		return e.append(payload)
	case profile.Insert:
		return e.insert(payload)
	default:
		return payload
	}
}

func (e Path) replace(payload string) string {
	return e.Prefix + payload
}

func (e Path) append(payload string) string {
	return e.Prefix + "/" + e.V + payload
}

func (e Path) insert(payload string) string {
	mid := len(e.V) / 2

	return e.Prefix + "/" + e.V[:mid] + payload + e.V[mid:]
}
