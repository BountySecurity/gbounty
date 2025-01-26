package entrypoint

import (
	"encoding/gob"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func init() {
	gob.Register(URL{})
}

// URL must implement the Entrypoint interface.
var _ Entrypoint = URL{}

// URL represents a URL entrypoint.
// It is used to inject payloads into the request's URL.
type URL struct {
	Prefix string
	Suffix string
	baseEntrypoint
}

func newURLFile(prefix, value, suffix string) URL {
	return newURL(profile.URLPathFile, prefix, value, suffix)
}

func newURLFolder(prefix, value, suffix string) URL {
	return newURL(profile.URLPathFolder, prefix, value, suffix)
}

func newURL(ipt profile.InsertionPointType, prefix, value, suffix string) URL {
	return URL{
		Prefix:         prefix,
		Suffix:         suffix,
		baseEntrypoint: baseEntrypoint{V: value, IPT: ipt},
	}
}

func (e URL) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	req.Path = e.inject(pos, payload)

	return req
}

func (e URL) inject(pos profile.PayloadPosition, payload string) string {
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

func (e URL) replace(payload string) string {
	return e.Prefix + payload + e.Suffix
}

func (e URL) append(payload string) string {
	return e.Prefix + e.V + payload + e.Suffix
}

func (e URL) insert(payload string) string {
	mid := len(e.V) / half

	return e.Prefix + e.V[:mid] + payload + e.V[mid:] + e.Suffix
}
