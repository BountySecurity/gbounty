package entrypoint

import (
	"encoding/gob"
	"strings"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

const cookieReplace = "+*+*+InjectHere+*+*+"

func init() {
	gob.Register(Cookie{})
}

// Cookie must implement the Entrypoint interface.
var _ Entrypoint = Cookie{}

// Cookie represents a cookie entrypoint.
// It is used to inject payloads into the cookie of a request.
// Both, keys and values can be injected.
type Cookie struct {
	Base string
	baseEntrypoint
}

func newCookieName(base, value string) Cookie {
	// For cookie names, we use the V as the P as well.
	return newCookie(profile.CookieName, base, value, value)
}

func newCookieValue(base, param, value string) Cookie {
	return newCookie(profile.CookieValue, base, param, value)
}

func newCookie(ipt profile.InsertionPointType, base, param, value string) Cookie {
	return Cookie{
		Base:           base,
		baseEntrypoint: baseEntrypoint{P: param, V: value, IPT: ipt},
	}
}

func (e Cookie) Param(payload string) string {
	var param string
	if e.IPT == profile.CookieName {
		param = payload
	} else {
		param = e.baseEntrypoint.Param(payload)
	}

	return param + " (cookie name)"
}

func (e Cookie) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.Headers["Cookie"] = []string{
		strings.Replace(e.Base, cookieReplace, e.inject(pos, payload), 1),
	}

	return injReq
}

func (e Cookie) inject(pos profile.PayloadPosition, payload string) string {
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

func (e Cookie) replace(payload string) string {
	return payload
}

func (e Cookie) append(payload string) string {
	return e.V + payload
}

func (e Cookie) insert(payload string) string {
	mid := len(e.V) / half

	return e.V[:mid] + payload + e.V[mid:]
}
