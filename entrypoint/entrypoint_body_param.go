package entrypoint

import (
	"encoding/gob"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func init() {
	gob.Register(BodyParam{})
}

// BodyParam must implement the Entrypoint interface.
var _ Entrypoint = BodyParam{}

// BodyParam represents a body parameter entrypoint.
// It is used to inject payloads into the request's body's params.
// Both, keys and values can be injected.
type BodyParam struct {
	Prefix string
	Suffix string
	baseEntrypoint
}

func newBodyParamName(prefix, value, suffix string) BodyParam {
	// For P names, we use the V as the P as well.
	return newBodyParam(profile.ParamBodyName, prefix, value, value, suffix)
}

func newBodyParamValue(prefix, param, value, suffix string) BodyParam {
	return newBodyParam(profile.ParamBodyValue, prefix, param, value, suffix)
}

func newBodyParam(ipt profile.InsertionPointType, prefix, param, value, suffix string) BodyParam {
	return BodyParam{
		Prefix:         prefix,
		Suffix:         suffix,
		baseEntrypoint: baseEntrypoint{P: param, V: value, IPT: ipt},
	}
}

func (e BodyParam) Param(payload string) string {
	var param string
	if e.IPT == profile.ParamBodyName {
		param = payload
	} else {
		param = e.baseEntrypoint.Param(payload)
	}

	return param + " (body param)"
}

func (e BodyParam) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.SetBody([]byte(e.inject(pos, payload)))
	return injReq
}

func (e BodyParam) inject(pos profile.PayloadPosition, payload string) string {
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

func (e BodyParam) replace(payload string) string {
	return e.Prefix + payload + e.Suffix
}

func (e BodyParam) append(payload string) string {
	return e.Prefix + e.V + payload + e.Suffix
}

func (e BodyParam) insert(payload string) string {
	mid := len(e.V) / half

	return e.Prefix + e.V[:mid] + payload + e.V[mid:] + e.Suffix
}
