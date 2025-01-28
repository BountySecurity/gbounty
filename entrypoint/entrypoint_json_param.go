package entrypoint

import (
	"encoding/gob"
	"strconv"
	"strings"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func init() {
	gob.Register(JSONParam{})
}

// JSONParam must implement the Entrypoint interface.
var _ Entrypoint = JSONParam{}

// JSONParam represents a JSON parameter entrypoint.
// It is used to inject payloads into the request's JSON parameters.
// Both, keys and values can be injected.
type JSONParam struct {
	Base string
	baseEntrypoint
}

func newJSONParamName(base, value string) JSONParam {
	// For P names, we use the V as the P as well.
	return newJSONParam(profile.ParamJSONName, base, value, value)
}

func newJSONParamValue(base, param, value string) JSONParam {
	return newJSONParam(profile.ParamJSONValue, base, param, value)
}

func newJSONParam(ipt profile.InsertionPointType, base, param, value string) JSONParam {
	return JSONParam{
		Base:           base,
		baseEntrypoint: baseEntrypoint{P: param, V: value, IPT: ipt},
	}
}

func (e JSONParam) Param(payload string) string {
	var param string
	if e.IPT == profile.ParamJSONName {
		param = payload
	} else {
		param = e.baseEntrypoint.Param(payload)
	}

	return param + " (json param)"
}

const jsonReplacer = 886018860

func (e JSONParam) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.SetBody([]byte(strings.Replace(e.Base, strconv.Itoa(jsonReplacer), e.inject(pos, payload), 1)))
	return injReq
}

func (e JSONParam) inject(pos profile.PayloadPosition, payload string) string {
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

func (e JSONParam) replace(payload string) string {
	return payload
}

func (e JSONParam) append(payload string) string {
	return e.V + payload
}

func (e JSONParam) insert(payload string) string {
	mid := len(e.V) / half

	return e.V[:mid] + payload + e.V[mid:]
}
