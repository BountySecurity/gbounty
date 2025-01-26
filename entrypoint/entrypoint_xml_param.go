package entrypoint

import (
	"encoding/gob"
	"strings"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

const xmlReplace = "*+*+*InjectHere*+*+*"

func init() {
	gob.Register(XMLParam{})
}

// XMLParam must implement the Entrypoint interface.
var _ Entrypoint = XMLParam{}

// XMLParam represents an XML entrypoint.
// It is used to inject payloads into the request's XML
// parameters and attributes.
// Both, keys and values can be injected.
type XMLParam struct {
	Base string
	baseEntrypoint
}

func newXMLParamName(base, value string) XMLParam {
	// For XML P names, we use the V as the P as well.
	return newXMLParam(profile.ParamXMLName, base, value, value)
}

func newXMLParamValue(base, param, value string) XMLParam {
	return newXMLParam(profile.ParamXMLValue, base, param, value)
}

func newXMLAttrName(base, value string) XMLParam {
	// For XML attribute names, we use the V as the P as well.
	return newXMLParam(profile.ParamXMLAttrName, base, value, value)
}

func newXMLAttrValue(base, param, value string) XMLParam {
	return newXMLParam(profile.ParamXMLAttrValue, base, param, value)
}

func newXMLParam(ipt profile.InsertionPointType, base, param, value string) XMLParam {
	return XMLParam{
		Base:           base,
		baseEntrypoint: baseEntrypoint{P: param, V: value, IPT: ipt},
	}
}

func (e XMLParam) Param(payload string) string {
	var param string
	if e.IPT == profile.ParamXMLName || e.IPT == profile.ParamXMLAttrName {
		param = payload
	} else {
		param = e.baseEntrypoint.Param(payload)
	}

	return param + " (xml param)"
}

func (e XMLParam) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.SetBody([]byte(strings.ReplaceAll(e.Base, xmlReplace, e.inject(pos, payload))))
	return injReq
}

func (e XMLParam) inject(pos profile.PayloadPosition, payload string) string {
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

func (e XMLParam) replace(payload string) string {
	return payload
}

func (e XMLParam) append(payload string) string {
	return e.V + payload
}

func (e XMLParam) insert(payload string) string {
	mid := len(e.V) / half

	return e.V[:mid] + payload + e.V[mid:]
}
