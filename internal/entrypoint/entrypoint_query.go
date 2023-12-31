package entrypoint

import (
	"encoding/gob"
	"fmt"

	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func init() {
	gob.Register(Query{})
}

// Query must implement the Entrypoint interface.
var _ Entrypoint = Query{}

// Query represents a query entrypoint.
// It is used to inject payloads into the request's query parameters.
// Both, keys and values can be injected.
type Query struct {
	Prefix string
	Suffix string
	baseEntrypoint
}

func newQueryKey(prefix, value, suffix string) Query {
	// For query keys, we use the V as the P as well.
	return newQuery(profile.ParamURLName, prefix, value, value, suffix)
}

func newQueryValue(prefix, param, value, suffix string) Query {
	return newQuery(profile.ParamURLValue, prefix, param, value, suffix)
}

func newQuery(ipt profile.InsertionPointType, prefix, param, value, suffix string) Query {
	return Query{
		Prefix:         prefix,
		Suffix:         suffix,
		baseEntrypoint: baseEntrypoint{P: param, V: value, IPT: ipt},
	}
}

func (e Query) Param(payload string) string {
	var param string
	if e.IPT == profile.ParamURLName {
		param = payload
	} else {
		param = e.baseEntrypoint.Param(payload)
	}

	return fmt.Sprintf("%s (query param)", param)
}

func (e Query) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	req.Path = e.inject(pos, payload)

	return req
}

func (e Query) inject(pos profile.PayloadPosition, payload string) string {
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

func (e Query) replace(payload string) string {
	return e.Prefix + payload + e.Suffix
}

func (e Query) append(payload string) string {
	return e.Prefix + e.V + payload + e.Suffix
}

func (e Query) insert(payload string) string {
	mid := len(e.V) / 2

	return e.Prefix + e.V[:mid] + payload + e.V[mid:] + e.Suffix
}
