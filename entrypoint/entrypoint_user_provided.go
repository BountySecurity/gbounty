package entrypoint

import (
	"encoding/gob"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func init() {
	gob.Register(UserProvidedPath{})
	gob.Register(UserProvidedHeaders{})
	gob.Register(UserProvidedBody{})
}

// UserProvidedInput is a special entrypoint that allows the user to select where to inject.
// Think about this as a placeholder for the user to mark their own entrypoint.
const UserProvidedInput = "$GBOUNTY$"

// The following types must implement the Entrypoint interface.
var (
	_ Entrypoint = UserProvidedPath{}
	_ Entrypoint = UserProvidedHeaders{}
)

type baseUserProvided struct {
	Prefix string
	Suffix string
	baseEntrypoint
}

// UserProvidedPath represents a user-provided entrypoint in the path.
type UserProvidedPath struct {
	baseUserProvided
}

// UserProvidedHeaders represents a user-provided entrypoint in the headers.
type UserProvidedHeaders struct {
	Header string
	ValIdx int
	baseUserProvided
}

// UserProvidedBody represents a user-provided entrypoint in the body.
type UserProvidedBody struct {
	baseUserProvided
}

func newUserProvidedPath(prefix, suffix string) UserProvidedPath {
	return UserProvidedPath{
		baseUserProvided: baseUserProvided{
			Prefix:         prefix,
			Suffix:         suffix,
			baseEntrypoint: baseEntrypoint{V: UserProvidedInput, IPT: profile.UserProvided},
		},
	}
}

func newUserProvidedHeaders(prefix, suffix, header string, valIdx int) UserProvidedHeaders {
	return UserProvidedHeaders{
		Header: header,
		ValIdx: valIdx,
		baseUserProvided: baseUserProvided{
			Prefix:         prefix,
			Suffix:         suffix,
			baseEntrypoint: baseEntrypoint{V: UserProvidedInput, IPT: profile.UserProvided},
		},
	}
}

func newUserProvidedBody(prefix, suffix string) UserProvidedBody {
	return UserProvidedBody{
		baseUserProvided: baseUserProvided{
			Prefix:         prefix,
			Suffix:         suffix,
			baseEntrypoint: baseEntrypoint{V: UserProvidedInput, IPT: profile.UserProvided},
		},
	}
}

func (e UserProvidedPath) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.Path = e.inject(pos, payload)
	return injReq
}

func (e UserProvidedHeaders) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.Headers[e.Header][e.ValIdx] = e.inject(pos, payload)
	return injReq
}

func (e UserProvidedBody) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.Body = []byte(e.inject(pos, payload))
	return injReq
}

func (e baseUserProvided) Param(payload string) string {
	return payload + " (user provided placeholder)"
}

func (e baseUserProvided) inject(pos profile.PayloadPosition, payload string) string {
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

func (e baseUserProvided) replace(payload string) string {
	return e.Prefix + payload + e.Suffix
}

func (e baseUserProvided) append(payload string) string {
	return e.Prefix + e.V + payload + e.Suffix
}

func (e baseUserProvided) insert(payload string) string {
	mid := len(e.V) / half

	return e.Prefix + e.V[:mid] + payload + e.V[mid:] + e.Suffix
}
