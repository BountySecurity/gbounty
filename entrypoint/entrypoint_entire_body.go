package entrypoint

import (
	"bufio"
	"bytes"
	"encoding/gob"
	"net/textproto"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func init() {
	gob.Register(EntireBody{})
}

// EntireBody must implement the Entrypoint interface.
var _ Entrypoint = EntireBody{}

// EntireBody represents an entire body entrypoint.
// It is used to inject payloads for the entire request's body.
type EntireBody struct {
	baseEntrypoint
}

func newEntireBody(ipt profile.InsertionPointType, original []byte) EntireBody {
	return EntireBody{
		baseEntrypoint: baseEntrypoint{V: string(original), IPT: ipt},
	}
}

func (e EntireBody) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	injReq := req.Clone()
	injReq.SetBody([]byte(e.inject(pos, payload)))
	injReq.Headers["Content-Type"] = []string{e.contentType(payload)}
	return injReq
}

func (e EntireBody) inject(pos profile.PayloadPosition, payload string) string {
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

func (e EntireBody) replace(payload string) string {
	return payload
}

func (e EntireBody) append(payload string) string {
	return e.V + payload
}

func (e EntireBody) insert(payload string) string {
	mid := len(e.V) / half
	return e.V[:mid] + payload + e.V[mid:]
}

func (e EntireBody) contentType(payload string) string {
	//nolint:exhaustive
	switch e.IPT {
	case profile.EntireBody:
		return "application/x-www-form-urlencoded"
	case profile.EntireBodyJSON:
		return "application/json"
	case profile.EntireBodyXML:
		return "application/xml"
	case profile.EntireBodyMulti:
		reader := textproto.NewReader(bufio.NewReader(bytes.NewBufferString(payload)))

		line, err := reader.ReadLine()
		if err != nil {
			return "multipart/form-data"
		}

		return "multipart/form-data; boundary=" + line[2:]
	default:
		return ""
	}
}
