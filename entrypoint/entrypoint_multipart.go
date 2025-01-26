package entrypoint

import (
	"bytes"
	"encoding/gob"
	"io"
	"mime"
	"mime/multipart"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func init() {
	gob.Register(Multipart{})
}

// Multipart must implement the Entrypoint interface.
var _ Entrypoint = Multipart{}

// Multipart represents a multipart entrypoint.
// It is used to inject payloads into the request's multipart attachments.
// Both, keys and values can be injected.
type Multipart struct {
	Key string
	baseEntrypoint
}

func NewMultipartName(key string) Multipart {
	return newMultipart(profile.ParamMultiAttrName, key)
}

func NewMultipartValue(key string) Multipart {
	return newMultipart(profile.ParamMultiAttrValue, key)
}

func newMultipart(ipt profile.InsertionPointType, key string) Multipart {
	return Multipart{
		Key:            key,
		baseEntrypoint: baseEntrypoint{IPT: ipt},
	}
}

func (e Multipart) Param(_ string) string {
	return e.Key + " (multipart attachment)"
}

func (e Multipart) InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request {
	var err error

	injReq := req.Clone()

	injBody, err := e.body(injReq, pos, payload)
	if err != nil {
		// Open questions:
		// - Should we log errors? (Maybe on verbose)
		return req
	}

	injReq.SetBody(injBody)

	return injReq
}

func (e Multipart) body(injReq request.Request, pos profile.PayloadPosition, payload string) ([]byte, error) {
	form, err := injReq.MultipartForm()
	if err != nil || form == nil {
		return nil, err
	}

	_, params, err := mime.ParseMediaType(injReq.ContentType())
	if err != nil {
		return nil, err
	}

	var buff bytes.Buffer
	w := multipart.NewWriter(&buff)

	err = w.SetBoundary(params["boundary"])
	if err != nil {
		return nil, err
	}

	for k, values := range form.Value {
		if e.IPT == profile.ParamMultiAttrName && k == e.Key {
			k = e.inject(pos, payload, e.Key)
		}

		fW, err := w.CreateFormField(k)
		if err != nil {
			return nil, err
		}

		for _, v := range values {
			var err error

			if e.IPT == profile.ParamMultiAttrValue && k == e.Key {
				_, err = fW.Write([]byte(e.inject(pos, payload, v)))
			} else {
				_, err = fW.Write([]byte(v))
			}

			if err != nil {
				return nil, err
			}
		}
	}

	for k, files := range form.File {
		if e.IPT == profile.ParamMultiAttrName && k == e.Key {
			k = e.inject(pos, payload, e.Key)
		}

		for _, f := range files {
			if _, ok := f.Header["Content-Disposition"]; ok {
				f.Header["Content-Disposition"] = []string{
					`form-data; name="` + k + `"; filename="` + f.Filename + `"`,
				}
			}

			fW, err := w.CreatePart(f.Header)
			if err != nil {
				return nil, err
			}

			file, err := f.Open()
			if err != nil {
				return nil, err
			}

			contents, err := io.ReadAll(file)
			if err != nil {
				return nil, err
			}

			if e.IPT == profile.ParamMultiAttrValue && k == e.Key {
				_, err = fW.Write([]byte(e.inject(pos, payload, string(contents))))
			} else {
				_, err = fW.Write(contents)
			}

			if err != nil {
				return nil, err
			}
		}

		err = w.Close()
		if err != nil {
			return nil, err
		}
	}

	return buff.Bytes(), nil
}

func (e Multipart) inject(pos profile.PayloadPosition, payload, val string) string {
	switch pos {
	case profile.Replace:
		return e.replace(payload)
	case profile.Append:
		return e.append(payload, val)
	case profile.Insert:
		return e.insert(payload, val)
	default:
		return payload
	}
}

func (e Multipart) replace(payload string) string {
	return payload
}

func (e Multipart) append(payload, val string) string {
	return val + payload
}

func (e Multipart) insert(payload, val string) string {
	mid := len(val) / half

	return val[:mid] + payload + val[mid:]
}
