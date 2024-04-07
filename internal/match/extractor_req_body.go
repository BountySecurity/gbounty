package match

import (
	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func reqBodyXMLBytes(req *request.Request) []byte {
	if !req.HasXMLBody() {
		return []byte{}
	}

	return req.Body
}

func reqBodyJSONBytes(req *request.Request) []byte {
	if !req.HasJSONBody() {
		return []byte{}
	}

	return req.Body
}

func reqBodyMultipartBytes(req *request.Request) []byte {
	if !req.HasMultipartBody() {
		return []byte{}
	}

	return req.Body
}

func reqBodyNameBytes(req *request.Request) []byte {
	return reqBodyBytes(req, profile.ParamBodyName)
}

func reqBodyValueBytes(req *request.Request) []byte {
	return reqBodyBytes(req, profile.ParamBodyValue)
}

func reqBodyBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewBodyParamFinder().Find(*req) {
		if v, ok := e.(entrypoint.BodyParam); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}
