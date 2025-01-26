package match

import (
	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func reqJSONNameBytes(req *request.Request) []byte {
	return reqJSONBytes(req, profile.ParamJSONName)
}

func reqJSONValueBytes(req *request.Request) []byte {
	return reqJSONBytes(req, profile.ParamJSONValue)
}

func reqJSONBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewJSONParamFinder().Find(*req) {
		if v, ok := e.(entrypoint.JSONParam); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}
