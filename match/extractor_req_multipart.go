package match

import (
	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func reqMultipartNameBytes(req *request.Request) []byte {
	return reqMultipartBytes(req, profile.ParamMultiAttrName)
}

func reqMultipartValueBytes(req *request.Request) []byte {
	return reqMultipartBytes(req, profile.ParamMultiAttrValue)
}

func reqMultipartBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewMultipartFinder().Find(*req) {
		if v, ok := e.(entrypoint.Multipart); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}
