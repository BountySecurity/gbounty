package match

import (
	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func reqXMLNameBytes(req *request.Request) []byte {
	return reqXMLBytes(req, profile.ParamXMLName)
}

func reqXMLValueBytes(req *request.Request) []byte {
	return reqXMLBytes(req, profile.ParamXMLValue)
}

func reqXMLAttrNameBytes(req *request.Request) []byte {
	return reqXMLBytes(req, profile.ParamXMLAttrName)
}

func reqXMLAttrValueBytes(req *request.Request) []byte {
	return reqXMLBytes(req, profile.ParamXMLAttrValue)
}

func reqXMLBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewXMLParamFinder().Find(*req) {
		if v, ok := e.(entrypoint.XMLParam); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}