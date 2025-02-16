package match

import (
	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func reqCookieNameBytes(req *request.Request) []byte {
	return reqCookieBytes(req, profile.CookieName)
}

func reqCookieValueBytes(req *request.Request) []byte {
	return reqCookieBytes(req, profile.CookieValue)
}

func reqCookieBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewCookieFinder().Find(*req) {
		if v, ok := e.(entrypoint.Cookie); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}
