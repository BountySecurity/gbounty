package match

import (
	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func reqURLFolderBytes(req *request.Request) []byte {
	return reqURLBytes(req, profile.URLPathFolder)
}

func reqURLFileBytes(req *request.Request) []byte {
	return reqURLBytes(req, profile.URLPathFile)
}

func reqURLBytes(req *request.Request, ipt profile.InsertionPointType) []byte {
	var b []byte
	for _, e := range entrypoint.NewURLFinder().Find(*req) {
		if v, ok := e.(entrypoint.URL); ok && v.InsertionPointType() == ipt {
			b = append(b, []byte(v.Value())...)
		}
	}
	return b
}
