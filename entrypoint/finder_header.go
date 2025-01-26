package entrypoint

import (
	"net/http"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// HeaderFinder must implement the Finder interface.
var _ Finder = HeaderFinder{}

// HeaderFinder is used to find entrypoints in the request's headers.
type HeaderFinder struct{}

// NewHeaderFinder instantiates a new HeaderFinder.
func NewHeaderFinder() HeaderFinder {
	return HeaderFinder{}
}

func (HeaderFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)

	for ipt, header := range headersMapping() {
		if _, ok := req.Headers[header]; ok {
			entrypoints = append(entrypoints, newHeader(ipt, header))
		}
	}

	return entrypoints
}

func headersMapping() map[profile.InsertionPointType]string {
	return map[profile.InsertionPointType]string{
		profile.HeaderUserAgent:      http.CanonicalHeaderKey("User-Agent"),
		profile.HeaderReferer:        http.CanonicalHeaderKey("Referer"),
		profile.HeaderOrigin:         http.CanonicalHeaderKey("Origin"),
		profile.HeaderHost:           http.CanonicalHeaderKey("Host"),
		profile.HeaderContentType:    http.CanonicalHeaderKey("Content-Type"),
		profile.HeaderAccept:         http.CanonicalHeaderKey("Accept"),
		profile.HeaderAcceptLanguage: http.CanonicalHeaderKey("Accept-Language"),
		profile.HeaderAcceptEncoding: http.CanonicalHeaderKey("Accept-Encoding"),
	}
}
