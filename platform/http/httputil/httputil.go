//nolint:gochecknoglobals
package httputil

import "net/http"

var listBasedHeaders = map[string]struct{}{
	"Accept":                        {},
	"Accept-Encoding":               {},
	"Accept-Language":               {},
	"Allow":                         {},
	"Cache-Control":                 {},
	"Connection":                    {},
	"Content-Encoding":              {},
	"Content-Language":              {},
	"Content-Type":                  {},
	"Via":                           {},
	"Vary":                          {},
	"Access-Control-Allow-Headers":  {},
	"Access-Control-Allow-Methods":  {},
	"Access-Control-Expose-Headers": {},
	"If-Match":                      {},
	"If-None-Match":                 {},
	"Trailer":                       {},
	"Transfer-Encoding":             {},
	"Upgrade":                       {},
	"Warning":                       {},
}

func IsListBasedHeader(h string) bool {
	_, isListBased := listBasedHeaders[http.CanonicalHeaderKey(h)]
	return isListBased
}
