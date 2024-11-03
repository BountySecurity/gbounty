package request

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strings"
)

// ToStdlib is the equivalent of [Request.ToStdlibWithContext] but with
// [context.Background] as the request's [context.Context].
func (r *Request) ToStdlib() (*http.Request, error) {
	return r.ToStdlibWithContext(context.Background())
}

// ToStdlibWithContext converts a [Request] to a standard library request
// (http.Request). Obviously, all the details that are specific to the internal
// request, like the unique identifier, modifications, etc. are lost in the process.
func (r *Request) ToStdlibWithContext(ctx context.Context) (*http.Request, error) {
	parsedURL, err := url.Parse(r.URL)
	if err != nil {
		return nil, err
	}

	if r.Path != "" {
		parsedURL.Path = r.Path
	}

	httpReq, err := http.NewRequestWithContext(ctx, r.Method, parsedURL.String(), bytes.NewReader(r.Body))
	if err != nil {
		return nil, err
	}

	if r.Proto != "" {
		protoParts := strings.Split(r.Proto, "/")
		if len(protoParts) == 2 {
			httpReq.Proto = r.Proto
			httpReq.ProtoMajor = int(protoParts[1][0] - '0')
			httpReq.ProtoMinor = int(protoParts[1][2] - '0')
		}
	}

	for key, values := range r.Headers {
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	return httpReq, nil
}
