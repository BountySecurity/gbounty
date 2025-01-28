package response

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// FromStdlib converts a [Response] to a standard library response (http.Response).
// Obviously, not all the details (like the duration) can be filled from the info
// the standard response contains.
//
// The http.Response.Body is read, but then reset with io.NopCloser.
func FromStdlib(res *http.Response) (Response, error) {
	var body []byte
	if res.Body != nil {
		var err error
		body, err = io.ReadAll(res.Body)
		if err != nil {
			return Response{}, err
		}
		res.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	isContentEncodingGzip := func(k string, vv []string) bool {
		return strings.EqualFold(k, "Content-Encoding") &&
			slices.ContainsFunc(vv, func(v string) bool {
				return strings.EqualFold(v, "gzip")
			})
	}

	decodeGzipBody := func() ([]byte, error) {
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(gz)
	}

	headers := make(map[string][]string)
	for key, values := range res.Header {
		if isContentEncodingGzip(key, values) {
			var err error
			body, err = decodeGzipBody()
			if err != nil {
				return Response{}, err
			}
			continue // We don't want to add the Content-Encoding header.
		}
		headers[key] = values
	}

	status := strings.TrimPrefix(res.Status, strconv.Itoa(res.StatusCode)+" ")

	return Response{
		Proto:   res.Proto,
		Code:    res.StatusCode,
		Status:  status,
		Headers: headers,
		Body:    body,
	}, nil
}
