package response

import (
	"bytes"
	"io"
	"net/http"
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

	headers := make(map[string][]string)
	for key, values := range res.Header {
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
