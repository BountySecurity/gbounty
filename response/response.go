package response

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/textproto"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BountySecurity/gbounty/platform/http/httputil"
)

var (
	// ErrInvalidStatusLine is returned when the status line is invalid.
	ErrInvalidStatusLine = errors.New("invalid status line")
	// ErrInvalidStatusCode is returned when the status code is invalid.
	ErrInvalidStatusCode = errors.New("invalid status code")
	// ErrInvalidHeaders is returned when the headers are invalid.
	ErrInvalidHeaders = errors.New("invalid headers")
	// ErrUnreadableBody is returned when the body is unreadable.
	ErrUnreadableBody = errors.New("unreadable body")
)

// Response is a representation of an HTTP response, similar
// to the equivalent [request.Request] and used here and there for scans.
type Response struct {
	Proto    string
	Code     int
	Status   string
	Headers  map[string][]string
	Body     []byte
	Time     time.Duration
	ConnTime time.Duration
}

// Location returns the Location header value.
// It concatenates multiple values with a space.
func (r Response) Location() string {
	return strings.Join(r.Headers["Location"], " ")
}

// Bytes returns the response as a byte slice.
func (r Response) Bytes() []byte {
	if r.IsEmpty() {
		return []byte{}
	}

	var ret strings.Builder

	ret.WriteString(r.Proto + " " + strconv.Itoa(r.Code) + " " + r.Status + "\r\n")

	keys := make([]string, 0, len(r.Headers))
	for key := range r.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, k := range keys {
		if httputil.IsListBasedHeader(k) {
			ret.WriteString(k + ": " + strings.Join(r.Headers[k], ", ") + "\r\n")
		} else {
			for _, v := range r.Headers[k] {
				ret.WriteString(k + ": " + v + "\r\n")
			}
		}
	}

	ret.WriteString("\r\n")
	ret.Write(r.Body)

	return []byte(ret.String())
}

// EscapedBytes returns the response as a byte slice, with the body
// escaped (i.e. JSON encoded).
func (r Response) EscapedBytes() []byte {
	raw := string(r.Bytes())

	escaped, err := json.Marshal(raw)
	if err != nil {
		// Open questions:
		// - Should we log errors? (Maybe on verbose)
		return nil
	}

	return escaped
}

// BytesWithoutHeaders returns the response as a byte slice, without headers.
func (r Response) BytesWithoutHeaders() []byte {
	if r.IsEmpty() {
		return []byte{}
	}
	return []byte(r.Proto + " " + strconv.Itoa(r.Code) + " " + r.Status + "\r\n" + string(r.Body))
}

// BytesOnlyHeaders returns the response headers as a byte slice.
func (r Response) BytesOnlyHeaders() []byte {
	if r.IsEmpty() {
		return []byte{}
	}

	keys := make([]string, 0, len(r.Headers))
	for key := range r.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var ret strings.Builder
	for _, k := range keys {
		if httputil.IsListBasedHeader(k) {
			ret.WriteString(k + ": " + strings.Join(r.Headers[k], ", ") + "\r\n")
		} else {
			for _, v := range r.Headers[k] {
				ret.WriteString(k + ": " + v + "\r\n")
			}
		}
	}

	return []byte(ret.String())
}

// ContentLength returns the length of the response.
// It tries to parse the Content-Length header.
// If the response is empty, it returns 0.
func (r Response) ContentLength() int {
	const empty = 0
	if r.IsEmpty() {
		return empty
	}

	h, ok := r.Headers["Content-Length"]
	if !ok {
		return empty
	}

	if length, err := strconv.ParseInt(strings.Join(h, ", "), 10, 64); err == nil {
		return int(length)
	}

	return empty
}

// Length returns the length of the response.
// If the response is empty, it returns 0.
// If the Content-Length header is set, it returns its value.
// Otherwise, it returns the length of the body.
func (r Response) Length() int {
	if r.IsEmpty() {
		return 0
	}

	if cl := r.ContentLength(); cl > 0 {
		return cl
	}

	return len(r.Body)
}

// ContentType returns the value of the Content-Type header.
// If the response is empty or the header is not set, it returns an empty string.
// It also removes any parameters from the header value.
func (r Response) ContentType() string {
	if r.IsEmpty() {
		return ""
	}

	h, ok := r.Headers["Content-Type"]
	if !ok || len(h) == 0 {
		return ""
	}

	return strings.Split(h[0], ";")[0]
}

// InferredType returns the inferred type of the response.
// It uses the Content-Type header to determine the type.
// Some types are inferred are:
// - HTML (text/html)
// - CSS (text/css)
// - CSV (text/csv)
// and many more (see [Response.mimeTypes()]).
func (r Response) InferredType() string {
	if r.IsEmpty() {
		return ""
	}

	if _, ok := r.mimeTypes()[r.ContentType()]; !ok {
		return ""
	}

	return r.mimeTypes()[r.ContentType()]
}

func (r Response) mimeTypes() map[string]string {
	return map[string]string{
		"text/html":               "HTML",
		"text/css":                "CSS",
		"text/csv":                "CSV",
		"text/calendar":           "ICS",
		"image/gif":               "GIF",
		"image/jpeg":              "JPEG",
		"image/png":               "PNG",
		"application/json":        "JSON",
		"application/x-httpd-php": "PHP",
		"application/xml":         "XML",
		"application/pdf":         "PDF",
		"application/gzip":        "GZIP",
		"application/ogg":         "OGG",
		"audio/mpeg":              "MP3",
		"audio/ogg":               "OGG",
		"video/mp4":               "MP4",
		"video/mpeg":              "MPEG",
		"video/ogg":               "OGG",
		"font/ttf":                "TTF",
		"font/woff":               "WOFF",
		"font/woff2":              "WOFF",
	}
}

// IsEmpty returns whether the response is empty.
func (r Response) IsEmpty() bool {
	return r.Proto == "" && r.Code == 0 && r.Status == "" && r.Headers == nil && r.Body == nil
}

// FromJSON returns a response from a JSON byte slice.
func FromJSON(data []byte) (Response, error) {
	var res Response
	err := json.Unmarshal(data, &res)
	return res, err
}

// ToJSON returns the response as a JSON byte slice.
func (r Response) ToJSON() ([]byte, error) {
	return json.Marshal(&r)
}

// ParseResponse parses a byte slice into a response.
func ParseResponse(b []byte) (*Response, error) {
	bytesReader := bytes.NewReader(b)
	tp := textproto.NewReader(bufio.NewReader(bytesReader))

	// Read the status line
	statusLine, err := tp.ReadLine()
	if err != nil {
		return nil, errors.Join(ErrInvalidStatusLine, err)
	}

	// Parse status line
	const chunks = 3
	parts := strings.SplitN(statusLine, " ", chunks)
	if len(parts) < chunks {
		return nil, errors.Join(ErrInvalidStatusLine, err)
	}

	proto := parts[0]
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, errors.Join(ErrInvalidStatusCode, err)
	}
	status := parts[2]

	// Read headers
	headers, err := tp.ReadMIMEHeader()
	if err != nil {
		return nil, errors.Join(ErrInvalidHeaders, err)
	}

	// Convert MIMEHeader to a map[string][]string
	headerMap := map[string][]string(headers)

	// Read body
	var body []byte
	if tp.R.Buffered() > 0 {
		body, err = io.ReadAll(tp.R)
		if err != nil {
			return nil, errors.Join(ErrUnreadableBody, err)
		}
	}

	return &Response{
		Proto:   proto,
		Code:    code,
		Status:  status,
		Headers: headerMap,
		Body:    body,
	}, nil
}
