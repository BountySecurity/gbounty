package request

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bountysecurity/gbounty/internal/profile"
	internalurl "github.com/bountysecurity/gbounty/kit/url"
)

const defaultTimeout = 20 * time.Second

var (
	// ErrInvalidHost is returned when building/parsing a request
	// from plain text and the Host line is invalid.
	ErrInvalidHost = errors.New("invalid host line")
	// ErrInvalidPayload is returned when building/parsing a request
	// from plain text and the payload is invalid.
	ErrInvalidPayload = errors.New("invalid payload")
)

// Request is a representation of an HTTP request, complementary
// to the standard [http.Request] and used here and there for scans.
type Request struct {
	UID               string // Used to detect interactions
	URL               string
	Method            string
	Path              string
	Proto             string
	Headers           map[string][]string
	Body              []byte
	Timeout           time.Duration
	RedirectType      profile.Redirect
	MaxRedirects      int
	FollowedRedirects int
	Modifications     map[string]string
}

// Default is a named constructor to instantiate a new [Request] with the given
// remote as the [Request]'s [Request.URL].
//
// By default, it sets the `GET` method, some basic headers, and a timeout of 20s.
func Default(remote string) Request {
	reqURL, _ := url.Parse(remote)
	return Request{
		URL:    remote,
		Method: "GET",
		Path:   reqURL.RequestURI(),
		Proto:  "HTTP/1.1",
		Headers: map[string][]string{
			"Host":            {strings.Split(reqURL.Host, ":")[0]},
			"Accept":          {"*/*"},
			"Accept-Language": {"en"},
			"Accept-Encoding": {"gzip, deflate"},
			"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"},
			"Connection":      {"close"},
		},
		// Default values
		Timeout:      defaultTimeout,
		RedirectType: profile.RedirectNever,
	}
}

// IsEmpty returns whether the request is empty.
func (r *Request) IsEmpty() bool {
	return r.URL == "" && r.Method == "" && r.Path == "" && r.Proto == "" && r.Headers == nil && r.Body == nil
}

// SetBody sets the request body and updates the Content-Length header
// accordingly.
func (r *Request) SetBody(body []byte) {
	r.Body = body
	if len(r.Body) > 0 {
		r.Headers["Content-Length"] = []string{strconv.Itoa(len(r.Body))}
	}
}

// HasJSONBody returns whether the request body is a valid JSON.
func (r *Request) HasJSONBody() bool {
	var js map[string]interface{}
	return json.Unmarshal(r.Body, &js) == nil
}

// HasXMLBody returns whether the request body is a valid XML.
func (r *Request) HasXMLBody() bool {
	if r.HasJSONBody() {
		return false
	}

	if r.HasMultipartBody() {
		return false
	}

	decoder := xml.NewDecoder(bytes.NewReader(r.Body))

	for {
		err := decoder.Decode(new(interface{}))
		if err != nil {
			return errors.Is(err, io.EOF)
		}
	}
}

// HasMultipartBody returns whether the request body is a valid multipart form.
func (r *Request) HasMultipartBody() bool {
	form, err := r.MultipartForm()
	return err == nil && form != nil
}

// ContentType returns the value of the Content-Type header.
func (r *Request) ContentType() string {
	return r.Header("Content-Type")
}

// Cookies returns the cookies (i.e. [*http.Cookie]) from the request headers.
func (r *Request) Cookies() []*http.Cookie {
	if r.Headers == nil {
		return nil
	}

	return (&http.Request{Header: http.Header{
		"Cookie": r.Headers["Cookie"],
	}}).Cookies()
}

// Header returns the value of the given header.
// If the header is not present, an empty string is returned.
// If the header has multiple values, the values are joined with a space.
func (r *Request) Header(header string) string {
	if r.Headers == nil {
		return ""
	}
	return strings.Join(r.Headers[header], " ")
}

// HeaderBytes returns the headers section as a byte slice.
func (r *Request) HeaderBytes() []byte {
	var ret string
	for k, values := range r.Headers {
		ret += k + ": " + strings.Join(values, ", ") + "\r\n"
	}
	return []byte(ret)
}

// MultipartForm returns the request body as a multipart form.
func (r *Request) MultipartForm() (*multipart.Form, error) {
	if len(r.Body) == 0 {
		return nil, nil
	}

	reader := textproto.NewReader(bufio.NewReader(bytes.NewBuffer(r.Body)))

	line, err := reader.ReadLine()
	if err != nil || len(line) < 2 {
		return nil, err
	}

	req := &http.Request{
		Header: http.Header{
			"Content-Type": {"multipart/form-data; boundary=" + line[2:]},
		},
		Body: io.NopCloser(bytes.NewReader(r.Body)),
	}

	const maxBodySize = int64(10 << 20) // 10MB
	if err = req.ParseMultipartForm(maxBodySize); err != nil {
		return nil, err
	}

	return req.MultipartForm, nil
}

// Clone returns a deep copy (e.g. headers' map, and body's byte slice
// are also copied) of the request.
func (r *Request) Clone() Request {
	return Request{
		UID:           r.UID,
		URL:           r.URL,
		Method:        r.Method,
		Path:          r.Path,
		Proto:         r.Proto,
		Headers:       copyHeaders(r.Headers),
		Body:          copyBody(r.Body),
		Timeout:       r.Timeout,
		RedirectType:  r.RedirectType,
		MaxRedirects:  r.MaxRedirects,
		Modifications: copyModifications(r.Modifications),
	}
}

func copyHeaders(headers map[string][]string) map[string][]string {
	result := make(map[string][]string, len(headers))

	for key, values := range headers {
		copyValues := make([]string, len(values))
		copy(copyValues, values)

		result[key] = copyValues
	}

	return result
}

func copyBody(body []byte) []byte {
	if body == nil {
		return nil
	}

	result := make([]byte, len(body))
	copy(result, body)
	return result
}

func copyModifications(modifications map[string]string) map[string]string {
	if modifications == nil {
		return nil
	}

	result := make(map[string]string, len(modifications))
	for key, value := range modifications {
		result[key] = value
	}
	return result
}

// RequestFromJSON creates a request from a JSON byte slice.
func RequestFromJSON(data []byte) (Request, error) {
	var req Request
	err := json.Unmarshal(data, &req)
	return req, err
}

// ToJSON returns the request as a JSON byte slice, with headers
// on its canonical form (i.e. [textproto.CanonicalMIMEHeaderKey]).
func (r *Request) ToJSON() ([]byte, error) {
	return json.Marshal(&r)
}

// Bytes returns the request as a byte slice.
func (r *Request) Bytes() []byte {
	ret := r.Method + " " + r.Path + " " + r.Proto + "\n"

	keys := make([]string, 0, len(r.Headers))
	for key := range r.Headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	for _, key := range keys {
		ret += textproto.CanonicalMIMEHeaderKey(key) + ": " + strings.Join(r.Headers[key], ", ") + "\n"
	}

	ret += "\n"
	ret += string(r.Body)

	return []byte(ret)
}

// EscapedBytes returns the request as a byte slice, with the body
// escaped (i.e. JSON encoded).
func (r *Request) EscapedBytes() []byte {
	raw := string(r.Bytes())
	escaped, err := json.Marshal(raw)
	if err != nil {
		// Open questions:
		// - Should we log errors? (Maybe on verbose)
		return nil
	}
	return escaped
}

// ParseRequest parses a request from a byte slice.
// If a host is given (variadic arg), it is used as the request URL.
func ParseRequest(b []byte, hh ...string) (Request, error) {
	var hostStr string

	// If there is any given host, then we use it straight away.
	if len(hh) > 1 {
		panic("ParseRequest: invalid function args: len(hh) > 1")
	}
	if len(hh) == 1 {
		hostStr = hh[0]
	}

	// If the first line can be interpreted as a URL, we should validate it,
	// and if valid, use it as the [Request.URL].
	firstNextLine := bytes.Index(b, []byte("\n"))
	firstLine := strings.TrimSpace(string(b[:firstNextLine]))
	if strings.HasPrefix(firstLine, "http") {
		if err := internalurl.Validate(&firstLine); err != nil {
			return Request{}, errors.Join(ErrInvalidHost, err)
		}

		host, err := url.Parse(firstLine)
		if err != nil {
			return Request{}, errors.Join(ErrInvalidHost, err)
		}

		hostStr = host.String()
		b = b[firstNextLine+len("\n"):]
	}

	bytesReader := bytes.NewReader(b)
	tp := textproto.NewReader(bufio.NewReader(bytesReader))

	first, err := tp.ReadLine()
	if err != nil {
		return Request{}, errors.Join(ErrInvalidPayload, err)
	}

	method, path, proto, ok := parseRequestLine(first)
	if !ok {
		return Request{}, fmt.Errorf("%w: %s", ErrInvalidPayload, "wrong format")
	}

	headers, err := tp.ReadMIMEHeader()
	if err != nil && !errors.Is(err, io.EOF) {
		return Request{}, errors.Join(ErrInvalidPayload, err)
	}

	// If [hostStr] remains empty, we should try to get the host from the headers.
	if len(hostStr) == 0 {
		hh := headers.Get("Host")
		if hh == "" {
			return Request{}, fmt.Errorf("%w: %s", ErrInvalidPayload, "missing host header")
		}

		if err := internalurl.Validate(&hh); err != nil {
			return Request{}, errors.Join(ErrInvalidHost, err)
		}

		host, err := url.Parse(strings.TrimSpace(hh))
		if err != nil {
			return Request{}, errors.Join(ErrInvalidHost, err)
		}

		hostStr = host.String()
	}

	body, err := readBody(tp)
	if err != nil && !errors.Is(err, io.EOF) {
		return Request{}, errors.Join(ErrInvalidPayload, err)
	}

	return Request{
		URL:     hostStr,
		Method:  method,
		Path:    path,
		Proto:   proto,
		Headers: headers,
		Body:    body,
		// Default values
		Timeout:      defaultTimeout,
		RedirectType: profile.RedirectNever,
	}, nil
}

func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")

	if s1 < 0 || s2 < 0 {
		return
	}

	s2 += s1 + 1

	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}

func readBody(tp *textproto.Reader) ([]byte, error) {
	var reqBytes []byte

	for {
		const buffSize = 1024
		recvBuf := make([]byte, buffSize)

		n, err := tp.R.Read(recvBuf)
		if err != nil {
			return nil, err
		}

		reqBytes = append(reqBytes, recvBuf[:n]...)

		if n < len(recvBuf) {
			break
		}
	}

	return reqBytes, nil
}
