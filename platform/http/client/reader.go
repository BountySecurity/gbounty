package client

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http/httputil"
	"net/textproto"
	"strconv"
	"strings"
)

var (
	// ErrInvalidHeader is returned when there is an error while parsing the header line.
	ErrInvalidHeader = errors.New("invalid header line")
	// ErrInvalidProtocol is returned when there is an error while parsing the protocol.
	ErrInvalidProtocol = errors.New("invalid protocol")
	// ErrInvalidStatusCode is returned when there is an error while parsing the status code.
	ErrInvalidStatusCode = errors.New("invalid status code")
	// ErrInvalidStatusLine is returned when there is an error while parsing the status line.
	ErrInvalidStatusLine = errors.New("invalid status line")
	// ErrInvalidGZIP is returned when there is an error while reading a gzipped response body.
	ErrInvalidGZIP = errors.New("invalid gzip encoding")
)

type reader struct {
	*bufio.Reader
}

func (r *reader) readResponse() (string, int, string, map[string][]string, io.Reader, error) {
	proto, code, msg, err := r.readStatusLine()
	if err != nil {
		return "", 0, "", nil, nil, fmt.Errorf("%w: %s", ErrInvalidStatusLine, err.Error())
	}

	headers := make(map[string][]string)

	for {
		var (
			key, value string
			done       bool
		)

		key, value, done, err = r.readHeader()
		if err != nil || done {
			break
		}

		if key == "" {
			return "", 0, "", nil, nil, ErrInvalidHeader
		}

		if _, exists := headers[key]; !exists {
			headers[key] = make([]string, 0, 1)
		}

		headers[key] = append(headers[key], value)
	}

	var body io.Reader = r
	if l := contentLength(headers); l >= 0 {
		body = io.LimitReader(body, l)
	} else if transferEncoding(headers) == "chunked" {
		body = httputil.NewChunkedReader(body)
	}

	if strings.Contains(strings.Join(headers["Content-Encoding"], " "), "gzip") {
		body, err = gzip.NewReader(body)
		if err != nil {
			return "", 0, "", nil, nil, ErrInvalidGZIP
		}

		const maxResponseReadSizeDecompress = 10 * 1024 * 1024
		body = io.LimitReader(body, maxResponseReadSizeDecompress)
	}

	return proto, code, msg, headers, body, err
}

func (r *reader) readProto() (string, error) {
	var major, minor int

	for pos := 0; pos < len("HTTP/x.x "); pos++ {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}

		switch pos {
		case 0:
			if c != 'H' {
				return "", fmt.Errorf("%w: expected: 'H', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		case 1, 2:
			if c != 'T' {
				return "", fmt.Errorf("%w: expected: 'T', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		case 3:
			if c != 'P' {
				return "", fmt.Errorf("%w: expected: 'P', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		case 4:
			if c != '/' {
				return "", fmt.Errorf("%w: expected: '/', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		case 5:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				major = int(c) - 0x30
			}
		case 6:
			if c != '.' {
				return "", fmt.Errorf("%w: expected: '.', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		case 7:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				minor = int(c) - 0x30
			}
		case 8:
			if c != ' ' {
				return "", fmt.Errorf("%w: expected: ' ', got: %q, position: %v", ErrInvalidProtocol, c, pos)
			}
		}
	}

	return fmt.Sprintf("HTTP/%d.%d", major, minor), nil
}

func (r *reader) readStatusCode() (int, error) {
	var code int

	for pos := 0; pos < len("200 "); pos++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}

		switch pos {
		case 0, 1, 2:
			switch c {
			case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
				switch pos {
				case 0:
					code = (int(c) - 0x30) * 100
				case 1:
					code += (int(c) - 0x30) * 10
				case 2:
					code += int(c) - 0x30
				}
			}
		case 3:
			switch c {
			case '\r':
			case ' ':
			default:
				return 0, fmt.Errorf("%w: expected: ' ', got: %q, position: %d", ErrInvalidStatusCode, c, pos)
			}
		}
	}

	return code, nil
}

func (r *reader) readStatusLine() (string, int, string, error) {
	proto, err := r.readProto()
	if err != nil {
		return "", 0, "", err
	}

	code, err := r.readStatusCode()
	if err != nil {
		return "", 0, "", err
	}

	msg, _, err := r.ReadLine()

	return proto, code, string(msg), err
}

func (r *reader) readHeader() (string, string, bool, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return "", "", false, err
	}

	if line := string(line); line == "\r\n" || line == "\n" {
		return "", "", true, nil
	}

	const pair = 2
	v := bytes.SplitN(line, []byte(":"), pair)
	if len(v) != pair {
		return "", "", false, fmt.Errorf("%w: %q", ErrInvalidHeader, line)
	}

	return textproto.CanonicalMIMEHeaderKey(string(bytes.TrimSpace(v[0]))), string(bytes.TrimSpace(v[1])), false, nil
}

func contentLength(headers map[string][]string) int64 {
	if _, exists := headers["Content-Length"]; !exists {
		return -1
	}

	for _, value := range headers["Content-Length"] {
		length, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			continue
		}

		return length
	}

	return -1
}

func transferEncoding(headers map[string][]string) string {
	if _, exists := headers["Transfer-Encoding"]; !exists {
		return ""
	}

	switch enc := headers["Transfer-Encoding"][0]; enc {
	case "identity", "chunked":
		return enc
	default:
		return "identity"
	}
}
