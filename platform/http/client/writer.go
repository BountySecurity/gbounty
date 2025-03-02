package client

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	
	"github.com/BountySecurity/gbounty/platform/http/httputil"
)

type writer struct {
	phase
	io.Writer
	tmp io.Writer
}

func (w *writer) writeRequest(method, path, proto string, headers map[string][]string, body io.Reader) error {
	if err := w.writeRequestLine(method, path, proto); err != nil {
		return err
	}

	for k, values := range headers {
		if httputil.IsListBasedHeader(k) {
			for _, v := range values {
				if err := w.writeHeader(k, v); err != nil {
					return err
				}
			}
		} else {
			if err := w.writeHeader(k, strings.Join(values, ", ")); err != nil {
				return err
			}
		}
	}

	if err := w.startBodyPhase(); err != nil || body == nil {
		return err
	}

	return w.writeBody(body)
}

func (w *writer) writeRequestLine(method, path, proto string) error {
	if w.phase != requestline {
		return &phaseError{requestline, w.phase}
	}

	w.tmp, w.Writer = w.Writer, bufio.NewWriter(w.Writer)
	_, err := fmt.Fprintf(w, "%s %s %s\r\n", method, path, proto)
	w.startHeadersPhase()

	return err
}

func (w *writer) startHeadersPhase() {
	w.phase = header
}

func (w *writer) writeHeader(key, value string) error {
	if w.phase != header {
		return &phaseError{header, w.phase}
	}

	var err error
	if value != "" {
		_, err = fmt.Fprintf(w, "%s: %s\r\n", key, value)
	} else {
		_, err = fmt.Fprintf(w, "%s\r\n", key)
	}

	return err
}

var errUnexpectedWriterType = errors.New("unexpected writer type")

func (w *writer) startBodyPhase() error {
	if _, err := w.Write([]byte("\r\n")); err != nil {
		return err
	}

	bW, ok := w.Writer.(*bufio.Writer)
	if !ok {
		return errUnexpectedWriterType
	}

	err := bW.Flush()
	w.Writer, w.tmp = w.tmp, nil
	w.phase = body

	return err
}

func (w *writer) writeBody(r io.Reader) error {
	if w.phase != body {
		return &phaseError{body, w.phase}
	}

	_, err := io.Copy(w, r)
	w.phase = requestline

	return err
}

type phase int

const (
	requestline phase = iota
	header
	body
)

func (p phase) String() string {
	switch p {
	case requestline:
		return "requestline"
	case header:
		return "headers"
	case body:
		return "body"
	default:
		return "unknown"
	}
}

type phaseError struct {
	expected, got phase
}

func (p *phaseError) Error() string {
	return fmt.Sprintf("phase error: expected %s, got %s", p.expected, p.got)
}
