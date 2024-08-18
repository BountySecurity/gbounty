package request

import (
	"time"
)

// Option defines a functional option type for [Request], that facilitates the construction
// of a [Default] template, but with some of the default values modified, like the HTTP method.
//
// It can be used in combination with [WithOptions].
//
// For instance:
// request.WithOptions("example.org", []request.Option{request.WithMethod("POST")}).
type Option func(Request) Request

// WithOptions can be used to construct a [Default] request, but with some of the default values modified,
// like the HTTP method.
//
// It can be used in combination with [Option].
//
// For instance:
// request.WithOptions("example.org", []request.Option{request.WithMethod("POST")}).
func WithOptions(host string, options ...Option) Request {
	req := Default(host)
	for _, option := range options {
		req = option(req)
	}
	return req
}

// WithMethod modifies the default method (i.e. GET).
func WithMethod(method string) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Method = method
		return newReq
	}
}

// WithPath modifies the default path (i.e. /).
func WithPath(path string) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Path = path
		return newReq
	}
}

// WithProto modifies the default proto (i.e. HTTP/1.1).
func WithProto(proto string) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Proto = proto
		return newReq
	}
}

// WithHeaders modifies the default headers (see [Default]).
func WithHeaders(headers map[string][]string) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Headers = headers
		return newReq
	}
}

// WithHeader adds a new header to the default ones (see [Default]).
func WithHeader(key, value string) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Headers[key] = []string{value}
		return newReq
	}
}

// WithBody sets a body (not defined by [Default]).
func WithBody(body []byte) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.SetBody(body)
		return newReq
	}
}

// WithData sets a body data as a form (i.e. as `application/x-www-form-urlencoded`).
func WithData(data []byte) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.SetBody(data)
		newReq.Headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
		return newReq
	}
}

// WithTimeout modifies the default timeout (i.e. 20s).
func WithTimeout(timeout time.Duration) Option {
	return func(req Request) Request {
		newReq := req.Clone()
		newReq.Timeout = timeout
		return newReq
	}
}
