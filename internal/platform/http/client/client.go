package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	stdurl "net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/bountysecurity/gbounty/internal/platform/metrics"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/panics"
)

const (
	httpProtocol = "http"
)

// Client is a custom implementation of an HTTP client that
// can be used to perform HTTP requests.
type Client struct {
	proxyAddr string
	proxyAuth string
}

// New is a constructor function that creates a new instance of
// the Client type with the given options [Opt].
func New(opts ...Opt) *Client {
	c := &Client{}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Do perform an HTTP request with the given [request.Request]
// and returns a [response.Response] and an error, if any.
func (c *Client) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	metrics.OngoingRequests.Inc()
	defer metrics.OngoingRequests.Dec()

	errReqTimeout := fmt.Errorf("http request took more than %s (canceled)", req.Timeout.String()) //nolint:goerr113
	ctxWithTimeout, cancel := context.WithTimeoutCause(ctx, req.Timeout, errReqTimeout)
	defer cancel()

	type result struct {
		response.Response
		error error
	}

	ch := make(chan result, 1)

	go func() {
		defer panics.Log(ctx)

		resp, err := c.do(
			ctxWithTimeout,
			req.URL, req.Method, req.Path, req.Proto,
			req.Headers, bytes.NewReader(req.Body),
			req.Timeout,
		)

		ch <- result{Response: resp, error: err}
	}()

	timer := time.NewTimer(req.Timeout + 3*time.Second)
	defer timer.Stop()

	select {
	case res := <-ch:
		return res.Response, res.error
	case <-timer.C:
		return response.Response{}, context.DeadlineExceeded
	case <-ctxWithTimeout.Done():
		return response.Response{}, context.Cause(ctxWithTimeout)
	}
}

func (c *Client) do(
	ctx context.Context,
	url, method, uripath, proto string,
	headers http.Header, body io.Reader,
	timeout time.Duration,
) (res response.Response, err error) {
	var conn net.Conn

	defer func() {
		// Ensures the connection is closed after all
		closeErr := c.closeConn(conn)
		if closeErr != nil && err == nil {
			err = closeErr
		}

		// Converts the given error into a marshalable error type
		if err != nil {
			netError := NetError("network error: " + err.Error())
			err = &netError
		}
	}()

	protocol := httpProtocol
	if strings.HasPrefix(strings.ToLower(url), "https://") {
		protocol = "https"
	}

	if headers == nil {
		headers = make(map[string][]string)
	}

	u, err := stdurl.ParseRequestURI(url)
	if err != nil {
		return
	}

	host := u.Host
	if !strings.Contains(host, ":") {
		if protocol == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}

	if uripath != "" {
		path = uripath
	}

	startTime := time.Now()
	defer func() {
		res.Time = time.Since(startTime)
	}()

	conn, err = c.connect(ctx, protocol, host, proto, timeout)
	if err != nil {
		return
	}
	res.ConnTime = time.Since(startTime)

	if timeout > 0 {
		err = conn.SetDeadline(time.Now().Add(timeout))
		if err != nil {
			return
		}
	}

	if err = c.writeRequest(conn, method, path, proto, headers, body); err != nil {
		return
	}

	var respBody io.Reader

	res.Proto, res.Code, res.Status, res.Headers, respBody, err = c.readResponse(conn)
	if err != nil {
		return
	}

	res.Body, err = io.ReadAll(respBody)

	return
}

func (c *Client) connect(ctx context.Context, protocol, host, proto string, timeout time.Duration) (net.Conn, error) {
	if len(c.proxyAddr) == 0 {
		var d proxy.ContextDialer = &net.Dialer{Timeout: timeout}
		if protocol != httpProtocol {
			//nolint:gosec,forcetypeassert
			d = &tls.Dialer{NetDialer: d.(*net.Dialer), Config: &tls.Config{InsecureSkipVerify: true}}
		}
		return d.DialContext(ctx, "tcp", host)
	}

	var (
		conn net.Conn
		err  error
	)

	var d proxy.ContextDialer = &net.Dialer{Timeout: timeout}
	if strings.HasPrefix(strings.ToLower(c.proxyAddr), "https://") {
		//nolint:gosec,forcetypeassert
		d = &tls.Dialer{NetDialer: d.(*net.Dialer), Config: &tls.Config{InsecureSkipVerify: true}}
		conn, err = d.DialContext(ctx, "tcp", c.proxyAddr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.proxyAddr)
	}

	if err != nil {
		return nil, err
	}

	headers := map[string][]string{}
	if len(c.proxyAuth) > 0 {
		headers["Proxy-Authorization"] = []string{"Basic " + c.proxyAuth}
	}

	err = c.writeRequest(conn, http.MethodConnect, host, proto, headers, nil)
	if err != nil {
		conn.Close()
		return nil, err
	}

	_, _, _, _, _, err = c.readResponse(conn) //nolint:dogsled
	if err != nil {
		conn.Close()
		return nil, err
	}

	if protocol == httpProtocol {
		return conn, nil
	}

	return tls.Client(conn, &tls.Config{InsecureSkipVerify: true}), nil //nolint:gosec
}

func (c *Client) writeRequest(conn io.Writer, method, path, proto string, headers map[string][]string, body io.Reader) error {
	return (&writer{Writer: conn}).writeRequest(method, path, proto, headers, body)
}

func (c *Client) readResponse(conn io.Reader) (string, int, string, map[string][]string, io.Reader, error) {
	const readerSize = 4096
	return (&reader{bufio.NewReaderSize(conn, readerSize)}).readResponse()
}

func (c *Client) closeConn(conn net.Conn) error {
	if conn == nil {
		return nil
	}

	defer func() { _ = recover() }()

	return conn.Close()
}
