package stdclient

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/bountysecurity/gbounty/kit/logger"
	"golang.org/x/net/http2"

	"github.com/bountysecurity/gbounty/internal/platform/metrics"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
)

// Client is a custom implementation of an HTTP client that
// can be used to perform HTTP requests.
type Client struct {
	c         *http.Client
	proxyAddr string
}

// New is a constructor function that creates a new instance of the Client type.
func New(opts ...Opt) *Client {
	c := &Client{
		c: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Do perform an HTTP request with the given [request.Request]
// and returns a [response.Response] and an error, if any.
func (c *Client) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	// First, we want to account all the ongoing HTTP requests.
	// So, we measure the ones performed by the [http.Client] as well.
	metrics.OngoingRequests.Inc()
	defer metrics.OngoingRequests.Dec()

	// Then, we set the client's [http.Client.Timeout] based on the one
	// defined on the request. However, we don't want to override the default
	// client's timeout for the upcoming requests, when reused, if ever.
	defaultTimeout := c.c.Timeout
	if req.Timeout > 0 {
		c.c.Timeout = req.Timeout
		defer func() {
			c.c.Timeout = defaultTimeout
		}()
	}

	// For HTTP/2 requests that aren't using TLS, we need to use custom
	// transport that allows HTTP/2 without TLS.
	defaultTransport := c.c.Transport
	if strings.Contains(req.Proto, "HTTP/2") {
		// We only need to hack-in, when it is not using TLS.
		if strings.HasPrefix(req.URL, "http://") {
			// In case the proxy is enabled, with return an error directly.
			// Because, we (the stdlib) don't have support to proxy non-TLS HTTP/2 requests.
			if c.proxyAddr != "" {
				return response.Response{}, errors.New("non-TLS HTTP/2 requests cannot be proxy-ed")
			}
			c.c.Transport = &http2.Transport{
				AllowHTTP: true, // Allows HTTP/2 without TLS.
				DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr) // Skip TLS handshake for plaintext.
				},
				IdleConnTimeout: 5 * time.Second,
			}
			defer func() {
				c.c.Transport = defaultTransport
			}()
		}
	} else {
		logger.For(ctx).Warn("In theory, this should never happen - the request is not using HTTP/2.")
		logger.For(ctx).Warn("Instead, you should use the custom client to perform non-HTTP/2 requests.")
		logger.For(ctx).Warn("You can find it at: `internal/platform/http/client`.")
	}

	// We translate the [request.Request] into a [http.Request].
	var resp response.Response
	httpReq, err := req.ToStdlibWithContext(ctx)
	if err != nil {
		return resp, err
	}

	// Then, we perform the request.
	httpRes, httpErr := c.c.Do(httpReq)
	if httpRes != nil {
		// If there's a response, we translate the [http.Response] into a [response.Response].
		resp, err = response.FromStdlib(httpRes)
		// Once we have read the body, we close it. So, later we can close the connection.
		// Also, to make sure we don't leak file descriptors.
		if httpRes.Body != nil {
			closeErr := httpRes.Body.Close()
			if closeErr != nil {
				logger.For(ctx).Warnf("Error while closing stdlib client's response body: %s", closeErr)
			}
		}
	}

	// Finally, before returning, we try to close the idle connections, with the aim of not
	// leaving connections open, especially in HTTP/2, where persistent connections are the default.
	//
	// In the future, we might explore a way to reuse connections per host, so we take benefit of
	// this default HTTP/2 behavior. However, re-usability isn't that simple, because we don't know
	// how many different hosts are we reaching concurrently and over the whole scan.
	switch t := c.c.Transport.(type) {
	case *http.Transport:
		t.CloseIdleConnections()
	case *http2.Transport:
		t.CloseIdleConnections()
	}

	return resp, errors.Join(httpErr, err)
}

var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 5 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          1,
	DisableKeepAlives:     true,
	IdleConnTimeout:       5 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}
