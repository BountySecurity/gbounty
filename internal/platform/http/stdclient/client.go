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
	if req.Proto == "HTTP/2.0" {
		// We only need to hack-in, when it is not using TLS.
		if strings.HasPrefix(req.URL, "http://") {
			// In case the proxy is enabled, with return an error directly.
			// Because, we (the stdlib) don't have support to proxy non-TLS HTTP/2.0 requests.
			if c.proxyAddr != "" {
				return response.Response{}, errors.New("non-TLS HTTP/2.0 requests cannot be proxy-ed")
			}
			c.c.Transport = &http2.Transport{
				AllowHTTP: true, // Allows HTTP/2 without TLS.
				DialTLSContext: func(_ context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
					return net.Dial(network, addr) // Skip TLS handshake for plaintext.
				},
			}
			defer func() {
				c.c.Transport = defaultTransport
			}()
		}
	} else {
		logger.For(ctx).Warn("In theory, this should never happen - the request is not using HTTP/2.0.")
		logger.For(ctx).Warn("Instead, you should use the custom client to perform non-HTTP/2.0 requests.")
		logger.For(ctx).Warn("You can find it at: `internal/platform/http/client`.")
	}

	var resp response.Response
	httpReq, err := req.ToStdlibWithContext(ctx)
	if err != nil {
		return resp, err
	}

	httpRes, httpErr := c.c.Do(httpReq)
	if httpRes != nil {
		resp, err = response.FromStdlib(httpRes)
	}

	return resp, errors.Join(httpErr, err)
}

var DefaultTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: defaultTransportDialContext(&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}),
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          100,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
	},
}

func defaultTransportDialContext(dialer *net.Dialer) func(context.Context, string, string) (net.Conn, error) {
	return dialer.DialContext
}
