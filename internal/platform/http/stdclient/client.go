package stdclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/bountysecurity/gbounty/internal/platform/metrics"
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
)

// Client is a custom implementation of an HTTP client that
// can be used to perform HTTP requests.
type Client struct {
	c *http.Client
}

// New is a constructor function that creates a new instance of the Client type.
func New(opts ...Opt) *Client {

	return &Client{
		c: http.DefaultClient,
	}
}

// Do perform an HTTP request with the given [request.Request]
// and returns a [response.Response] and an error, if any.
func (c *Client) Do(ctx context.Context, req *request.Request) (response.Response, error) {
	metrics.OngoingRequests.Inc()
	defer metrics.OngoingRequests.Dec()

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
