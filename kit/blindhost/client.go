package blindhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Client is a client that can interact with the blind host server
// to add hosts and retrieve interactions.
type Client struct {
	addr string
	*http.Client
}

// ClientOpt is an option to modify a [Client].
type ClientOpt func(*Client)

// WithClient is a [ClientOpt] that sets the given *http.Client  as the inner client of the [Client].
// If not provided, the default client is the [http.DefaultClient].
func WithClient(httpClient *http.Client) ClientOpt {
	return func(c *Client) {
		c.Client = httpClient
	}
}

// NewClient creates a new [Client], ready to use, with the given address and options.
func NewClient(addr string, opts ...ClientOpt) (*Client, error) {
	if !strings.Contains(addr, "://") {
		addr = "http://" + addr
	}
	_, err := parseBlindHostAddress(addr)
	if err != nil {
		return nil, err
	}

	client := &Client{addr: addr, Client: http.DefaultClient}
	for _, opt := range opts {
		opt(client)
	}
	return client, nil
}

// AddHost adds a new interaction host to the blind host server.
func (c *Client) AddHost(ctx context.Context, id HostIdentifier) (err error) {
	// Validate URL
	var u string
	u, err = url.JoinPath(c.addr, "/add")
	if err != nil {
		return err
	}

	// Prepare request
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(fmt.Sprintf(`[
	{"ID": "%s", "PrivateKey": "%s"}
]`, id.ID(), id.PrivateKey()))))
	if err != nil {
		return err
	}

	// Set up headers (Content-Type: application/json)
	req.Header.Set("Content-Type", "application/json")

	// Perform request (POST)
	var resp *http.Response
	resp, err = c.Do(req)
	if err != nil {
		return err
	}

	// Close response body (report error, if any)
	defer func() {
		closeErr := resp.Body.Close()
		err = errors.Join(err, closeErr)
	}()

	// Parse response body
	var body struct {
		Status string `json:"status"`
	}
	err = json.NewDecoder(resp.Body).Decode(&body)
	if err != nil {
		return err
	}

	// Check status (adhoc)
	if body.Status != "Added successfully" {
		return fmt.Errorf("%w: %s", ErrAddHost, body.Status)
	}

	return nil
}

// GetAllInteractions retrieves all the interactions detected for the
// interaction host with the given [HostIdentifier].
func (c *Client) GetAllInteractions(ctx context.Context, id HostIdentifier) (interactions []Interaction, err error) {
	return c.getInteractions(ctx, id, "/historic")
}

// GetInteractions retrieves the new interactions (since last retrieval) detected for the
// interaction host with the given [HostIdentifier].
func (c *Client) GetInteractions(ctx context.Context, id HostIdentifier) (interactions []Interaction, err error) {
	return c.getInteractions(ctx, id, "/get")
}

func (c *Client) getInteractions(ctx context.Context, id HostIdentifier, endpoint string) (interactions []Interaction, err error) {
	// Validate URL
	var u string
	u, err = url.JoinPath(c.addr, endpoint)
	if err != nil {
		return nil, err
	}

	// Prepare request
	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(fmt.Sprintf(`[
	{"ID": "%s", "PrivateKey": "%s"}
]`, id.ID(), id.PrivateKey()))))
	if err != nil {
		return nil, err
	}

	// Set up headers (Content-Type: application/json)
	req.Header.Set("Content-Type", "application/json")

	// Perform request (POST)
	var resp *http.Response
	resp, err = c.Do(req)
	if err != nil {
		return nil, err
	}

	// Close response body (report error, if any)
	defer func() {
		closeErr := resp.Body.Close()
		err = errors.Join(err, closeErr)
	}()

	err = json.NewDecoder(resp.Body).Decode(&interactions)
	if err != nil {
		return nil, err
	}

	return interactions, nil
}

func parseBlindHostAddress(addr string) (*url.URL, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("%w (%s): %s", ErrInvalidAddress, err.Error(), addr)
	}

	if u.Scheme == "" {
		return nil, fmt.Errorf("%s (%w): %s", ErrInvalidAddress.Error(), ErrMissingScheme, addr)
	}

	if u.Host == "" {
		return nil, fmt.Errorf("%s (%w): %s", ErrInvalidAddress.Error(), ErrMissingHost, addr)
	}
	return u, nil
}
