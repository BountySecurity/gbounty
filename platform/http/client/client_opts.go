package client

// Opt is a functional option for the Client.
type Opt func(*Client)

// WithProxyAddr is an option that sets the proxy address.
func WithProxyAddr(addr string) Opt {
	return func(c *Client) {
		c.proxyAddr = addr
	}
}

// WithProxyAuth is an option that sets the proxy authentication.
func WithProxyAuth(auth string) Opt {
	return func(c *Client) {
		c.proxyAuth = auth
	}
}
