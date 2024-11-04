package stdclient

import (
	"net/http"
	"net/url"
)

// Opt is a functional option for the Client.
type Opt func(*Client)

// WithClient is an option that sets the [http.Client] instance.
//
// Be careful when used in combination with [WithProxyAddr],
// as it will override the transport settings.
func WithClient(std *http.Client) Opt {
	return func(c *Client) {
		c.c = std
	}
}

// WithProxyAddr is an option that sets the proxy address.
//
// Be careful when used in combination with [WithClient],
// as it will override the transport settings.
func WithProxyAddr(addr string) Opt {
	return func(c *Client) {
		// Let's ignore the error here, as it will pop up somewhere else.
		// In the future, we might explore other ways to handle this error.
		proxyURL, _ := url.Parse(addr)

		transport := DefaultTransport.Clone()
		transport.Proxy = http.ProxyURL(proxyURL)
		c.c.Transport = transport
		c.proxyAddr = addr
	}
}
