package entrypoint

import (
	"net/http"

	"github.com/bountysecurity/gbounty/request"
)

// CookieFinder must implement the Finder interface.
var _ Finder = CookieFinder{}

// CookieFinder is used to find entrypoints in the request's cookies.
type CookieFinder struct{}

// NewCookieFinder instantiates a new CookieFinder.
func NewCookieFinder() CookieFinder {
	return CookieFinder{}
}

func (f CookieFinder) Find(req request.Request) []Entrypoint {
	reqCookies := req.Cookies()
	if len(reqCookies) == 0 {
		return nil
	}

	var (
		tmp         string
		entrypoints = make([]Entrypoint, 0, len(reqCookies)*2) //nolint:mnd
	)

	for _, c := range reqCookies {
		// Cookie name
		cName := c.Name
		tmp = cName
		c.Name = cookieReplace
		entrypoints = append(entrypoints, newCookieName(cookies(reqCookies).string(), tmp))
		c.Name = tmp

		// Cookie V
		tmp = c.Value
		c.Value = cookieReplace
		entrypoints = append(entrypoints, newCookieValue(cookies(reqCookies).string(), cName, tmp))
		c.Value = tmp
	}

	return entrypoints
}

type cookies []*http.Cookie

func (c cookies) string() string {
	var cookieStr string

	for i, c := range c {
		next := c.Name + "=" + c.Value

		if i == 0 {
			cookieStr += next
		} else {
			cookieStr += "; " + next
		}
	}

	return cookieStr
}
