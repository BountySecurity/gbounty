package profile

// Redirect represents the redirect type.
type Redirect int

// Never returns true if the redirect type is never.
func (r Redirect) Never() bool {
	return r == RedirectNever
}

// OnSite returns true if the redirect type is on site.
func (r Redirect) OnSite() bool {
	return r == RedirectOnSite
}

// Always returns true if the redirect type is always.
func (r Redirect) Always() bool {
	return r == RedirectAlways
}

const (
	RedirectNever  Redirect = 1
	RedirectOnSite Redirect = 2
	RedirectAlways Redirect = 4
)
