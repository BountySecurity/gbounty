package url

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ErrInvalidURL is returned when there's an error during
// the URL validation (i.e. Validate).
var ErrInvalidURL = errors.New("invalid url")

// Validate checks if the given URL is valid and complete,
// following the same rules as [url.ParseRequestURI], and verifying
// that the URL contains a host (e.g. not just a path or query).
//
// If the URL has no protocol, it fallbacks to `http://`,
// by modifying the value stored in the given string pointer.
func Validate(str *string) error {
	if !strings.Contains(*str, "://") {
		*str = fmt.Sprintf("http://%s", *str)
	}

	u, err := url.ParseRequestURI(*str)
	if err != nil {
		return errors.Join(ErrInvalidURL, err)
	}

	if u.Host == "" {
		return fmt.Errorf("%w: %s", ErrInvalidURL, *str)
	}

	return nil
}
