package blindhost

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrInvalidAddress is returned when the blind host address cannot
	// be parsed as a valid address.
	ErrInvalidAddress = errors.New("invalid address")

	// ErrMissingScheme is returned when the blind host address is missing the scheme.
	ErrMissingScheme = errors.New("missing scheme")

	// ErrMissingHost is returned when the blind host address is missing the host.
	ErrMissingHost = errors.New("missing host")

	// ErrAddHost is returned when the client failed to add a host.
	ErrAddHost = errors.New("failed to add host")
)

// Interaction holds all the information that represents an interaction
// between an HTTP client and the blind host server.
type Interaction struct {
	ID            string    `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Protocol      string    `json:"protocol"`
	Type          string    `json:"type"`
	RemoteAddress string    `json:"remoteAddress"`
	RawRequest    string    `json:"rawRequest"`
	RawResponse   string    `json:"rawResponse"`
	NRequest      string    `json:"nRequest"`
}

// HostIdentifier is a unique identifier for an interaction host.
type HostIdentifier uuid.UUID

// RandomHostIdentifier generates a random host identifier by using
// the Google's UUIDv4 generation library (github.com/google/uuid).
func RandomHostIdentifier() HostIdentifier {
	return HostIdentifier(uuid.New())
}

// ID returns the first 8 characters of the interaction host identifier, considered as the id.
func (h HostIdentifier) ID() string {
	return uuid.UUID(h).String()[:8]
}

// PrivateKey returns the interaction host identifier (UUIDv4) as a string.
func (h HostIdentifier) PrivateKey() string {
	return uuid.UUID(h).String()
}

// HostBaseURL calculates the base URL of the interaction host, given a base URL.
func (h HostIdentifier) HostBaseURL(base string) string {
	scheme := urlScheme(base)
	return fmt.Sprintf("%s://%s.%s", scheme, h.ID(), base)
}

// HostReqURL calculates the request URL of the interaction host, given a base URL and a unique identifier.
// This can be used to uniquely identify each interaction with the interaction host.
func (h HostIdentifier) HostReqURL(scheme, base, uid string) string {
	return fmt.Sprintf("%s://%s.%s.%s", scheme, uid, h.ID(), base)
}

func urlScheme(addr string) string {
	u, err := url.Parse(addr)
	if err != nil || u == nil || u.Scheme == "" {
		// Error must always be nil at this point,
		// but let's be cautious.
		return "http"
	}
	return u.Scheme
}
