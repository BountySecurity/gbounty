package entrypoint

import (
	"github.com/BountySecurity/gbounty/kit/strings/occurrence"
	"github.com/BountySecurity/gbounty/request"
)

// UserProvidedFinder must implement the Finder interface.
var _ Finder = UserProvidedFinder{}

// UserProvidedFinder is used to find user-provided entrypoints.
type UserProvidedFinder struct{}

// NewUserProvidedFinder instantiates a new QueryFinder.
func NewUserProvidedFinder() UserProvidedFinder {
	return UserProvidedFinder{}
}

func (f UserProvidedFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)

	// Find in path
	occurrence.ForEach(req.Path, UserProvidedInput, func(s string, from, to int) {
		entrypoints = append(entrypoints, newUserProvidedPath(req.Path[:from], req.Path[to:]))
	})

	// Find in headers
	for header, values := range req.Headers {
		for valIdx, val := range values {
			occurrence.ForEach(val, UserProvidedInput, func(s string, from, to int) {
				entrypoints = append(entrypoints, newUserProvidedHeaders(val[:from], val[to:], header, valIdx))
			})
		}
	}

	// Find in body
	occurrence.ForEach(string(req.Body), UserProvidedInput, func(s string, from, to int) {
		entrypoints = append(entrypoints, newUserProvidedBody(string(req.Body)[:from], string(req.Body)[to:]))
	})

	return entrypoints
}
