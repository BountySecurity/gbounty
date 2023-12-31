package entrypoint

import (
	"github.com/bountysecurity/gbounty/internal/request"
)

// MultipartFinder must implement the Finder interface.
var _ Finder = MultipartFinder{}

// MultipartFinder is used to find entrypoints in the request's multipart form.
type MultipartFinder struct{}

// NewMultipartFinder instantiates a new MultipartFinder.
func NewMultipartFinder() MultipartFinder {
	return MultipartFinder{}
}

func (f MultipartFinder) Find(req request.Request) []Entrypoint {
	form, err := req.MultipartForm()
	if err != nil || form == nil {
		// Open questions:
		// - Should we log errors? (Maybe on verbose)
		return nil
	}

	entrypoints := make([]Entrypoint, 0, len(form.Value)*2+len(form.File)*2)

	for k := range form.Value {
		entrypoints = append(entrypoints, NewMultipartName(k), NewMultipartValue(k))
	}

	for k := range form.File {
		entrypoints = append(entrypoints, NewMultipartName(k), NewMultipartValue(k))
	}

	return entrypoints
}
