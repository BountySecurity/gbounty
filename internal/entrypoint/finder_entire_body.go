package entrypoint

import (
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

// EntireBodyFinder must implement the Finder interface.
var _ Finder = EntireBodyFinder{}

// EntireBodyFinder is used to find entrypoints in the request's entire body.
type EntireBodyFinder struct{}

// NewEntireBodyFinder instantiates a new EntireBodyFinder.
func NewEntireBodyFinder() EntireBodyFinder {
	return EntireBodyFinder{}
}

func (EntireBodyFinder) Find(req request.Request) []Entrypoint {
	if len(req.Body) == 0 {
		return nil
	}

	entrypoints := []Entrypoint{newEntireBody(profile.EntireBody, req.Body)}

	if req.HasJSONBody() {
		entrypoints = append(entrypoints, newEntireBody(profile.EntireBodyJSON, req.Body))
	}

	if req.HasXMLBody() {
		entrypoints = append(entrypoints, newEntireBody(profile.EntireBodyXML, req.Body))
	}

	if req.HasMultipartBody() {
		entrypoints = append(entrypoints, newEntireBody(profile.EntireBodyMulti, req.Body))
	}

	return entrypoints
}
