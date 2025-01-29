package entrypoint

import (
	"strings"

	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

// PathFinder must implement the Finder interface.
var _ Finder = PathFinder{}

// PathFinder is used to find entrypoints in the request's path.
type PathFinder struct{}

// NewPathFinder instantiates a new PathFinder.
func NewPathFinder() PathFinder {
	return PathFinder{}
}

func (PathFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)

	pathChunks := strings.Split(strings.Split(req.Path, "?")[0], "/")

	for i, chunk := range pathChunks[1:] {
		prefix := strings.Join(pathChunks[:i+1], "/")
		entrypoints = append(entrypoints, newMultiplePath(prefix, chunk))

		if i == 0 {
			entrypoints = append(entrypoints, newSinglePath(prefix, chunk))
		}
	}

	return entrypoints
}

func newMultiplePath(prefix, value string) Path {
	return newPath(profile.MultiplePathDiscovery, prefix, value)
}
