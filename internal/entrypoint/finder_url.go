package entrypoint

import (
	"fmt"
	"path"
	"strings"

	"github.com/bountysecurity/gbounty/internal/request"
)

// URLFinder must implement the Finder interface.
var _ Finder = URLFinder{}

// URLFinder is used to find entrypoints in the request's URL.
type URLFinder struct{}

// NewURLFinder instantiates a new URLFinder.
func NewURLFinder() URLFinder {
	return URLFinder{}
}

func (f URLFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)

	dir := path.Dir(req.Path)
	base := path.Base(req.Path)

	file, query := f.splitFile(base)

	switch dir {
	case ".":
		return append(entrypoints, newURLFile("", file, query))
	case "/":
		return append(entrypoints, newURLFile("/", file, query))
	default:
		entrypoints = append(entrypoints, newURLFile(fmt.Sprintf("%s/", dir), file, query))
	}

	if dir != "/" {
		dirChunks := strings.Split(dir, "/")

		for i, chunk := range dirChunks[1:] {
			prefix := strings.Join(dirChunks[:i+1], "/")

			var tmpBase string
			if i < len(dirChunks)-2 {
				tmpBase = fmt.Sprintf("/%s/%s", strings.Join(dirChunks[i+2:], "/"), base)
			} else {
				tmpBase = fmt.Sprintf("/%s", base)
			}

			entrypoints = append(entrypoints, newURLFolder(fmt.Sprintf("%s/", prefix), chunk, tmpBase))
		}
	}

	return entrypoints
}

func (URLFinder) splitFile(file string) (string, string) {
	idx := strings.Index(file, "?")

	switch idx {
	case -1:
		return file, ""
	default:
		return file[:idx], file[idx:]
	}
}
