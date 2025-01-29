package entrypoint

import (
	"path"
	"strings"

	"github.com/BountySecurity/gbounty/request"
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
		entrypoints = append(entrypoints, newURLFile(dir+"/", file, query))
	}

	if dir != "/" {
		dirChunks := strings.Split(dir, "/")

		for i, chunk := range dirChunks[1:] {
			prefix := strings.Join(dirChunks[:i+1], "/")

			var tmpBase string
			if i < len(dirChunks)-2 {
				tmpBase = "/" + strings.Join(dirChunks[i+2:], "/") + "/" + base
			} else {
				tmpBase = "/" + base
			}

			entrypoints = append(entrypoints, newURLFolder(prefix+"/", chunk, tmpBase))
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
