package entrypoint

import (
	"strings"

	"github.com/BountySecurity/gbounty/request"
)

// BodyParamFinder must implement the Finder interface.
var _ Finder = BodyParamFinder{}

// BodyParamFinder is used to find entrypoints in the request's body.
type BodyParamFinder struct{}

// NewBodyParamFinder instantiates a new BodyParamFinder.
func NewBodyParamFinder() BodyParamFinder {
	return BodyParamFinder{}
}

func (f BodyParamFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)
	raw := string(req.Body)

	var (
		idx           int
		query         = raw
		lastParamSeen string
	)

	for query != "" {
		idx1 := strings.Index(query, "=")
		idx2 := strings.Index(query, "&")

		if idx2 == -1 {
			if idx1 == -1 {
				lastParamSeen = raw[idx:]
				entrypoints = append(entrypoints, newBodyParamName(raw[:idx], lastParamSeen, ""))
			} else {
				lastParamSeen = raw[idx : idx+idx1]
				entrypoints = append(entrypoints, newBodyParamName(raw[:idx], lastParamSeen, raw[idx+idx1:]))
				entrypoints = append(entrypoints, newBodyParamValue(raw[:idx+idx1+1], lastParamSeen, raw[idx+idx1+1:], ""))
			}

			idx += len(query)
			query = query[len(query):]

			continue
		}

		if idx1 > idx2 {
			lastParamSeen = raw[idx : idx+idx2]
			entrypoints = append(entrypoints, newBodyParamName(raw[:idx], lastParamSeen, raw[idx+idx2:]))
		} else if idx1 < idx2 {
			lastParamSeen = raw[idx : idx+idx1]
			entrypoints = append(entrypoints, newBodyParamName(raw[:idx], lastParamSeen, raw[idx+idx1:]))
			entrypoints = append(entrypoints, newBodyParamValue(raw[:idx+idx1+1], lastParamSeen, raw[idx+idx1+1:idx+idx2], raw[idx+idx2:]))
		}

		idx += len(query[:idx2+1])
		query = query[idx2+1:]
	}

	return entrypoints
}
