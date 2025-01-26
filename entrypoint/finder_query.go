package entrypoint

import (
	"strings"

	"github.com/bountysecurity/gbounty/request"
)

// QueryFinder must implement the Finder interface.
var _ Finder = QueryFinder{}

// QueryFinder is used to find entrypoints in the request's query.
type QueryFinder struct{}

// NewQueryFinder instantiates a new QueryFinder.
func NewQueryFinder() QueryFinder {
	return QueryFinder{}
}

func (f QueryFinder) Find(req request.Request) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)
	base, raw := f.splitQuery(req.Path)

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
				entrypoints = append(entrypoints, newQueryKey(base+raw[:idx], lastParamSeen, ""))
			} else {
				lastParamSeen = raw[idx : idx+idx1]
				entrypoints = append(entrypoints, newQueryKey(base+raw[:idx], lastParamSeen, raw[idx+idx1:]))
				entrypoints = append(entrypoints, newQueryValue(base+raw[:idx+idx1+1], lastParamSeen, raw[idx+idx1+1:], ""))
			}

			idx += len(query)
			query = query[len(query):]

			continue
		}

		if idx1 > idx2 {
			lastParamSeen = raw[idx : idx+idx2]
			entrypoints = append(entrypoints, newQueryKey(base+raw[:idx], lastParamSeen, raw[idx+idx2:]))
		} else if idx1 < idx2 {
			lastParamSeen = raw[idx : idx+idx1]
			entrypoints = append(entrypoints, newQueryKey(base+raw[:idx], lastParamSeen, raw[idx+idx1:]))
			entrypoints = append(entrypoints, newQueryValue(base+raw[:idx+idx1+1], lastParamSeen, raw[idx+idx1+1:idx+idx2], raw[idx+idx2:]))
		}

		idx += len(query[:idx2+1])
		query = query[idx2+1:]
	}

	return entrypoints
}

func (QueryFinder) splitQuery(path string) (string, string) {
	idx := strings.Index(path, "?")

	switch idx {
	case -1:
		return "", ""
	case 0:
		return "?", path[1:]
	default:
		return path[:idx+1], path[idx+1:]
	}
}
