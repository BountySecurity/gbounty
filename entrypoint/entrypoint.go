package entrypoint

import (
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

// Entrypoint defines the behavior of a request's entrypoint,
// which is a point in the request where a payload can be injected.
// For instance, a URL entrypoint would be the path of the request.
//
// Specific implementations of this interface are responsible
// for injecting payloads into the request.
type Entrypoint interface {
	Param(param string) string
	Value() string
	InsertionPointType() profile.InsertionPointType
	InjectPayload(req request.Request, pos profile.PayloadPosition, payload string) request.Request
}

// Finder defines the behavior of an entrypoints finder,
// which is a component capable of finding entrypoints in a request.
type Finder interface {
	Find(req request.Request) []Entrypoint
}

// Finders returns a list of all available entrypoints finders
// within the `entrypoint` package.
func Finders() []Finder {
	return []Finder{
		NewBodyParamFinder(),
		NewCookieFinder(),
		NewEntireBodyFinder(),
		NewHeaderFinder(),
		NewJSONParamFinder(),
		NewMultipartFinder(),
		NewPathFinder(),
		NewQueryFinder(),
		NewURLFinder(),
		NewXMLParamFinder(),
	}
}

// From compiles a list of entrypoints from a [profile.Step].
// It is used (only) to generate a list of [profile.HeaderNew]
// entrypoints, so to add new headers to the request.
func From(s profile.Step) []Entrypoint {
	entrypoints := make([]Entrypoint, 0)
	if insertionPointEnabled(s, profile.HeaderNew) {
		for _, ch := range s.CustomHeaders {
			entrypoints = append(entrypoints, newCustomHeader(ch))
		}
	}
	return entrypoints
}

func insertionPointEnabled(s profile.Step, ipt profile.InsertionPointType) bool {
	for _, enabledIPT := range s.InsertionPoints {
		if enabledIPT == ipt {
			return true
		}
	}
	return false
}

type baseEntrypoint struct {
	P string
	V string

	IPT profile.InsertionPointType
}

func (b baseEntrypoint) Param(_ string) string {
	return b.P
}

func (b baseEntrypoint) Value() string {
	return b.V
}

func (b baseEntrypoint) InsertionPointType() profile.InsertionPointType {
	return b.IPT
}

const half = 2
