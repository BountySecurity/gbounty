package occurrence_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/strings/occurrence"
)

func TestFind(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		s   string
		sub string
		exp []occurrence.Occurrence
	}{
		"empty":                {s: "", sub: "", exp: []occurrence.Occurrence{}},
		"empty string":         {s: "", sub: "test", exp: []occurrence.Occurrence{}},
		"empty substring":      {s: "This is a test string.", sub: "", exp: []occurrence.Occurrence{}},
		"single occurrence":    {s: "This is a test string.", sub: "test", exp: []occurrence.Occurrence{{10, 14}}},
		"multiple occurrences": {s: "This is a test string. Let's test string matching.", sub: "test", exp: []occurrence.Occurrence{{10, 14}, {29, 33}}},
		"not matching":         {s: "This is a test string. Let's test string matching.", sub: "desd", exp: []occurrence.Occurrence{}},
	}

	for name, tc := range tcs {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.exp, occurrence.Find(tc.s, tc.sub))
		})
	}
}

func TestFindRegexp(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		s   string
		sub string // Now this represents a regexp pattern
		exp []occurrence.Occurrence
	}{
		"empty":                {s: "", sub: "", exp: []occurrence.Occurrence{}},
		"empty string":         {s: "", sub: "t\\w{2}t", exp: []occurrence.Occurrence{}},
		"empty substring":      {s: "This is a test string.", sub: "", exp: []occurrence.Occurrence{}},
		"single occurrence":    {s: "This is a test string.", sub: "t\\w{2}t", exp: []occurrence.Occurrence{{10, 14}}},
		"multiple occurrences": {s: "This is a test string. Let's test string matching.", sub: "t\\w{2}t", exp: []occurrence.Occurrence{{10, 14}, {29, 33}}},
		"not matching":         {s: "This is a test string. Let's test string matching.", sub: "d\\w{2}d", exp: []occurrence.Occurrence{}},
	}

	for name, tc := range tcs {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.exp, occurrence.FindRegexp(tc.s, tc.sub))
		})
	}
}
