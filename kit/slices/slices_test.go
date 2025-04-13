package slices_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/kit/slices"
)

func TestOccurrences(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in     []string
		lookup string
		out    int
	}{
		"nil slice":                     {in: nil, lookup: "any", out: 0},
		"empty slice":                   {in: []string{}, lookup: "any", out: 0},
		"single non-matching elem":      {in: []string{"other"}, lookup: "elem", out: 0},
		"single matching elem":          {in: []string{"elem"}, lookup: "elem", out: 1},
		"multiple matching element":     {in: []string{"one", "other", "elem", "another", "elem"}, lookup: "elem", out: 2},
		"multiple non-matching element": {in: []string{"one", "other", "another"}, lookup: "elem", out: 0},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, slices.Occurrences(tc.in, tc.lookup))
		})
	}
}

func TestIn(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in     []string
		lookup string
		out    bool
	}{
		"nil slice":                     {in: nil, lookup: "any", out: false},
		"empty slice":                   {in: []string{}, lookup: "any", out: false},
		"single non-matching elem":      {in: []string{"other"}, lookup: "elem", out: false},
		"single matching elem":          {in: []string{"elem"}, lookup: "elem", out: true},
		"multiple matching element":     {in: []string{"one", "other", "elem"}, lookup: "elem", out: true},
		"multiple non-matching element": {in: []string{"one", "other", "another"}, lookup: "elem", out: false},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, slices.In(tc.in, tc.lookup))
		})
	}
}

func TestNoneIn(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in     []string
		lookup []string
		out    bool
	}{
		"nil slice":                {in: nil, lookup: nil, out: true},
		"empty slice":              {in: []string{}, lookup: nil, out: true},
		"single matching elem":     {in: []string{"elem"}, lookup: []string{"elem"}, out: false},
		"single non-matching elem": {in: []string{"other"}, lookup: []string{"elem"}, out: true},
		"multiple, none matching":  {in: []string{"one", "two", "three"}, lookup: []string{"elem", "elem2"}, out: true},
		"multiple, some matching":  {in: []string{"one", "other", "elem"}, lookup: []string{"elem", "elem2"}, out: false},
		"multiple, all matching":   {in: []string{"one", "other", "elem"}, lookup: []string{"one", "other", "elem"}, out: false},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, slices.NoneIn(tc.in, tc.lookup))
		})
	}
}

func TestValForKey(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		inSlice []string
		inKey   string
		expKey  string
		expOk   bool
	}{
		"nil slice":             {inSlice: nil, inKey: "any", expKey: "", expOk: false},
		"empty slice":           {inSlice: []string{}, inKey: "any", expKey: "", expOk: false},
		"single elem":           {inSlice: []string{"lookup"}, inKey: "lookup", expKey: "", expOk: false},
		"single lookup-value":   {inSlice: []string{"lookup", "value"}, inKey: "lookup", expKey: "value", expOk: true},
		"missing value":         {inSlice: []string{"lookup", "value", "key2"}, inKey: "key2", expKey: "", expOk: false},
		"multiple lookup-value": {inSlice: []string{"lookup", "value", "key2", "value2"}, inKey: "key2", expKey: "value2", expOk: true},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			gotVal, gotOk := slices.ValForKey(tc.inSlice, tc.inKey)
			assert.Equal(t, tc.expKey, gotVal)
			assert.Equal(t, tc.expOk, gotOk)
		})
	}
}
