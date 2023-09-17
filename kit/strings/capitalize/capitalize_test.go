package capitalize_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/kit/strings/capitalize"
)

func Test_First(t *testing.T) {
	t.Parallel()
	tcs := map[string]struct {
		in, out string
	}{
		"empty string":        {in: "", out: ""},
		"single lower char":   {in: "c", out: "C"},
		"single upper char":   {in: "C", out: "C"},
		"multiple lower char": {in: "ccc", out: "Ccc"},
		"multiple upper char": {in: "CCC", out: "CCC"},
		"already capitalized": {in: "Ccc", out: "Ccc"},
		"starting number":     {in: "1cc", out: "1cc"},
		"starting symbol":     {in: "-cc", out: "-cc"},
	}
	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.out, capitalize.First(tc.in))
		})
	}
}

func Test_All(t *testing.T) {
	t.Parallel()
	tcs := map[string]struct {
		in, out string
	}{
		"empty string":        {in: "", out: ""},
		"single lower char":   {in: "c", out: "C"},
		"single upper char":   {in: "C", out: "C"},
		"multiple lower char": {in: "ccc", out: "CCC"},
		"multiple upper char": {in: "CCC", out: "CCC"},
		"already capitalized": {in: "Ccc", out: "CCC"},
		"starting number":     {in: "1cc", out: "1CC"},
		"starting symbol":     {in: "-cc", out: "-CC"},
	}
	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.out, capitalize.All(tc.in))
		})
	}
}
