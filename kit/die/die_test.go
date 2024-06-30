package die //nolint:testpackage

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_dieFmt(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		in  []string
		out string
	}{
		"nil":      {in: []string{}, out: "test err"},
		"empty":    {in: []string{}, out: "test err"},
		"single":   {in: []string{"failure"}, out: "failure: test err"},
		"double":   {in: []string{"panic", "failure"}, out: "panic: failure: test err"},
		"multiple": {in: []string{"Unexpected", "panic", "failure"}, out: "Unexpected: panic: failure: test err"},
	}

	for name, tc := range tcs {
		tc := tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := errors.New("test err") //nolint:goerr113
			assert.Equal(t, tc.out, dieFmt(err, tc.in...))
		})
	}
}
