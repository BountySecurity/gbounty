package entrypoint //nolint:testpackage

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func TestCustomHeader_InjectPayload(t *testing.T) {
	t.Parallel()

	tcs := map[string]struct {
		header  string
		payload string
		req     request.Request
		exp     request.Request
	}{
		"non-existing header": {
			header:  "Origin",
			payload: "localhost:8080",
			req: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			},
			exp: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
					"Origin":       {"localhost:8080"},
				},
			},
		},
		"existing header": {
			header:  "Content-Type",
			payload: "application/xml",
			req: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/json"},
				},
			},
			exp: request.Request{
				Headers: map[string][]string{
					"Content-Type": {
						"application/json",
						"application/xml",
					},
				},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			e := newCustomHeader(tc.header)
			injReq := e.InjectPayload(tc.req, profile.Replace, tc.payload)
			assert.Equal(t, tc.exp, injReq)
		})
	}
}
