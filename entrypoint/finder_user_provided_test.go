package entrypoint_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestUserProvided_Find_Replace_path(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{},
		},
		{
			req: request.Request{Path: "/$GBOUNTY$/dir2"},
			exp: []string{"//.git/HEAD/dir2"},
		},
		{
			req: request.Request{Path: "/$GBOUNTY$/$GBOUNTY$"},
			exp: []string{
				"//.git/HEAD/$GBOUNTY$",
				"/$GBOUNTY$//.git/HEAD",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewUserProvidedFinder()
			entrypoints := finder.Find(tc.req)
			reachedPaths := make([]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Replace, payload)
				reachedPaths = append(reachedPaths, injReq.Path)
			}

			assert.ElementsMatch(t, tc.exp, reachedPaths)
		})
	}
}

func TestUserProvided_Find_Replace_headers(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []map[string][]string
	}{
		{
			req: request.Request{Headers: map[string][]string{
				"X-Header": {"/dir1/dir2"},
			}},
			exp: []map[string][]string{},
		},
		{
			req: request.Request{Headers: map[string][]string{
				"X-Header": {"/$GBOUNTY$/dir2"},
			}},
			exp: []map[string][]string{
				{
					"X-Header": {"//.git/HEAD/dir2"},
				},
			},
		},
		{
			req: request.Request{Headers: map[string][]string{
				"X-Header": {"/$GBOUNTY$/$GBOUNTY$"},
			}},
			exp: []map[string][]string{
				{
					"X-Header": {"//.git/HEAD/$GBOUNTY$"},
				},
				{
					"X-Header": {"/$GBOUNTY$//.git/HEAD"},
				},
			},
		},
		{
			req: request.Request{Headers: map[string][]string{
				"X-Header": {"/$GBOUNTY$/dir2"},
				"Y-Header": {"/dir1/$GBOUNTY$"},
			}},
			exp: []map[string][]string{
				{
					"X-Header": {"//.git/HEAD/dir2"},
					"Y-Header": {"/dir1/$GBOUNTY$"},
				},
				{
					"X-Header": {"/$GBOUNTY$/dir2"},
					"Y-Header": {"/dir1//.git/HEAD"},
				},
			},
		},
		{
			req: request.Request{Headers: map[string][]string{
				"X-Header": {"/$GBOUNTY$/dir2", "/dir1/$GBOUNTY$"},
			}},
			exp: []map[string][]string{
				{
					"X-Header": {"//.git/HEAD/dir2", "/dir1/$GBOUNTY$"},
				},
				{
					"X-Header": {"/$GBOUNTY$/dir2", "/dir1//.git/HEAD"},
				},
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(fmt.Sprintf("%v", tc.req.Headers), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewUserProvidedFinder()
			entrypoints := finder.Find(tc.req)
			reachedHeaders := make([]map[string][]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Replace, payload)
				reachedHeaders = append(reachedHeaders, injReq.Headers)
			}

			assert.ElementsMatch(t, tc.exp, reachedHeaders)
		})
	}
}

func TestUserProvided_Find_Replace_body(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Body: []byte("/dir1/dir2")},
			exp: []string{},
		},
		{
			req: request.Request{Body: []byte("/$GBOUNTY$/dir2")},
			exp: []string{"//.git/HEAD/dir2"},
		},
		{
			req: request.Request{Body: []byte("/$GBOUNTY$/$GBOUNTY$")},
			exp: []string{
				"//.git/HEAD/$GBOUNTY$",
				"/$GBOUNTY$//.git/HEAD",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewUserProvidedFinder()
			entrypoints := finder.Find(tc.req)
			reachedBodies := make([]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Replace, payload)
				reachedBodies = append(reachedBodies, string(injReq.Body))
			}

			assert.ElementsMatch(t, tc.exp, reachedBodies)
		})
	}
}
