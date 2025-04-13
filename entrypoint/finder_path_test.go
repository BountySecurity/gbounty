package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestPathFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := map[string]struct {
		req request.Request
		exp []string
	}{
		"/dir1/dir2": {
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"/.git/HEAD",
				"/.git/HEAD",
				"/dir1/.git/HEAD",
			},
		},
		"/dir1/dir2/file.php": {
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"/.git/HEAD",
				"/.git/HEAD",
				"/dir1/.git/HEAD",
				"/dir1/dir2/.git/HEAD",
			},
		},
		"/dir1/dir2/file.php?param=value&param2=value2": {
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2"},
			exp: []string{
				"/.git/HEAD",
				"/.git/HEAD",
				"/dir1/.git/HEAD",
				"/dir1/dir2/.git/HEAD",
			},
		},
		"?param=value&param2=value2": {
			req: request.Request{Path: "?param=value&param2=value2"},
			exp: []string{},
		},
		"/this/is/a/path/search.php?test=query": {
			req: request.Request{Path: "/this/is/a/path/search.php?test=query"},
			exp: []string{
				"/.git/HEAD",
				"/.git/HEAD",
				"/this/.git/HEAD",
				"/this/is/.git/HEAD",
				"/this/is/a/.git/HEAD",
				"/this/is/a/path/.git/HEAD",
			},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewPathFinder()
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

func TestPathFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"/dir1/.git/HEAD",
				"/dir1/.git/HEAD",
				"/dir1/dir2/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"/dir1/.git/HEAD",
				"/dir1/.git/HEAD",
				"/dir1/dir2/.git/HEAD",
				"/dir1/dir2/file.php/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2"},
			exp: []string{
				"/dir1/.git/HEAD",
				"/dir1/.git/HEAD",
				"/dir1/dir2/.git/HEAD",
				"/dir1/dir2/file.php/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "?param=value&param2=value2"},
			exp: []string{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewPathFinder()
			entrypoints := finder.Find(tc.req)
			reachedPaths := make([]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Append, payload)
				reachedPaths = append(reachedPaths, injReq.Path)
			}

			assert.ElementsMatch(t, tc.exp, reachedPaths)
		})
	}
}

func TestPathFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"/di/.git/HEADr1",
				"/di/.git/HEADr1",
				"/dir1/di/.git/HEADr2",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"/di/.git/HEADr1",
				"/di/.git/HEADr1",
				"/dir1/di/.git/HEADr2",
				"/dir1/dir2/file/.git/HEAD.php",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2"},
			exp: []string{
				"/di/.git/HEADr1",
				"/di/.git/HEADr1",
				"/dir1/di/.git/HEADr2",
				"/dir1/dir2/file/.git/HEAD.php",
			},
		},
		{
			req: request.Request{Path: "?param=value&param2=value2"},
			exp: []string{},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewPathFinder()
			entrypoints := finder.Find(tc.req)
			reachedPaths := make([]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Insert, payload)
				reachedPaths = append(reachedPaths, injReq.Path)
			}

			assert.ElementsMatch(t, tc.exp, reachedPaths)
		})
	}
}
