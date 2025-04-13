package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestURLFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "file.php"},
			exp: []string{
				"/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/file.php"},
			exp: []string{
				"//.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"//.git/HEAD/dir2",
				"/dir1//.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"//.git/HEAD/dir2/file.php",
				"/dir1//.git/HEAD/file.php",
				"/dir1/dir2//.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"//.git/HEAD/dir2/file.php?param=value",
				"/dir1//.git/HEAD/file.php?param=value",
				"/dir1/dir2//.git/HEAD?param=value",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"/.git/HEAD?param=value1&param=value2",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewURLFinder()
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

func TestURLFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "file.php"},
			exp: []string{
				"file.php/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/file.php"},
			exp: []string{
				"/file.php/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"/dir1/.git/HEAD/dir2",
				"/dir1/dir2/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"/dir1/.git/HEAD/dir2/file.php",
				"/dir1/dir2/.git/HEAD/file.php",
				"/dir1/dir2/file.php/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"/dir1/.git/HEAD/dir2/file.php?param=value",
				"/dir1/dir2/.git/HEAD/file.php?param=value",
				"/dir1/dir2/file.php/.git/HEAD?param=value",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"/.git/HEAD?param=value1&param=value2",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewURLFinder()
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

func TestURLFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp []string
	}{
		{
			req: request.Request{Path: "file.php"},
			exp: []string{
				"file/.git/HEAD.php",
			},
		},
		{
			req: request.Request{Path: "/file.php"},
			exp: []string{
				"/file/.git/HEAD.php",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2"},
			exp: []string{
				"/di/.git/HEADr1/dir2",
				"/dir1/di/.git/HEADr2",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{
				"/di/.git/HEADr1/dir2/file.php",
				"/dir1/di/.git/HEADr2/file.php",
				"/dir1/dir2/file/.git/HEAD.php",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"/di/.git/HEADr1/dir2/file.php?param=value",
				"/dir1/di/.git/HEADr2/file.php?param=value",
				"/dir1/dir2/file/.git/HEAD.php?param=value",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"/.git/HEAD?param=value1&param=value2",
			},
		},
	}

	for _, tc := range tcs {
		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewURLFinder()
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
