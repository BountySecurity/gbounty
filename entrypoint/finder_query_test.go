package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func TestQueryFinder_Find_Replace(t *testing.T) {
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
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param"},
			exp: []string{"/dir1/dir2/file.php?/.git/HEAD"},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"/dir1/dir2/file.php?/.git/HEAD=value",
				"/dir1/dir2/file.php?param=/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2&param3=value3"},
			exp: []string{
				"/dir1/dir2/file.php?/.git/HEAD=value&param2&param3=value3",
				"/dir1/dir2/file.php?param=/.git/HEAD&param2&param3=value3",
				"/dir1/dir2/file.php?param=value&/.git/HEAD&param3=value3",
				"/dir1/dir2/file.php?param=value&param2&/.git/HEAD=value3",
				"/dir1/dir2/file.php?param=value&param2&param3=/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2&param3"},
			exp: []string{
				"/dir1/dir2/file.php?/.git/HEAD=value&param2=value2&param3",
				"/dir1/dir2/file.php?param=/.git/HEAD&param2=value2&param3",
				"/dir1/dir2/file.php?param=value&/.git/HEAD=value2&param3",
				"/dir1/dir2/file.php?param=value&param2=/.git/HEAD&param3",
				"/dir1/dir2/file.php?param=value&param2=value2&/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value1&param=value2"},
			exp: []string{
				"/dir1/dir2/file.php?/.git/HEAD=value1&param=value2",
				"/dir1/dir2/file.php?param=/.git/HEAD&param=value2",
				"/dir1/dir2/file.php?param=value1&/.git/HEAD=value2",
				"/dir1/dir2/file.php?param=value1&param=/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"?/.git/HEAD=value1&param=value2",
				"?param=/.git/HEAD&param=value2",
				"?param=value1&/.git/HEAD=value2",
				"?param=value1&param=/.git/HEAD",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewQueryFinder()
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

func TestQueryFinder_Find_Append(t *testing.T) {
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
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param"},
			exp: []string{"/dir1/dir2/file.php?param/.git/HEAD"},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"/dir1/dir2/file.php?param/.git/HEAD=value",
				"/dir1/dir2/file.php?param=value/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2&param3=value3"},
			exp: []string{
				"/dir1/dir2/file.php?param/.git/HEAD=value&param2&param3=value3",
				"/dir1/dir2/file.php?param=value/.git/HEAD&param2&param3=value3",
				"/dir1/dir2/file.php?param=value&param2/.git/HEAD&param3=value3",
				"/dir1/dir2/file.php?param=value&param2&param3/.git/HEAD=value3",
				"/dir1/dir2/file.php?param=value&param2&param3=value3/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2&param3"},
			exp: []string{
				"/dir1/dir2/file.php?param/.git/HEAD=value&param2=value2&param3",
				"/dir1/dir2/file.php?param=value/.git/HEAD&param2=value2&param3",
				"/dir1/dir2/file.php?param=value&param2/.git/HEAD=value2&param3",
				"/dir1/dir2/file.php?param=value&param2=value2/.git/HEAD&param3",
				"/dir1/dir2/file.php?param=value&param2=value2&param3/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value1&param=value2"},
			exp: []string{
				"/dir1/dir2/file.php?param/.git/HEAD=value1&param=value2",
				"/dir1/dir2/file.php?param=value1/.git/HEAD&param=value2",
				"/dir1/dir2/file.php?param=value1&param/.git/HEAD=value2",
				"/dir1/dir2/file.php?param=value1&param=value2/.git/HEAD",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"?param/.git/HEAD=value1&param=value2",
				"?param=value1/.git/HEAD&param=value2",
				"?param=value1&param/.git/HEAD=value2",
				"?param=value1&param=value2/.git/HEAD",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewQueryFinder()
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

func TestQueryFinder_Find_Insert(t *testing.T) {
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
			req: request.Request{Path: "/dir1/dir2/file.php"},
			exp: []string{},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param"},
			exp: []string{"/dir1/dir2/file.php?pa/.git/HEADram"},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value"},
			exp: []string{
				"/dir1/dir2/file.php?pa/.git/HEADram=value",
				"/dir1/dir2/file.php?param=va/.git/HEADlue",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2&param3=value3"},
			exp: []string{
				"/dir1/dir2/file.php?pa/.git/HEADram=value&param2&param3=value3",
				"/dir1/dir2/file.php?param=va/.git/HEADlue&param2&param3=value3",
				"/dir1/dir2/file.php?param=value&par/.git/HEADam2&param3=value3",
				"/dir1/dir2/file.php?param=value&param2&par/.git/HEADam3=value3",
				"/dir1/dir2/file.php?param=value&param2&param3=val/.git/HEADue3",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value&param2=value2&param3"},
			exp: []string{
				"/dir1/dir2/file.php?pa/.git/HEADram=value&param2=value2&param3",
				"/dir1/dir2/file.php?param=va/.git/HEADlue&param2=value2&param3",
				"/dir1/dir2/file.php?param=value&par/.git/HEADam2=value2&param3",
				"/dir1/dir2/file.php?param=value&param2=val/.git/HEADue2&param3",
				"/dir1/dir2/file.php?param=value&param2=value2&par/.git/HEADam3",
			},
		},
		{
			req: request.Request{Path: "/dir1/dir2/file.php?param=value1&param=value2"},
			exp: []string{
				"/dir1/dir2/file.php?pa/.git/HEADram=value1&param=value2",
				"/dir1/dir2/file.php?param=val/.git/HEADue1&param=value2",
				"/dir1/dir2/file.php?param=value1&pa/.git/HEADram=value2",
				"/dir1/dir2/file.php?param=value1&param=val/.git/HEADue2",
			},
		},
		{
			req: request.Request{Path: "?param=value1&param=value2"},
			exp: []string{
				"?pa/.git/HEADram=value1&param=value2",
				"?param=val/.git/HEADue1&param=value2",
				"?param=value1&pa/.git/HEADram=value2",
				"?param=value1&param=val/.git/HEADue2",
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(tc.req.Path, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewQueryFinder()
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
