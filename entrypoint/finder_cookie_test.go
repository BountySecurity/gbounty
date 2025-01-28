package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func TestCookieFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := map[string]struct {
		req request.Request
		exp [][]string
	}{
		"no headers": {
			req: request.Request{},
			exp: nil,
		},
		"no cookie header": {
			req: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
			},
			exp: nil,
		},
		"single cookie": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1"},
				},
			},
			exp: [][]string{
				{"/.git/HEAD=value1"},
				{"cookie1=/.git/HEAD"},
			},
		},
		"multiple cookies": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1; cookie2=value2; cookie3=value3"},
				},
			},
			exp: [][]string{
				{"/.git/HEAD=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=/.git/HEAD; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; /.git/HEAD=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=/.git/HEAD; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; /.git/HEAD=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=/.git/HEAD"},
			},
		},
		"multiple lines": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {
						"cookie1=value1",
						"cookie2=value2; cookie3=value3",
					},
				},
			},
			exp: [][]string{
				{"/.git/HEAD=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=/.git/HEAD; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; /.git/HEAD=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=/.git/HEAD; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; /.git/HEAD=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=/.git/HEAD"},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewCookieFinder()
			entrypoints := finder.Find(tc.req)

			builtCookies := make([][]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Replace, payload)
				builtCookies = append(builtCookies, injReq.Headers["Cookie"])
			}

			assert.ElementsMatch(t, tc.exp, builtCookies)
		})
	}
}

func TestCookieFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := map[string]struct {
		req request.Request
		exp [][]string
	}{
		"no headers": {
			req: request.Request{},
			exp: nil,
		},
		"no cookie header": {
			req: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
			},
			exp: nil,
		},
		"single cookie": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1"},
				},
			},
			exp: [][]string{
				{"cookie1/.git/HEAD=value1"},
				{"cookie1=value1/.git/HEAD"},
			},
		},
		"multiple cookies": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1; cookie2=value2; cookie3=value3"},
				},
			},
			exp: [][]string{
				{"cookie1/.git/HEAD=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=value1/.git/HEAD; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; cookie2/.git/HEAD=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=value2/.git/HEAD; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; cookie3/.git/HEAD=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=value3/.git/HEAD"},
			},
		},
		"multiple lines": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {
						"cookie1=value1",
						"cookie2=value2; cookie3=value3",
					},
				},
			},
			exp: [][]string{
				{"cookie1/.git/HEAD=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=value1/.git/HEAD; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; cookie2/.git/HEAD=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=value2/.git/HEAD; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; cookie3/.git/HEAD=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=value3/.git/HEAD"},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewCookieFinder()
			entrypoints := finder.Find(tc.req)

			builtCookies := make([][]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Append, payload)
				builtCookies = append(builtCookies, injReq.Headers["Cookie"])
			}

			assert.ElementsMatch(t, tc.exp, builtCookies)
		})
	}
}

func TestCookieFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := map[string]struct {
		req request.Request
		exp [][]string
	}{
		"no headers": {
			req: request.Request{},
			exp: nil,
		},
		"no cookie header": {
			req: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
			},
			exp: nil,
		},
		"single cookie": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1"},
				},
			},
			exp: [][]string{
				{"coo/.git/HEADkie1=value1"},
				{"cookie1=val/.git/HEADue1"},
			},
		},
		"multiple cookies": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {"cookie1=value1; cookie2=value2; cookie3=value3"},
				},
			},
			exp: [][]string{
				{"coo/.git/HEADkie1=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=val/.git/HEADue1; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; coo/.git/HEADkie2=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=val/.git/HEADue2; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; coo/.git/HEADkie3=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=val/.git/HEADue3"},
			},
		},
		"multiple lines": {
			req: request.Request{
				Headers: map[string][]string{
					"Cookie": {
						"cookie1=value1",
						"cookie2=value2; cookie3=value3",
					},
				},
			},
			exp: [][]string{
				{"coo/.git/HEADkie1=value1; cookie2=value2; cookie3=value3"},
				{"cookie1=val/.git/HEADue1; cookie2=value2; cookie3=value3"},
				{"cookie1=value1; coo/.git/HEADkie2=value2; cookie3=value3"},
				{"cookie1=value1; cookie2=val/.git/HEADue2; cookie3=value3"},
				{"cookie1=value1; cookie2=value2; coo/.git/HEADkie3=value3"},
				{"cookie1=value1; cookie2=value2; cookie3=val/.git/HEADue3"},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewCookieFinder()
			entrypoints := finder.Find(tc.req)

			builtCookies := make([][]string, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Insert, payload)
				builtCookies = append(builtCookies, injReq.Headers["Cookie"])
			}

			assert.ElementsMatch(t, tc.exp, builtCookies)
		})
	}
}
