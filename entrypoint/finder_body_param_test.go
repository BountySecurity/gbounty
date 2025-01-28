package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

func TestBodyParamFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp [][]byte
	}{
		{
			req: request.Request{},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte("param")},
			exp: [][]byte{[]byte("/.git/HEAD")},
		},
		{
			req: request.Request{Body: []byte("param=value")},
			exp: [][]byte{
				[]byte("/.git/HEAD=value"),
				[]byte("param=/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2&param3=value3")},
			exp: [][]byte{
				[]byte("/.git/HEAD=value&param2&param3=value3"),
				[]byte("param=/.git/HEAD&param2&param3=value3"),
				[]byte("param=value&/.git/HEAD&param3=value3"),
				[]byte("param=value&param2&/.git/HEAD=value3"),
				[]byte("param=value&param2&param3=/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2=value2&param3")},
			exp: [][]byte{
				[]byte("/.git/HEAD=value&param2=value2&param3"),
				[]byte("param=/.git/HEAD&param2=value2&param3"),
				[]byte("param=value&/.git/HEAD=value2&param3"),
				[]byte("param=value&param2=/.git/HEAD&param3"),
				[]byte("param=value&param2=value2&/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("/.git/HEAD=value1&param=value2"),
				[]byte("param=/.git/HEAD&param=value2"),
				[]byte("param=value1&/.git/HEAD=value2"),
				[]byte("param=value1&param=/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("/.git/HEAD=value1&param=value2"),
				[]byte("param=/.git/HEAD&param=value2"),
				[]byte("param=value1&/.git/HEAD=value2"),
				[]byte("param=value1&param=/.git/HEAD"),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewBodyParamFinder()
			entrypoints := finder.Find(tc.req)
			builtBodies := make([][]byte, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Replace, payload)
				builtBodies = append(builtBodies, injReq.Body)
			}

			assert.ElementsMatch(t, tc.exp, builtBodies)
		})
	}
}

func TestBodyParamFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp [][]byte
	}{
		{
			req: request.Request{},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte("param")},
			exp: [][]byte{[]byte("param/.git/HEAD")},
		},
		{
			req: request.Request{Body: []byte("param=value")},
			exp: [][]byte{
				[]byte("param/.git/HEAD=value"),
				[]byte("param=value/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2&param3=value3")},
			exp: [][]byte{
				[]byte("param/.git/HEAD=value&param2&param3=value3"),
				[]byte("param=value/.git/HEAD&param2&param3=value3"),
				[]byte("param=value&param2/.git/HEAD&param3=value3"),
				[]byte("param=value&param2&param3/.git/HEAD=value3"),
				[]byte("param=value&param2&param3=value3/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2=value2&param3")},
			exp: [][]byte{
				[]byte("param/.git/HEAD=value&param2=value2&param3"),
				[]byte("param=value/.git/HEAD&param2=value2&param3"),
				[]byte("param=value&param2/.git/HEAD=value2&param3"),
				[]byte("param=value&param2=value2/.git/HEAD&param3"),
				[]byte("param=value&param2=value2&param3/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("param/.git/HEAD=value1&param=value2"),
				[]byte("param=value1/.git/HEAD&param=value2"),
				[]byte("param=value1&param/.git/HEAD=value2"),
				[]byte("param=value1&param=value2/.git/HEAD"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("param/.git/HEAD=value1&param=value2"),
				[]byte("param=value1/.git/HEAD&param=value2"),
				[]byte("param=value1&param/.git/HEAD=value2"),
				[]byte("param=value1&param=value2/.git/HEAD"),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewBodyParamFinder()
			entrypoints := finder.Find(tc.req)
			builtBodies := make([][]byte, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Append, payload)
				builtBodies = append(builtBodies, injReq.Body)
			}

			assert.ElementsMatch(t, tc.exp, builtBodies)
		})
	}
}

func TestBodyParamFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	tcs := []struct {
		req request.Request
		exp [][]byte
	}{
		{
			req: request.Request{},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte("param")},
			exp: [][]byte{[]byte("pa/.git/HEADram")},
		},
		{
			req: request.Request{Body: []byte("param=value")},
			exp: [][]byte{
				[]byte("pa/.git/HEADram=value"),
				[]byte("param=va/.git/HEADlue"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2&param3=value3")},
			exp: [][]byte{
				[]byte("pa/.git/HEADram=value&param2&param3=value3"),
				[]byte("param=va/.git/HEADlue&param2&param3=value3"),
				[]byte("param=value&par/.git/HEADam2&param3=value3"),
				[]byte("param=value&param2&par/.git/HEADam3=value3"),
				[]byte("param=value&param2&param3=val/.git/HEADue3"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value&param2=value2&param3")},
			exp: [][]byte{
				[]byte("pa/.git/HEADram=value&param2=value2&param3"),
				[]byte("param=va/.git/HEADlue&param2=value2&param3"),
				[]byte("param=value&par/.git/HEADam2=value2&param3"),
				[]byte("param=value&param2=val/.git/HEADue2&param3"),
				[]byte("param=value&param2=value2&par/.git/HEADam3"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("pa/.git/HEADram=value1&param=value2"),
				[]byte("param=val/.git/HEADue1&param=value2"),
				[]byte("param=value1&pa/.git/HEADram=value2"),
				[]byte("param=value1&param=val/.git/HEADue2"),
			},
		},
		{
			req: request.Request{Body: []byte("param=value1&param=value2")},
			exp: [][]byte{
				[]byte("pa/.git/HEADram=value1&param=value2"),
				[]byte("param=val/.git/HEADue1&param=value2"),
				[]byte("param=value1&pa/.git/HEADram=value2"),
				[]byte("param=value1&param=val/.git/HEADue2"),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewBodyParamFinder()
			entrypoints := finder.Find(tc.req)
			builtBodies := make([][]byte, 0, len(entrypoints))

			for _, e := range entrypoints {
				injReq := e.InjectPayload(tc.req, profile.Insert, payload)
				builtBodies = append(builtBodies, injReq.Body)
			}

			assert.ElementsMatch(t, tc.exp, builtBodies)
		})
	}
}
