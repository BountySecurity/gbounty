package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func TestJSONParamFinder_Find_Replace(t *testing.T) {
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
			req: request.Request{Body: []byte("{}")},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value"}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":"value"}`),
				[]byte(`{"param":"/.git/HEAD"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param1":"value1", "param2":2, "param3":3.14, "param4":false, "param5":null}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":"value1","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"/.git/HEAD","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","/.git/HEAD":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":/.git/HEAD,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"/.git/HEAD":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":/.git/HEAD,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"/.git/HEAD":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":/.git/HEAD,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"/.git/HEAD":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"param5":/.git/HEAD}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value","param2":"value2"}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":"value","param2":"value2"}`),
				[]byte(`{"param":"/.git/HEAD","param2":"value2"}`),
				[]byte(`{"param":"value","/.git/HEAD":"value2"}`),
				[]byte(`{"param":"value","param2":"/.git/HEAD"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":"value2"}}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":{"param2":"value2"}}`),
				[]byte(`{"param":{"/.git/HEAD":"value2"}}`),
				[]byte(`{"param":{"param2":"/.git/HEAD"}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":{"param3":"value3"}}}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":{"param2":{"param3":"value3"}}}`),
				[]byte(`{"param":{"/.git/HEAD":{"param3":"value3"}}}`),
				[]byte(`{"param":{"param2":{"/.git/HEAD":"value3"}}}`),
				[]byte(`{"param":{"param2":{"param3":"/.git/HEAD"}}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":["value1","value2",3]}}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":{"param2":["value1","value2",3]}}`),
				[]byte(`{"param":{"/.git/HEAD":["value1","value2",3]}}`),
				[]byte(`{"param":{"param2":["/.git/HEAD","value2",3]}}`),
				[]byte(`{"param":{"param2":["value1","/.git/HEAD",3]}}`),
				[]byte(`{"param":{"param2":["value1","value2",/.git/HEAD]}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":3}}`)},
			exp: [][]byte{
				[]byte(`{"/.git/HEAD":{"param2":3}}`),
				[]byte(`{"param":{"/.git/HEAD":3}}`),
				[]byte(`{"param":{"param2":/.git/HEAD}}`),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewJSONParamFinder()
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

func TestJSONParamFinder_Find_Append(t *testing.T) {
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
			req: request.Request{Body: []byte("{}")},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value"}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":"value"}`),
				[]byte(`{"param":"value/.git/HEAD"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param1":"value1", "param2":2, "param3":3.14, "param4":false, "param5":null}`)},
			exp: [][]byte{
				[]byte(`{"param1/.git/HEAD":"value1","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1/.git/HEAD","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2/.git/HEAD":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2/.git/HEAD,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3/.git/HEAD":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14/.git/HEAD,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4/.git/HEAD":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false/.git/HEAD,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"param5/.git/HEAD":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"param5":null/.git/HEAD}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value","param2":"value2"}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":"value","param2":"value2"}`),
				[]byte(`{"param":"value/.git/HEAD","param2":"value2"}`),
				[]byte(`{"param":"value","param2/.git/HEAD":"value2"}`),
				[]byte(`{"param":"value","param2":"value2/.git/HEAD"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":"value2"}}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":{"param2":"value2"}}`),
				[]byte(`{"param":{"param2/.git/HEAD":"value2"}}`),
				[]byte(`{"param":{"param2":"value2/.git/HEAD"}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":{"param3":"value3"}}}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":{"param2":{"param3":"value3"}}}`),
				[]byte(`{"param":{"param2/.git/HEAD":{"param3":"value3"}}}`),
				[]byte(`{"param":{"param2":{"param3/.git/HEAD":"value3"}}}`),
				[]byte(`{"param":{"param2":{"param3":"value3/.git/HEAD"}}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":["value1","value2",3]}}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":{"param2":["value1","value2",3]}}`),
				[]byte(`{"param":{"param2/.git/HEAD":["value1","value2",3]}}`),
				[]byte(`{"param":{"param2":["value1/.git/HEAD","value2",3]}}`),
				[]byte(`{"param":{"param2":["value1","value2/.git/HEAD",3]}}`),
				[]byte(`{"param":{"param2":["value1","value2",3/.git/HEAD]}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":3}}`)},
			exp: [][]byte{
				[]byte(`{"param/.git/HEAD":{"param2":3}}`),
				[]byte(`{"param":{"param2/.git/HEAD":3}}`),
				[]byte(`{"param":{"param2":3/.git/HEAD}}`),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewJSONParamFinder()
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

func TestJSONParamFinder_Find_Insert(t *testing.T) {
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
			req: request.Request{Body: []byte("{}")},
			exp: [][]byte{},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value"}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":"value"}`),
				[]byte(`{"param":"va/.git/HEADlue"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param1":"value1", "param2":2, "param3":3.14, "param4":false, "param5":null}`)},
			exp: [][]byte{
				[]byte(`{"par/.git/HEADam1":"value1","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"val/.git/HEADue1","param2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","par/.git/HEADam2":2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":/.git/HEAD2,"param3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"par/.git/HEADam3":3.14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3./.git/HEAD14,"param4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"par/.git/HEADam4":false,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":fa/.git/HEADlse,"param5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"par/.git/HEADam5":null}`),
				[]byte(`{"param1":"value1","param2":2,"param3":3.14,"param4":false,"param5":nu/.git/HEADll}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":"value","param2":"value2"}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":"value","param2":"value2"}`),
				[]byte(`{"param":"va/.git/HEADlue","param2":"value2"}`),
				[]byte(`{"param":"value","par/.git/HEADam2":"value2"}`),
				[]byte(`{"param":"value","param2":"val/.git/HEADue2"}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":"value2"}}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":{"param2":"value2"}}`),
				[]byte(`{"param":{"par/.git/HEADam2":"value2"}}`),
				[]byte(`{"param":{"param2":"val/.git/HEADue2"}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":{"param3":"value3"}}}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":{"param2":{"param3":"value3"}}}`),
				[]byte(`{"param":{"par/.git/HEADam2":{"param3":"value3"}}}`),
				[]byte(`{"param":{"param2":{"par/.git/HEADam3":"value3"}}}`),
				[]byte(`{"param":{"param2":{"param3":"val/.git/HEADue3"}}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":["value1","value2",3]}}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":{"param2":["value1","value2",3]}}`),
				[]byte(`{"param":{"par/.git/HEADam2":["value1","value2",3]}}`),
				[]byte(`{"param":{"param2":["val/.git/HEADue1","value2",3]}}`),
				[]byte(`{"param":{"param2":["value1","val/.git/HEADue2",3]}}`),
				[]byte(`{"param":{"param2":["value1","value2",/.git/HEAD3]}}`),
			},
		},
		{
			req: request.Request{Body: []byte(`{"param":{"param2":3}}`)},
			exp: [][]byte{
				[]byte(`{"pa/.git/HEADram":{"param2":3}}`),
				[]byte(`{"param":{"par/.git/HEADam2":3}}`),
				[]byte(`{"param":{"param2":/.git/HEAD3}}`),
			},
		},
	}

	for _, tc := range tcs {
		tc := tc

		t.Run(string(tc.req.Body), func(t *testing.T) {
			t.Parallel()

			finder := entrypoint.NewJSONParamFinder()
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
