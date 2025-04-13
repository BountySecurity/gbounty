package entrypoint_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/entrypoint"
	"github.com/BountySecurity/gbounty/profile"
	"github.com/BountySecurity/gbounty/request"
)

func TestEntireBodyFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	finder := entrypoint.NewEntireBodyFinder()

	t.Run("with no body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{Headers: headers()}
		entrypoints := finder.Find(req)
		assert.Empty(t, entrypoints)
	})

	t.Run("with simple body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`searchFor=test&goButton=go`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 1)

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Replace, payload)
			assert.Equal(t, []byte(payload), injected.Body)
			assert.NotEqual(t, req.Body, injected.Body)
		}
	})

	t.Run("with json body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`{"key":"value"}`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyJSON, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Replace, payload)
			assert.Equal(t, injected.Body, []byte(payload))
			assert.NotEqual(t, req.Body, injected.Body)
		}
	})

	t.Run("with xml body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`<key>value</key>`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyXML, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Replace, payload)
			assert.Equal(t, injected.Body, []byte(payload))
			assert.NotEqual(t, req.Body, injected.Body)
		}
	})

	t.Run("with multipart body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body: []byte(`--------------------------d74496d66958873e
Content-Disposition: form-data; name="person"

anonymous
--------------------------d74496d66958873e
Content-Disposition: form-data; name="secret"; filename="file.txt"
Content-Type: text/plain

contents of the file
--------------------------d74496d66958873e--`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyMulti, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Replace, payload)
			assert.Equal(t, injected.Body, []byte(payload))
			assert.NotEqual(t, req.Body, injected.Body)
		}
	})
}

func TestEntireBodyFinder_Find_Append(t *testing.T) {
	t.Parallel()

	finder := entrypoint.NewEntireBodyFinder()

	t.Run("with no body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{Headers: headers()}
		entrypoints := finder.Find(req)
		assert.Empty(t, entrypoints)
	})

	t.Run("with simple body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`searchFor=test&goButton=go`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 1)

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Append, payload)
			assert.Equal(t, string(injected.Body), string(req.Body)+payload)
		}
	})

	t.Run("with json body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`{"key":"value"}`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyJSON, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Append, payload)
			assert.Equal(t, string(injected.Body), string(req.Body)+payload)
		}
	})

	t.Run("with xml body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`<key>value</key>`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyXML, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Append, payload)
			assert.Equal(t, string(injected.Body), string(req.Body)+payload)
		}
	})

	t.Run("with multipart body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body: []byte(`--------------------------d74496d66958873e
Content-Disposition: form-data; name="person"

anonymous
--------------------------d74496d66958873e
Content-Disposition: form-data; name="secret"; filename="file.txt"
Content-Type: text/plain

contents of the file
--------------------------d74496d66958873e--`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyMulti, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Append, payload)
			assert.Equal(t, string(injected.Body), string(req.Body)+payload)
		}
	})
}

func TestEntireBodyFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	finder := entrypoint.NewEntireBodyFinder()

	t.Run("with no body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{Headers: headers()}
		entrypoints := finder.Find(req)
		assert.Empty(t, entrypoints)
	})

	t.Run("with simple body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`searchFor=test&goButton=go`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 1)

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Insert, payload)
			assert.Contains(t, string(injected.Body), payload)

			expectedBodyLength := len(req.Body) + len([]byte(payload))
			assert.Len(t, injected.Body, expectedBodyLength)
		}
	})

	t.Run("with json body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`{"key":"value"}`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyJSON, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Insert, payload)
			assert.Contains(t, string(injected.Body), payload)

			expectedBodyLength := len(req.Body) + len([]byte(payload))
			assert.Len(t, injected.Body, expectedBodyLength)
		}
	})

	t.Run("with xml body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body:    []byte(`<key>value</key>`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyXML, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Insert, payload)
			assert.Contains(t, string(injected.Body), payload)

			expectedBodyLength := len(req.Body) + len([]byte(payload))
			assert.Len(t, injected.Body, expectedBodyLength)
		}
	})

	t.Run("with multipart body", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Headers: headers(),
			Body: []byte(`--------------------------d74496d66958873e
Content-Disposition: form-data; name="person"

anonymous
--------------------------d74496d66958873e
Content-Disposition: form-data; name="secret"; filename="file.txt"
Content-Type: text/plain

contents of the file
--------------------------d74496d66958873e--`),
		}

		entrypoints := finder.Find(req)
		assert.Len(t, entrypoints, 2)

		assert.Equal(t, profile.EntireBody, entrypoints[0].InsertionPointType())
		assert.Equal(t, profile.EntireBodyMulti, entrypoints[1].InsertionPointType())

		for _, e := range entrypoints {
			injected := e.InjectPayload(req, profile.Insert, payload)
			assert.Contains(t, string(injected.Body), payload)

			expectedBodyLength := len(req.Body) + len([]byte(payload))
			assert.Len(t, injected.Body, expectedBodyLength)
		}
	})
}
