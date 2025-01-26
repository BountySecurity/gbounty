package response_test

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty/response"
)

func TestResponse_JSON(t *testing.T) {
	t.Parallel()

	res := response.Response{
		Proto:  "HTTP/1.1",
		Code:   404,
		Status: "Not Found",
		Headers: map[string][]string{
			"Server":         {"nginx/1.19.0"},
			"Date":           {"Sun, 07 Feb 2021 23:44:49 GMT"},
			"Content-Type":   {"text/html; charset=utf-8"},
			"Connection":     {"close"},
			"Content-Length": {"150"},
		},
		Body: []byte(`<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.19.0</center>
</body>
</html>
`),
	}

	data, err := res.ToJSON()
	require.NoError(t, err)

	res2, err := response.FromJSON(data)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(res, res2))
}

func TestParseResponse(t *testing.T) {
	t.Parallel()

	t.Run("valid response", func(t *testing.T) {
		t.Parallel()

		res, err := response.ParseResponse([]byte(`HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 13

Hello, world!`))

		require.NoError(t, err)
		assert.Equal(t, &response.Response{
			Proto:  "HTTP/1.1",
			Code:   200,
			Status: "OK",
			Headers: map[string][]string{
				"Content-Type":   {"text/plain"},
				"Content-Length": {"13"},
			},
			Body: []byte("Hello, world!"),
		}, res)
	})

	t.Run("invalid status line", func(t *testing.T) {
		t.Parallel()

		res, err := response.ParseResponse([]byte(`HTTP/1.1 200
Content-Type: text/plain
Content-Length: 13

Hello, world!`))

		assert.Nil(t, res)
		require.Error(t, err)
		require.ErrorIs(t, err, response.ErrInvalidStatusLine)
	})

	t.Run("no body", func(t *testing.T) {
		t.Parallel()

		res, err := response.ParseResponse([]byte(`HTTP/1.1 204 No Content
Content-Type: text/plain
Content-Length: 0

`))

		require.NoError(t, err)
		assert.Equal(t, &response.Response{
			Proto:  "HTTP/1.1",
			Code:   204,
			Status: "No Content",
			Headers: map[string][]string{
				"Content-Type":   {"text/plain"},
				"Content-Length": {"0"},
			},
			Body: nil,
		}, res)
	})
}
