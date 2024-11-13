package request_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/internal/request"
)

func TestToStdlib_Basic(t *testing.T) {
	baseReqBody := []byte("test body")

	baseReq := request.Request{
		Method: "POST",
		URL:    "https://example.com",
		Body:   baseReqBody,
	}

	httpReq, err := baseReq.ToStdlib()
	require.NoError(t, err)

	assert.Equal(t, "POST", httpReq.Method)
	assert.Equal(t, "https://example.com", httpReq.URL.String())

	httpReqBody, err := io.ReadAll(httpReq.Body)
	require.NoError(t, err)

	assert.Equal(t, baseReqBody, httpReqBody)
}

func TestToStdlib_CustomPath(t *testing.T) {
	const baseReqPath = "/custom-path"

	baseReq := request.Request{
		Method: "GET",
		URL:    "https://example.com",
		Path:   baseReqPath,
	}

	httpReq, err := baseReq.ToStdlib()
	require.NoError(t, err)

	assert.Equal(t, baseReqPath, httpReq.URL.Path)
}

func TestToStdlib_CustomProtocolVersion(t *testing.T) {
	baseReq := request.Request{
		Method: "GET",
		URL:    "https://example.com",
		Proto:  "HTTP/1.1",
	}

	httpReq, err := baseReq.ToStdlib()
	require.NoError(t, err)

	assert.Equal(t, "HTTP/1.1", httpReq.Proto)
	assert.Equal(t, 1, httpReq.ProtoMajor)
	assert.Equal(t, 1, httpReq.ProtoMinor)
}

func TestToStdlib_Headers(t *testing.T) {
	baseReq := request.Request{
		Method: "POST",
		URL:    "https://example.com",
		Headers: map[string][]string{
			"Content-Type":    {"application/json"},
			"X-Custom-Header": {"value1", "value2"},
		},
	}

	httpReq, err := baseReq.ToStdlib()
	require.NoError(t, err)

	assert.Equal(t, "application/json", httpReq.Header.Get("Content-Type"))
	assert.Equal(t, []string{"value1", "value2"}, httpReq.Header.Values("X-Custom-Header"))
}

func TestToStdlib_InvalidURL(t *testing.T) {
	baseReq := request.Request{
		Method: "GET",
		URL:    "://invalid-url",
	}

	_, err := baseReq.ToStdlib()
	require.Error(t, err)
}
