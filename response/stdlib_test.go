package response_test

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty/response"
)

func TestFromStdlib_Basic(t *testing.T) {
	t.Parallel()

	httpRes := &http.Response{
		Proto:      "HTTP/1.1",
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewBufferString(`{"key": "value"}`)),
	}

	resp, err := response.FromStdlib(httpRes)
	require.NoError(t, err)

	assert.Equal(t, "HTTP/1.1", resp.Proto)
	assert.Equal(t, 200, resp.Code)
	assert.Equal(t, "OK", resp.Status)
	assert.Equal(t, headerAsMap(httpRes.Header), resp.Headers)
	assert.JSONEq(t, `{"key": "value"}`, string(resp.Body))
}

func TestFromStdlib_NilBody(t *testing.T) {
	t.Parallel()

	httpRes := &http.Response{
		Proto:      "HTTP/1.1",
		Status:     "204 No Content",
		StatusCode: http.StatusNoContent,
		Header:     http.Header{},
		Body:       nil,
	}

	resp, err := response.FromStdlib(httpRes)
	require.NoError(t, err)

	assert.Equal(t, "HTTP/1.1", resp.Proto)
	assert.Equal(t, http.StatusNoContent, resp.Code)
	assert.Equal(t, "No Content", resp.Status)
	assert.Equal(t, headerAsMap(httpRes.Header), resp.Headers)
	assert.Empty(t, resp.Body)
}

func TestFromStdlib_BodyError(t *testing.T) {
	t.Parallel()

	httpRes := &http.Response{
		Proto:      "HTTP/1.1",
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(&errorReader{}), // Simulate a read error
	}

	_, err := response.FromStdlib(httpRes)
	require.Error(t, err)
}

func headerAsMap(header http.Header) map[string][]string {
	headers := make(map[string][]string)
	for key, values := range header {
		headers[key] = values
	}
	return headers
}

type errorReader struct{}

func (e *errorReader) Read(_ []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (e *errorReader) Close() error {
	return nil
}
