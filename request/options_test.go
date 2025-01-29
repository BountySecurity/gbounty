package request_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/request"
)

func TestOption(t *testing.T) {
	t.Parallel()

	req := request.Default("example.com:8080")

	t.Run("WithMethod", func(t *testing.T) {
		t.Parallel()
		newMethod := "PUT"
		newReq := request.WithMethod(newMethod)(req)
		assert.Equal(t, newMethod, newReq.Method)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Method, newReq.Method)
	})

	t.Run("WithPath", func(t *testing.T) {
		t.Parallel()
		newPath := "/some/example/path"
		newReq := request.WithPath(newPath)(req)
		assert.Equal(t, newPath, newReq.Path)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Path, newReq.Path)
	})

	t.Run("WithProto", func(t *testing.T) {
		t.Parallel()
		newProto := "HTTP/1.0"
		newReq := request.WithProto(newProto)(req)
		assert.Equal(t, newProto, newReq.Proto)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Proto, newReq.Proto)
	})

	t.Run("WithHeaders", func(t *testing.T) {
		t.Parallel()
		newHeaders := map[string][]string{
			"Host":                      {"testphp.vulnweb.com"},
			"User-Agent":                {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"},
			"Accept":                    {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
			"Accept-Language":           {"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3"},
			"Accept-Encoding":           {"gzip, deflate"},
			"Content-Type":              {"application/x-www-form-urlencoded"},
			"Content-Length":            {"26"},
			"Origin":                    {"http://testphp.vulnweb.com"},
			"Dnt":                       {"1"},
			"Connection":                {"close"},
			"Referer":                   {"http://testphp.vulnweb.com/search.php?test=query"},
			"Upgrade-Insecure-Requests": {"1"},
		}
		newReq := request.WithHeaders(newHeaders)(req)
		assert.Equal(t, newHeaders, newReq.Headers)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Headers, newReq.Headers)
	})

	t.Run("WithBody", func(t *testing.T) {
		t.Parallel()
		newBody := []byte(`<xml><node name="nodename1">nodetext1</node><node name="nodename2">nodetext2</node></xml>
`)
		newReq := request.WithBody(newBody)(req)
		assert.Equal(t, newBody, newReq.Body)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Body, newReq.Body)
	})

	t.Run("WithTimeout", func(t *testing.T) {
		t.Parallel()
		newTimeout := time.Second * 5
		newReq := request.WithTimeout(newTimeout)(req)
		assert.Equal(t, newTimeout, newReq.Timeout)
		assert.NotEqual(t, req, newReq)
		assert.NotEqual(t, req.Timeout, newReq.Timeout)
	})
}
