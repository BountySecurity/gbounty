package entrypoint_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

const (
	payload = "/.git/HEAD"
)

func TestHeaderFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	req := request.Request{Headers: headers()}

	finder := entrypoint.NewHeaderFinder()
	entrypoints := finder.Find(req)

	injected := make(map[string]bool)

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Replace, payload)
		injected[findHeaderWithPayload(injReq)] = true
	}

	for key, expected := range expectedInjections() {
		assert.Equal(t, expected, injected[key])
	}

	// Original headers has not been modified
	assert.True(t, reflect.DeepEqual(req.Headers, headers()))
}

func TestHeaderFinder_Find_Append(t *testing.T) {
	t.Parallel()

	req := request.Request{Headers: headers()}

	finder := entrypoint.NewHeaderFinder()
	entrypoints := finder.Find(req)

	injected := make(map[string]bool)

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Append, payload)
		injected[findHeaderWithPayload(injReq)] = true
	}

	for key, expected := range expectedInjections() {
		assert.Equal(t, expected, injected[key])
	}

	// Original headers has not been modified
	assert.True(t, reflect.DeepEqual(req.Headers, headers()))
}

func TestHeaderFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	req := request.Request{Headers: headers()}

	finder := entrypoint.NewHeaderFinder()
	entrypoints := finder.Find(req)

	injected := make(map[string]bool)

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Insert, payload)
		injected[findHeaderWithPayload(injReq)] = true
	}

	for key, expected := range expectedInjections() {
		assert.Equal(t, expected, injected[key])
	}

	// Original headers has not been modified
	assert.True(t, reflect.DeepEqual(req.Headers, headers()))
}

func findHeaderWithPayload(req request.Request) string {
	for key, values := range req.Headers {
		for _, val := range values {
			if strings.Contains(val, payload) {
				return key
			}
		}
	}

	return ""
}

func headers() map[string][]string {
	return map[string][]string{
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
}

func expectedInjections() map[string]bool {
	return map[string]bool{
		// expected
		"Host":            true,
		"User-Agent":      true,
		"Accept":          true,
		"Accept-Language": true,
		"Accept-Encoding": true,
		"Content-Type":    true,
		"Origin":          true,
		"Referer":         true,
		// non-expected
		"Content-Length":            false,
		"Dnt":                       false,
		"Upgrade-Insecure-Requests": false,
	}
}
