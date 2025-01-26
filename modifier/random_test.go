package modifier_test

import (
	"github.com/BountySecurity/gbounty"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/BountySecurity/gbounty/modifier"
	"github.com/BountySecurity/gbounty/request"
)

const randomLabel = "{RANDOM}"

func TestRandom_Modify(t *testing.T) {
	t.Parallel()

	m := modifier.NewRandom()

	t.Run("on path", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithRandomOnPath())
		require.NoError(t, err)

		replaced := m.Modify(nil, gbounty.Template{}, req)

		req.Headers["Content-Length"] = replaced.Headers["Content-Length"]
		assert.Equal(t, req.Headers, replaced.Headers)
		assert.Equal(t, req.Body, replaced.Body)
		assert.NotEqual(t, req.Path, replaced.Path)
		assert.NotContains(t, replaced.Path, randomLabel)
		assert.Contains(t, replaced.Modifications, randomLabel)
	})

	t.Run("on header", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithRandomOnHeader())
		require.NoError(t, err)

		replaced := m.Modify(nil, gbounty.Template{}, req)

		assert.Equal(t, req.Path, replaced.Path)
		assert.Equal(t, req.Body, replaced.Body)
		assert.NotEqual(t, req.Headers, replaced.Headers)
		assert.NotContains(t, replaced.Headers["Content-Length"][0], randomLabel)
		assert.Contains(t, replaced.Modifications, randomLabel)
	})

	t.Run("on body", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithRandomOnBody())
		require.NoError(t, err)

		replaced := m.Modify(nil, gbounty.Template{}, req)

		assert.Equal(t, req.Path, replaced.Path)
		req.Headers["Content-Length"] = replaced.Headers["Content-Length"]
		assert.Equal(t, req.Headers, replaced.Headers)
		assert.NotEqual(t, req.Body, replaced.Body)
		assert.NotContains(t, replaced.Body, randomLabel)
		assert.Contains(t, replaced.Modifications, randomLabel)
	})
}

func rawReqWithRandomOnPath() []byte {
	return []byte(`POST /search.php?test={RANDOM} HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Connection: close
Content-Length: 26
Content-Type: application/x-www-form-urlencoded
Dnt: 1
Host: http://localhost:8080
Origin: http://testphp.vulnweb.com
Referer: http://testphp.vulnweb.com/search.php?test=query
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

searchFor=test&goButton=go

`)
}

func rawReqWithRandomOnHeader() []byte {
	return []byte(`POST /search.php?test=query HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Connection: close
Content-Length: {RANDOM}
Content-Type: application/x-www-form-urlencoded
Dnt: 1
Host: http://localhost:8080
Origin: http://testphp.vulnweb.com
Referer: http://testphp.vulnweb.com/search.php?test=query
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

searchFor=test&goButton=go

`)
}

func rawReqWithRandomOnBody() []byte {
	return []byte(`POST /search.php?test=query HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Connection: close
Content-Length: 26
Content-Type: application/x-www-form-urlencoded
Dnt: 1
Host: http://localhost:8080
Origin: http://testphp.vulnweb.com
Referer: http://testphp.vulnweb.com/search.php?test=query
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

searchFor={RANDOM}&goButton=go

`)
}
