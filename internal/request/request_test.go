package request_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func Test_ParseRequest(t *testing.T) {
	t.Parallel()

	t.Run("without body", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithoutBody())

		require.NoError(t, err)
		assert.Equal(t, request.Request{
			URL:    "http://localhost:8080",
			Method: "POST",
			Path:   "/search.php?test=query",
			Proto:  "HTTP/1.1",
			Headers: map[string][]string{
				"Host":                      {"http://localhost:8080"},
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
			},
			Timeout:      20 * time.Second,
			RedirectType: profile.RedirectNever,
			MaxRedirects: 0,
		}, req)
	})

	t.Run("with empty body", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithEmptyBody())

		require.NoError(t, err)
		assert.Equal(t, request.Request{
			URL:    "http://localhost:8080",
			Method: "POST",
			Path:   "/search.php?test=query",
			Proto:  "HTTP/1.1",
			Headers: map[string][]string{
				"Host":                      {"http://localhost:8080"},
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
			},
			Timeout:      20 * time.Second,
			RedirectType: profile.RedirectNever,
			MaxRedirects: 0,
		}, req)
	})

	t.Run("with new line body", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithNewLineBody())

		require.NoError(t, err)
		assert.Equal(t, request.Request{
			URL:    "http://localhost:8080",
			Method: "POST",
			Path:   "/search.php?test=query",
			Proto:  "HTTP/1.1",
			Headers: map[string][]string{
				"Host":                      {"http://localhost:8080"},
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
			},
			Timeout:      20 * time.Second,
			RedirectType: profile.RedirectNever,
			MaxRedirects: 0,
		}, req)
	})

	t.Run("with body", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithBody())

		require.NoError(t, err)
		assert.Equal(t, request.Request{
			URL:    "http://localhost:8080",
			Method: "POST",
			Path:   "/search.php?test=query",
			Proto:  "HTTP/1.1",
			Headers: map[string][]string{
				"Host":                      {"http://localhost:8080"},
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
			},
			Body: []byte(`searchFor=test&goButton=go

`),
			Timeout:      20 * time.Second,
			RedirectType: profile.RedirectNever,
			MaxRedirects: 0,
		}, req)
	})
}

func TestRequest_Clone(t *testing.T) {
	t.Parallel()

	req, err := request.ParseRequest(rawReqWithBody())
	require.NoError(t, err)

	req.Modifications = map[string]string{
		"{RANDOM}": "01FCADQSCX",
	}

	req2 := req.Clone()
	assert.True(t, reflect.DeepEqual(req, req2))

	req2.Headers["Host"] = []string{"localhost:8080"}
	assert.False(t, reflect.DeepEqual(req, req2))

	req2.Body = []byte("searchFor=go&goButton=test")
	assert.False(t, reflect.DeepEqual(req, req2))

	req2.Modifications["{LABEL}"] = "3NS4CHD9"
	assert.False(t, reflect.DeepEqual(req, req2))
	assert.Equal(t, req.Modifications["{RANDOM}"], req2.Modifications["{RANDOM}"])
}

func TestRequest_MultipartForm(t *testing.T) {
	t.Parallel()

	t.Run("multipart values", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithMultipart())
		require.NoError(t, err)

		form, err := req.MultipartForm()
		require.NoError(t, err)

		assert.Equal(t, map[string][]string{"hello": {"there"}, "testing": {"abc"}}, form.Value)
	})

	t.Run("multipart file", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithMultipartFile())
		require.NoError(t, err)

		form, err := req.MultipartForm()
		require.NoError(t, err)

		assert.Equal(t, map[string][]string{"hello": {"there"}}, form.Value)

		assert.Equal(t, "1.txt", form.File["testing"][0].Filename)
		assert.Equal(t, int64(457), form.File["testing"][0].Size)
		assert.Equal(t, "form-data; name=\"testing\"; filename=\"1.txt\"", form.File["testing"][0].Header.Get("Content-Disposition"))
		assert.Equal(t, "text/plain", form.File["testing"][0].Header.Get("Content-Type"))
	})
}

func TestRequest_HasJSONBody(t *testing.T) {
	t.Parallel()

	t.Run("form", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithBody())
		require.NoError(t, err)
		assert.False(t, req.HasJSONBody())
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest([]byte(`POST /search.php?test=query HTTP/1.1
Host: http://localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

{"searchFor":"test","goButton":"go"}

`))
		require.NoError(t, err)
		assert.True(t, req.HasJSONBody())
	})

	t.Run("xml", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest([]byte(`POST /search.php?test=query HTTP/1.1
Host: http://localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

<xml><node name="nodename1">nodetext1</node><node name="nodename2">nodetext2</node></xml>
`))
		require.NoError(t, err)
		assert.False(t, req.HasJSONBody())
	})
}

func TestRequest_HasXMLBody(t *testing.T) {
	t.Parallel()

	t.Run("form", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest(rawReqWithBody())
		require.NoError(t, err)
		assert.False(t, req.HasXMLBody())
	})

	t.Run("json", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest([]byte(`POST /search.php?test=query HTTP/1.1
Host: http://localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

{"searchFor":"test","goButton":"go"}

`))
		require.NoError(t, err)
		assert.False(t, req.HasXMLBody())
	})

	t.Run("xml", func(t *testing.T) {
		t.Parallel()

		req, err := request.ParseRequest([]byte(`POST /search.php?test=query HTTP/1.1
Host: http://localhost:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0

<xml><node name="nodename1">nodetext1</node><node name="nodename2">nodetext2</node></xml>
`))
		require.NoError(t, err)
		assert.True(t, req.HasXMLBody())
	})
}

func TestRequest_JSON(t *testing.T) {
	t.Parallel()

	req := request.Request{
		URL:    "http://localhost:8080",
		Method: "POST",
		Path:   "/search.php?test=query",
		Proto:  "HTTP/1.1",
		Headers: map[string][]string{
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
		},
		Body: []byte(`searchFor=test&goButton=go

`),
		Timeout:      20 * time.Second,
		RedirectType: profile.RedirectNever,
		MaxRedirects: 0,
	}

	data, err := req.ToJSON()
	require.NoError(t, err)

	req2, err := request.RequestFromJSON(data)
	require.NoError(t, err)

	assert.True(t, reflect.DeepEqual(req, req2))
}

func rawReqWithoutBody() []byte {
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
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0`)
}

func rawReqWithEmptyBody() []byte {
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
`)
}

func rawReqWithNewLineBody() []byte {
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

`)
}

func rawReqWithBody() []byte {
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

searchFor=test&goButton=go

`)
}

func rawReqWithMultipart() []byte {
	return []byte(`POST / HTTP/1.1
Host: http://localhost:8080
User-Agent: curl/7.64.1
Accept: */*
Content-Length: 244
Content-Type: multipart/form-data; boundary=------------------------37d8662fb09b6472

--------------------------37d8662fb09b6472
Content-Disposition: form-data; name="hello"

there
--------------------------37d8662fb09b6472
Content-Disposition: form-data; name="testing"

abc
--------------------------37d8662fb09b6472--

`)
}

func rawReqWithMultipartFile() []byte {
	return []byte(`POST / HTTP/1.1
Host: http://localhost:8080
User-Agent: curl/7.64.1
Accept: */*
Content-Length: 735
Content-Type: multipart/form-data; boundary=------------------------1a075e12067d8650

--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..
--------------------------1a075e12067d8650--`)
}
