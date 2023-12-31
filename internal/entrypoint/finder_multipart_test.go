package entrypoint_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bountysecurity/gbounty/internal/entrypoint"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

func TestMultipartFinder_Find_Replace(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{
		Headers: map[string][]string{
			"Content-Type": {"multipart/form-data; boundary=------------------------1a075e12067d8650"},
		},
		Body: []byte(`--------------------------1a075e12067d8650
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
--------------------------1a075e12067d8650--`),
	}

	exp := [][]byte{
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="/.git/HEAD"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

/.git/HEAD
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="/.git/HEAD"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `/.git/HEAD`)),
	}

	finder := entrypoint.NewMultipartFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Replace, payload)

		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}

func TestMultipartFinder_Find_Append(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{
		Headers: map[string][]string{
			"Content-Type": {"multipart/form-data; boundary=------------------------1a075e12067d8650"},
		},
		Body: []byte(`--------------------------1a075e12067d8650
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
--------------------------1a075e12067d8650--`),
	}

	exp := [][]byte{
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello/.git/HEAD"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there/.git/HEAD
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing/.git/HEAD"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
../.git/HEAD`)),
	}

	finder := entrypoint.NewMultipartFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Append, payload)

		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}

func TestMultipartFinder_Find_Insert(t *testing.T) {
	t.Parallel()

	const payload = "/.git/HEAD"

	req := request.Request{
		Headers: map[string][]string{
			"Content-Type": {"multipart/form-data; boundary=------------------------1a075e12067d8650"},
		},
		Body: []byte(`--------------------------1a075e12067d8650
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
--------------------------1a075e12067d8650--`),
	}

	exp := [][]byte{
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="he/.git/HEADllo"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

th/.git/HEADere
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="tes/.git/HEADting"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
		[]byte(fmt.Sprintf(strings.ReplaceAll(`--------------------------1a075e12067d8650
Content-Disposition: form-data; name="hello"

there
--------------------------1a075e12067d8650
Content-Disposition: form-data; name="testing"; filename="1.txt"
Content-Type: text/plain

%s
--------------------------1a075e12067d8650--
`, "\n", "\r\n"), `http://localhost:8888.GET /listproducts.php?cat=1 HTTP/1.1.Host:
 testphp.vulnweb.com.User-Agent: Mozilla/5.0 (Windows NT 10.0; W
in64; x64; rv:83.0) Gecko/20100101 Firefox/83.0.Accept: text/htm
l,application/xhtml+xml,applicati/.git/HEADon/xml;q=0.9,image/webp,*/*;q=0
.8.Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3.Accept-E
ncoding: gzip, deflate.DNT: 1.Connection: close.Referer: http://
testphp.vulnweb.com/categories.php.Upgrade-Insecure-Requests: 1.
..`)),
	}

	finder := entrypoint.NewMultipartFinder()
	entrypoints := finder.Find(req)
	builtBodies := make([][]byte, 0, len(entrypoints))

	for _, e := range entrypoints {
		injReq := e.InjectPayload(req, profile.Insert, payload)

		builtBodies = append(builtBodies, injReq.Body)
	}

	assert.ElementsMatch(t, exp, builtBodies)
}
