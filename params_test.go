//nolint:testpackage
package gbounty

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/BountySecurity/gbounty/request"
)

func Test_ParamsCfg_Expand_GET(t *testing.T) {
	t.Parallel()

	pCfg := ParamsCfg{
		Params: []string{"query", "order", "limit,100"},
		Size:   2,
		Method: http.MethodGet,
	}

	tcs := map[string]struct {
		tpl Template
		out []Template
	}{
		"with none": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?order=order&query=query", Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?order=order&query=query",
					Method:  http.MethodGet,
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?limit=100", Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?limit=100",
					Method:  http.MethodGet,
				}},
			},
		},
		"with url params": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?test=query",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?order=order&query=query", Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?order=order&query=query",
					Method:  http.MethodGet,
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?limit=100", Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?limit=100",
					Method:  http.MethodGet,
				}},
			},
		},
		"with url-encoded body": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?order=order&query=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path:   "/search.php?order=order&query=query",
					Method: http.MethodGet,
					Body:   []byte("test=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?limit=100", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path:   "/search.php?limit=100",
					Method: http.MethodGet,
					Body:   []byte("test=query"),
				}},
			},
		},
		"with both": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php?test=query",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?order=order&query=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path:   "/search.php?order=order&query=query",
					Method: http.MethodGet,
					Body:   []byte("test=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?limit=100", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path:   "/search.php?limit=100",
					Method: http.MethodGet,
					Body:   []byte("test=query"),
				}},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, pCfg.Alter(tc.tpl))
		})
	}
}

func Test_ParamsCfg_Expand_POST_url(t *testing.T) {
	t.Parallel()

	pCfg := ParamsCfg{
		Params:   []string{"query", "order", "limit,100"},
		Size:     2,
		Method:   http.MethodPost,
		Encoding: "url",
	}

	tcs := map[string]struct {
		tpl Template
		out []Template
	}{
		"with none": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"23"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte("order=order&query=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"9"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte("limit=100"),
				}},
			},
		},
		"with url params": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?test=query",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"23"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte("order=order&query=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"9"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte("limit=100"),
				}},
			},
		},
		"with url-encoded body": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"23"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte("order=order&query=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"9"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte("limit=100"),
				}},
			},
		},
		"with both": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php?test=query",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"23"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte("order=order&query=query"),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"9"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte("limit=100"),
				}},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, pCfg.Alter(tc.tpl))
		})
	}
}

func Test_ParamsCfg_Expand_POST_json(t *testing.T) {
	t.Parallel()

	pCfg := ParamsCfg{
		Params:   []string{"query", "order", "limit,100"},
		Size:     2,
		Method:   http.MethodPost,
		Encoding: "json",
	}

	tcs := map[string]struct {
		tpl Template
		out []Template
	}{
		"with none": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"33"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte(`{"order":"order","query":"query"}`),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"15"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte(`{"limit":"100"}`),
				}},
			},
		},
		"with url params": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{},
					Path:    "/search.php?test=query",
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"33"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte(`{"order":"order","query":"query"}`),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"15"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte(`{"limit":"100"}`),
				}},
			},
		},
		"with url-encoded body": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"33"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte(`{"order":"order","query":"query"}`),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"15"},
					},
					Path:   "/search.php",
					Method: http.MethodPost,
					Body:   []byte(`{"limit":"100"}`),
				}},
			},
		},
		"with both": {
			tpl: Template{
				Idx:         0,
				OriginalURL: "http://testphp.vulnweb.com/search.php?test=query",
				Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/x-www-form-urlencoded"},
						"Content-Length": {"10"},
					},
					Path: "/search.php?test=query",
					Body: []byte("test=query"),
				},
			},
			out: []Template{
				{Idx: 0, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"33"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte(`{"order":"order","query":"query"}`),
				}},
				{Idx: 1, OriginalURL: "http://testphp.vulnweb.com/search.php?test=query", Request: request.Request{
					Headers: map[string][]string{
						"Content-Type":   {"application/json"},
						"Content-Length": {"15"},
					},
					Path:   "/search.php?test=query",
					Method: http.MethodPost,
					Body:   []byte(`{"limit":"100"}`),
				}},
			},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.out, pCfg.Alter(tc.tpl))
		})
	}
}

func Test_ParamsCfg_grouped(t *testing.T) {
	t.Parallel()

	const size = 2

	tcs := map[string]struct {
		params []string
		out    [][]string
	}{
		"less than size": {
			params: []string{"query"},
			out:    [][]string{{"query"}},
		},
		"equals to size": {
			params: []string{"query", "order"},
			out:    [][]string{{"query", "order"}},
		},
		"greater than size": {
			params: []string{"query", "order", "limit"},
			out:    [][]string{{"query", "order"}, {"limit"}},
		},
		"double the size": {
			params: []string{"query", "order", "limit", "offset"},
			out:    [][]string{{"query", "order"}, {"limit", "offset"}},
		},
		"more than double the size": {
			params: []string{"query", "order", "limit", "offset", "page"},
			out:    [][]string{{"query", "order"}, {"limit", "offset"}, {"page"}},
		},
	}

	for name, tc := range tcs {
		tc := tc

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			pCfg := ParamsCfg{Params: tc.params, Size: size}
			assert.Equal(t, tc.out, pCfg.grouped())
		})
	}
}
