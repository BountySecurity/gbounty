package modifier_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/modifier"
	"github.com/bountysecurity/gbounty/internal/request"
)

func TestTemplate_Modify(t *testing.T) {
	t.Parallel()

	m := modifier.NewTemplate()

	t.Run("{CURRENT_INDEX}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{Idx: 99}
		req := request.Request{Path: "/{CURRENT_INDEX}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/99", modified.Path)
	})

	t.Run("{CURRENT_URL}", func(t *testing.T) {
		t.Parallel()

		req := request.Request{
			Path: "/{CURRENT_URL}",
		}

		t.Run("full url", func(t *testing.T) {
			t.Parallel()

			tpl := scan.Template{
				Idx: 99,
				Request: request.Request{
					URL: "http://testphp.vulnweb.com:80/search.php?test=query",
				},
			}

			modified := m.Modify(nil, tpl, req)
			assert.Equal(t, "/http://testphp.vulnweb.com:80/search.php?test=query", modified.Path)
		})

		t.Run("url + path", func(t *testing.T) {
			t.Parallel()

			tpl := scan.Template{
				Idx: 99,
				Request: request.Request{
					URL:  "http://testphp.vulnweb.com:80",
					Path: "/search.php?test=query",
				},
			}

			modified := m.Modify(nil, tpl, req)
			assert.Equal(t, "/http://testphp.vulnweb.com:80/search.php?test=query", modified.Path)
		})

		t.Run("url + path (no port)", func(t *testing.T) {
			t.Parallel()

			tpl := scan.Template{
				Idx: 99,
				Request: request.Request{
					URL:  "https://testphp.vulnweb.com",
					Path: "/search.php?test=query",
				},
			}

			modified := m.Modify(nil, tpl, req)
			assert.Equal(t, "/https://testphp.vulnweb.com:443/search.php?test=query", modified.Path)
		})

		t.Run("url + path (no query)", func(t *testing.T) {
			t.Parallel()

			tpl := scan.Template{
				Idx: 99,
				Request: request.Request{
					URL:  "http://testphp.vulnweb.com:80",
					Path: "/search.php",
				},
			}

			modified := m.Modify(nil, tpl, req)
			assert.Equal(t, "/http://testphp.vulnweb.com:80/search.php", modified.Path)
		})

		t.Run("url + path (no path)", func(t *testing.T) {
			t.Parallel()

			tpl := scan.Template{
				Idx: 99,
				Request: request.Request{
					URL: "http://testphp.vulnweb.com:80",
				},
			}

			modified := m.Modify(nil, tpl, req)
			assert.Equal(t, "/http://testphp.vulnweb.com:80", modified.Path)
		})
	})

	t.Run("{CURRENT_PORT}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				URL: "http://testphp.vulnweb.com:3000/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_PORT}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/3000", modified.Path)
	})

	t.Run("{CURRENT_PATH}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				URL: "http://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_PATH}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "//dir1/dir2/search.php", modified.Path)
	})

	t.Run("{CURRENT_HOST}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				URL: "http://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_HOST}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/testphp.vulnweb.com", modified.Path)
	})

	t.Run("{CURRENT_METHOD}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Method: http.MethodDelete,
				URL:    "http://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_METHOD}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/DELETE", modified.Path)
	})

	t.Run("{CURRENT_QUERY}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Method: http.MethodDelete,
				URL:    "http://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_QUERY}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/test=query", modified.Path)
	})

	t.Run("{CURRENT_FILE}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Method: http.MethodDelete,
				URL:    "http://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_FILE}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/search.php", modified.Path)
	})

	t.Run("{CURRENT_PROTOCOL}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Method: http.MethodDelete,
				URL:    "https://testphp.vulnweb.com:3000/dir1/dir2/search.php?test=query",
			},
		}

		req := request.Request{Path: "/{CURRENT_PROTOCOL}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/https", modified.Path)
	})

	t.Run("{CURRENT_USER_AGENT}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_USER_AGENT}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:83.0) Gecko/20100101 Firefox/83.0", modified.Path)
	})

	t.Run("{CURRENT_REFERER}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Referer": {"http://testphp.vulnweb.com/search.php?test=query"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_REFERER}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/http://testphp.vulnweb.com/search.php?test=query", modified.Path)
	})

	t.Run("{CURRENT_ORIGIN}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Origin": {"http://testphp.vulnweb.com"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_ORIGIN}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/http://testphp.vulnweb.com", modified.Path)
	})

	t.Run("{CURRENT_CONTENT_TYPE}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Content-Type": {"application/x-www-form-urlencoded"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_CONTENT_TYPE}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/application/x-www-form-urlencoded", modified.Path)
	})

	t.Run("{CURRENT_ACCEPT}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Accept": {"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_ACCEPT}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", modified.Path)
	})

	t.Run("{CURRENT_ACCEPT_LANGUAGE}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Accept-Language": {"es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_ACCEPT_LANGUAGE}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3", modified.Path)
	})

	t.Run("{CURRENT_ACCEPT_ENCODING}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Accept-Encoding": {"gzip, deflate"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_ACCEPT_ENCODING}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/gzip, deflate", modified.Path)
	})

	t.Run("{CURRENT_CONTENT_LENGTH}", func(t *testing.T) {
		t.Parallel()

		tpl := scan.Template{
			Idx: 99,
			Request: request.Request{
				Headers: map[string][]string{
					"Content-Length": {"28"},
				},
			},
		}

		req := request.Request{Path: "/{CURRENT_CONTENT_LENGTH}"}

		modified := m.Modify(nil, tpl, req)
		assert.Equal(t, "/28", modified.Path)
	})
}
