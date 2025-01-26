package modifier

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	scan "github.com/bountysecurity/gbounty"
	"github.com/bountysecurity/gbounty/entrypoint"
	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
)

const (
	indexLabel               = "{CURRENT_INDEX}"
	indexURL                 = "{CURRENT_URL}"
	indexPort                = "{CURRENT_PORT}"
	indexPath                = "{CURRENT_PATH}"
	indexHost                = "{CURRENT_HOST}"
	indexMethod              = "{CURRENT_METHOD}"
	indexQuery               = "{CURRENT_QUERY}"
	indexFile                = "{CURRENT_FILE}"
	indexProtocol            = "{CURRENT_PROTOCOL}"
	indexUserAgent           = "{CURRENT_USER_AGENT}"
	indexReferer             = "{CURRENT_REFERER}"
	indexOrigin              = "{CURRENT_ORIGIN}"
	indexContentType         = "{CURRENT_CONTENT_TYPE}"
	indexAccept              = "{CURRENT_ACCEPT}"
	indexAcceptLanguage      = "{CURRENT_ACCEPT_LANGUAGE}"
	indexAcceptEncoding      = "{CURRENT_ACCEPT_ENCODING}"
	indexContentLength       = "{CURRENT_CONTENT_LENGTH}"
	indexInsertionPoint      = "{CURRENT_INSERTION_POINT}"
	indexInsertionPointName  = "{CURRENT_INSERTION_POINT_NAME}"
	indexInsertionPointValue = "{CURRENT_INSERTION_POINT_VALUE}"
)

// Template must implement the [scan.Modifier] interface.
var _ scan.Modifier = &Template{}

// Template is a [scan.Modifier] implementation that modifies the request
// by replacing some specific placeholders (e.g. {CURRENT_METHOD}, {CURRENT_PATH})
// with the corresponding values (e.g. POST, /login) from the given template.
type Template struct {
	insertionPoint string
}

// NewTemplate is a constructor function that creates a new instance of
// the [Template] modifier.
func NewTemplate() *Template {
	return &Template{
		insertionPoint: indexInsertionPoint,
	}
}

// Customize sets the insertion point for the template.
func (t *Template) Customize(entrypoint entrypoint.Entrypoint) {
	t.insertionPoint = entrypoint.Value()
}

// Modify modifies the request by replacing the template placeholders.
func (t *Template) Modify(_ *profile.Step, tpl scan.Template, req request.Request) request.Request {
	tplURL := t.url(tpl)

	return replace(req, map[string]string{
		// Index:
		indexLabel: strconv.Itoa(tpl.Idx),

		// URL:
		indexURL:      tplURL.String(),
		indexPort:     tplURL.port,
		indexPath:     tplURL.path,
		indexHost:     tplURL.host,
		indexQuery:    tplURL.query,
		indexFile:     tplURL.file,
		indexProtocol: tplURL.protocol,

		// Method:
		indexMethod: tpl.Request.Method,

		// Headers:
		indexUserAgent:      tpl.Request.Header("User-Agent"),
		indexReferer:        tpl.Request.Header("Referer"),
		indexOrigin:         tpl.Request.Header("Origin"),
		indexContentType:    tpl.Request.Header("Content-Type"),
		indexAccept:         tpl.Request.Header("Accept"),
		indexAcceptLanguage: tpl.Request.Header("Accept-Language"),
		indexAcceptEncoding: tpl.Request.Header("Accept-Encoding"),
		indexContentLength:  tpl.Request.Header("Content-Length"),

		// Insertion:
		indexInsertionPoint:      t.insertionPoint,
		indexInsertionPointName:  t.insertionPoint,
		indexInsertionPointValue: t.insertionPoint,
	})
}

func (*Template) url(tpl scan.Template) urlParts {
	tplURL := urlParts{protocol: "http"}

	if strings.HasPrefix(strings.ToLower(tpl.Request.URL), "https://") {
		tplURL.protocol = "https"
	}

	parsedURL, err := url.ParseRequestURI(tpl.Request.URL)
	if err != nil {
		return urlParts{}
	}

	if strings.Contains(parsedURL.Host, ":") {
		parts := strings.Split(parsedURL.Host, ":")

		tplURL.host = parts[0]
		tplURL.port = parts[1]
	} else {
		tplURL.host = parsedURL.Host

		if tplURL.protocol == "https" {
			tplURL.port = "443"
		} else {
			tplURL.port = "80"
		}
	}

	if tpl.Request.Path != "" {
		parsedPath, err := url.Parse(tpl.Request.Path)
		if err != nil {
			return urlParts{}
		}

		tplURL.path = parsedPath.Path
		tplURL.query = parsedPath.RawQuery
	} else {
		tplURL.path = parsedURL.Path
		tplURL.query = parsedURL.RawQuery
	}

	if len(tplURL.path) > 0 && !strings.HasPrefix(tplURL.path, "/") {
		tplURL.path = "/" + tplURL.path
	}

	if len(tplURL.query) > 0 && strings.HasPrefix(tplURL.query, "?") {
		tplURL.query = tplURL.query[1:]
	}

	tplURL.file = filepath.Base(tplURL.path)

	return tplURL
}

type urlParts struct {
	protocol string
	host     string
	port     string
	path     string
	query    string
	file     string
}

func (u urlParts) String() string {
	query := u.query
	if len(query) > 0 && !strings.HasPrefix(query, "?") {
		query = "?" + query
	}

	return fmt.Sprintf("%s://%s:%s%s%s", u.protocol, u.host, u.port, u.path, query)
}
