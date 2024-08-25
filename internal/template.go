package scan

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/url"
	"strings"

	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
	"github.com/bountysecurity/gbounty/kit/logger"
)

// Template is an abstraction that represents a request and response pair
// used for scanning. It also contains the original URL and the unique
// index within the entire scan.
type Template struct {
	Idx         int
	OriginalURL string
	request.Request
	Response *response.Response
}

// TemplatesFromZipBytes initializes a slice of [Template] with the given [ParamsCfg], a slice of [request.Option]
// and interpreting the slice of bytes as the contents of a zipped (.zip) file that contains one or more files,
// each containing a raw HTTP request.
func TemplatesFromZipBytes(ctx context.Context, pCfg ParamsCfg, fileBytes []byte, opts ...request.Option) ([]Template, error) {
	zipReader, err := zip.NewReader(bytes.NewReader(fileBytes), int64(len(fileBytes)))
	if err != nil {
		return nil, err
	}

	var tplIdx int
	templates := make([]Template, 0, len(zipReader.File))

	for _, zipFile := range zipReader.File {
		file, err := zipFile.Open()
		if err != nil {
			return nil, err
		}

		fileBytes, err := io.ReadAll(file)
		if err != nil {
			return nil, err
		}

		req, err := request.ParseRequest(fileBytes)
		if err != nil {
			return nil, err
		}

		for _, opt := range opts {
			req = opt(req)
		}

		expanded := pCfg.Alter(NewTemplate(ctx, tplIdx, req, nil))
		templates = append(templates, expanded...)
		tplIdx += len(expanded)
	}

	return templates, nil
}

// TemplateFromRawBytes initializes a slice of [Template] with the given [ParamsCfg], a slice of [request.Option]
// and interpreting the slice of bytes as a file that contains a raw HTTP request.
func TemplateFromRawBytes(ctx context.Context, idx int, pCfg ParamsCfg, fileBytes []byte, opts ...request.Option) ([]Template, error) {
	req, err := request.ParseRequest(fileBytes)
	if err != nil {
		return nil, err
	}

	for _, opt := range opts {
		req = opt(req)
	}

	return pCfg.Alter(NewTemplate(ctx, idx, req, nil)), nil
}

// NewTemplate instantiates a new [Template] with the given [request.Request], the [response.Response],
// if any, and the given index. So, similar to manually populating the [Template] fields but with some
// validations in place.
func NewTemplate(ctx context.Context, idx int, req request.Request, res *response.Response) Template {
	defaultReturn := Template{Idx: idx, OriginalURL: req.URL, Request: req, Response: res}

	if strings.Contains(req.URL, req.Path) {
		return defaultReturn
	}

	baseURL, err := url.Parse(req.URL)
	if err != nil {
		logger.For(ctx).Errorf("Cannot parse base url(%s): %s", req.URL, err.Error())
		return defaultReturn
	}

	urlPath, err := url.Parse(req.Path)
	if err != nil {
		logger.For(ctx).Errorf("Cannot parse url path(%s): %s", req.Path, err.Error())
		return defaultReturn
	}

	return Template{Idx: idx, OriginalURL: baseURL.ResolveReference(urlPath).String(), Request: req, Response: res}
}

// Clone returns a clone (copy) of the [Template], keeping the same index, URL,
// and deep-copying the [request.Request].
func (tpl Template) Clone(idx int) Template {
	return Template{
		Idx:         idx,
		OriginalURL: tpl.OriginalURL,
		Request:     tpl.Request.Clone(),
	}
}
