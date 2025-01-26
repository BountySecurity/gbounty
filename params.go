package gbounty

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// ParamsCfg defines the configuration for request parameters and is responsible
// for splitting them into chunked groups.
type ParamsCfg struct {
	Params   []string
	Size     int
	Method   string
	Encoding string
}

// Alter takes a [Template] as an input, and using the given [ParamsCfg] it constructs
// a new set of [Template].
func (pCfg ParamsCfg) Alter(tpl Template) []Template {
	groups := pCfg.grouped()
	if len(groups) == 0 {
		return []Template{tpl}
	}

	templates := make([]Template, 0, len(groups))

	tplIdx := tpl.Idx
	for _, params := range groups {
		switch pCfg.Method {
		case http.MethodGet:
			templates = append(templates, paramsToURL(tpl, tplIdx, params))
			tplIdx++
		case http.MethodPost:
			switch pCfg.Encoding {
			case "url", "json":
				templates = append(templates, paramsToBody(tpl, tplIdx, params, pCfg.Encoding))
				tplIdx++
			}
		}
	}

	return templates
}

func (pCfg ParamsCfg) grouped() [][]string {
	if len(pCfg.Params) == 0 || pCfg.Size == 0 {
		return nil
	}

	ng := len(pCfg.Params) / pCfg.Size
	if len(pCfg.Params)%pCfg.Size > 0 {
		ng++
	}

	groups := make([][]string, ng)

	for i := 0; i < ng; i++ {
		start := i * pCfg.Size
		end := start + pCfg.Size
		if end > len(pCfg.Params) {
			end = len(pCfg.Params)
		}

		groups[i] = append(groups[i], pCfg.Params[start:end]...)
	}

	return groups
}

func splitPath(path string) (string, string) {
	// There is query string (url values)
	if strings.Contains(path, "?") {
		chunks := strings.Split(path, "?")
		return chunks[0], chunks[1]
	}

	return path, ""
}

func paramsToURL(tpl Template, idx int, params []string) Template {
	newTpl := tpl.Clone(idx)
	newTpl.Method = http.MethodGet
	path, _ := splitPath(tpl.Request.Path)
	// We explicitly override the existing query string
	encodedValues := paramsAsURL(params)
	newTpl.Request.Path = strings.Join([]string{path, encodedValues}, "?")

	newOriginalURL, err := url.Parse(tpl.OriginalURL)
	if err == nil {
		newOriginalURL.RawQuery = encodedValues
		newTpl.OriginalURL = newOriginalURL.String()
	}

	return newTpl
}

func paramsToBody(tpl Template, idx int, params []string, encoding string) Template {
	newTpl := tpl.Clone(idx)
	newTpl.Method = http.MethodPost
	// Calculate the content body based on params and encoding
	var body string
	switch encoding {
	case "url":
		body = paramsAsURL(params)
		newTpl.Request.Headers["Content-Type"] = []string{"application/x-www-form-urlencoded"}
	case "json":
		body = paramsAsJSON(params)
		newTpl.Request.Headers["Content-Type"] = []string{"application/json"}
	}

	// We explicitly override the existing body
	newTpl.Request.SetBody([]byte(body))
	return newTpl
}

func paramsAsURL(params []string) string {
	values := make(url.Values)
	for _, p := range params {
		p, v := p, p
		if strings.Contains(p, ",") {
			chunks := strings.Split(p, ",")
			p, v = chunks[0], chunks[1]
			p, v = strings.TrimSpace(p), strings.TrimSpace(v)
		}

		values.Add(p, v)
	}
	return values.Encode()
}

func paramsAsJSON(params []string) string {
	m := make(map[string]string)
	for _, p := range params {
		p, v := p, p
		if strings.Contains(p, ",") {
			chunks := strings.Split(p, ",")
			p, v = chunks[0], chunks[1]
			p, v = strings.TrimSpace(p), strings.TrimSpace(v)
		}

		m[p] = v
	}

	mb, _ := json.Marshal(m) //nolint:errchkjson
	return string(mb)
}
