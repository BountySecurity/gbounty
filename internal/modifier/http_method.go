package modifier

import (
	"fmt"
	"net/http"
	"strings"

	scan "github.com/bountysecurity/gbounty/internal"
	"github.com/bountysecurity/gbounty/internal/profile"
	"github.com/bountysecurity/gbounty/internal/request"
)

// HTTPMethod must implement the [scan.Modifier] interface.
var _ scan.Modifier = HTTPMethod{}

// HTTPMethod is a [scan.Modifier] implementation that changes the HTTP method of a [request.Request].
type HTTPMethod struct{}

// NewHTTPMethod is a constructor function that creates a new instance of the [HTTPMethod] modifier.
func NewHTTPMethod() HTTPMethod {
	return HTTPMethod{}
}

// Modify modifies the request by changing the HTTP method.
// It follows the following behavior:
// - In case of switching POST => GET, it sets the body as path, and removes the "Content-Length" header.
// - In case of switching GET => POST, it sets the query as the body, and adds the "Content-Length" header.
// - In case of swapping GET <=> POST, it sets the query as the body, the body as path,
// and updates the "Content-Length" header accordingly.
func (HTTPMethod) Modify(step *profile.Step, _ scan.Template, req request.Request) request.Request {
	cloned := req.Clone()
	if step == nil || !step.ChangeHTTPMethod {
		return cloned
	}

	switch {
	case step.ChangeHTTPMethodType.PostToGet() && req.Method == http.MethodPost:
		cloned.Method = http.MethodGet
		path, _ := split(req.Path)
		cloned.Path = merge(path, strings.TrimSpace(string(cloned.Body)))
		cloned.Body = nil
		delete(cloned.Headers, "Content-Length")

	case step.ChangeHTTPMethodType.GetToPost() && req.Method == http.MethodGet:
		cloned.Method = http.MethodPost
		path, query := split(req.Path)
		cloned.Path = path
		cloned.SetBody([]byte(query))

	case step.ChangeHTTPMethodType.SwapGetAndPost() && (req.Method == http.MethodGet || req.Method == http.MethodPost):
		if req.Method == http.MethodPost {
			cloned.Method = http.MethodGet
		} else if req.Method == http.MethodGet {
			cloned.Method = http.MethodPost
		}

		path, query := split(req.Path)
		cloned.Path = merge(path, strings.TrimSpace(string(cloned.Body)))
		cloned.SetBody([]byte(query))
	}

	return cloned
}

func merge(path, body string) string {
	if !strings.Contains(path, "?") {
		return fmt.Sprintf("%s?%s", path, body)
	}

	return fmt.Sprintf("%s&%s", path, body)
}

func split(path string) (string, string) {
	idx := strings.Index(path, "?")

	if idx < 0 {
		return path, ""
	}

	return path[:idx], path[idx+1:]
}
