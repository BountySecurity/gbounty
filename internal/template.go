package scan

import (
	"github.com/bountysecurity/gbounty/internal/request"
	"github.com/bountysecurity/gbounty/internal/response"
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
