package match

import (
	"strconv"
	"strings"

	"github.com/bountysecurity/gbounty/profile"
	"github.com/bountysecurity/gbounty/request"
	"github.com/bountysecurity/gbounty/response"
)

func bytesToFindIn(g profile.Grep, req *request.Request, res *response.Response) (int, []byte) {
	if len(g.Where) == 0 && res == nil ||
		len(g.Where) > 0 && req == nil {
		return 0, []byte{}
	}

	// Find grep in response
	if len(g.Where) == 0 {
		return resBytesToFindIn(g, res)
	}

	// Find grep in request
	return reqBytesToFindIn(g.Where, req)
}

func resBytesToFindIn(g profile.Grep, res *response.Response) (int, []byte) {
	headers := res.BytesOnlyHeaders()
	lenHeaders := len(headers) + len("\r\n")
	lenStatusLine := len(res.Proto + " " + strconv.Itoa(res.Code) + " " + res.Status + "\r\n")

	switch {
	case g.Option.OnlyInHeaders():
		return lenStatusLine, res.BytesOnlyHeaders()
	case g.Option.NotInHeaders():
		return lenHeaders, res.BytesWithoutHeaders()
	default:
		return 0, res.Bytes()
	}
}

func reqBytesToFindIn(where string, req *request.Request) (int, []byte) {
	switch {
	case strings.HasPrefix(where, "All"):
		return reqBytesToFindInAll(where, req)
	case strings.HasPrefix(where, "Url"):
		return reqBytesToFindInURL(where, req)
	case strings.HasPrefix(where, "Param"):
		return reqBytesToFindInParam(where, req)
	case strings.HasPrefix(where, "Entire"):
		return reqBytesToFindInEntire(where, req)
	case strings.HasPrefix(where, "HTTP"):
		return reqBytesToFindInHTTP(where, req)
	}

	return 0, []byte{}
}
