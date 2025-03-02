package writer

import "strings"

func trimBytesNewline(r interface{ Bytes() []byte }) string {
	return strings.TrimSuffix(string(r.Bytes()), "\n")
}
