package client

import "encoding/gob"

func init() {
	netError := NetError("")
	gob.Register(&netError)
}

// NetError represents a network error.
type NetError string

// Error returns the error message.
// Implements the [error] interface.
func (err *NetError) Error() string {
	return string(*err)
}

// GobEncode encodes the error into a byte slice.
// Implements the [gob.GobEncoder] interface.
func (err *NetError) GobEncode() ([]byte, error) {
	r := make([]byte, 0, len(string(*err))+1)
	return append(r, string(*err)...), nil
}

// GobDecode decodes the error from a byte slice.
// Implements the [gob.GobDecoder] interface.
func (err *NetError) GobDecode(b []byte) error {
	*err = NetError(b)
	return nil
}
