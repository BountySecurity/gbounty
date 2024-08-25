package cli

import "strings"

// MultiValue defines a stringified command-line argument that can contain multiple values.
// So, it can be used multiple times within the same command run.
type MultiValue []string

func (m *MultiValue) String() string {
	return strings.Join(*m, ",")
}

func (m *MultiValue) Set(value string) error {
	*m = append(*m, value)
	return nil
}
