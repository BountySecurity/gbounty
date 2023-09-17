package capitalize

import (
	"strings"
	"unicode"
)

// First returns a new string where the first character of the
// input string `str` is converted to its uppercase form.
//
// If the input string is empty, it returns an empty string.
func First(str string) string {
	if len(str) == 0 {
		return ""
	}

	tmp := []rune(str)
	tmp[0] = unicode.ToUpper(tmp[0])

	return string(tmp)
}

// All returns a new string where all characters of the input
// string are converted to their uppercase form.
func All(str string) string {
	return strings.ToUpper(str)
}
