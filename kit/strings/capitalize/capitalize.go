package capitalize

import (
	"strings"
	"unicode"
)

func First(str string) string {
	if len(str) == 0 {
		return ""
	}

	tmp := []rune(str)
	tmp[0] = unicode.ToUpper(tmp[0])

	return string(tmp)
}

func All(str string) string {
	return strings.ToUpper(str)
}
