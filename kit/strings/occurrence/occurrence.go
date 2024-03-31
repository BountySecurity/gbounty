package occurrence

import (
	"regexp"
	"strings"
)

// Occurrence is a 2-integer array that represents the positions
// (beginning-end) of the substring in the string.
type Occurrence [2]int

// Find returns the positions of the substring in the string.
// If the string or the substring is empty, it returns nil.
func Find(s, sub string) []Occurrence {
	// If either the string or the substring is empty,
	// there are no markers.
	if len(s) == 0 || len(sub) == 0 {
		return []Occurrence{}
	}
	positions := make([]Occurrence, 0)
	start := 0
	for {
		// If the substring is not found, break the loop
		index := strings.Index(s[start:], sub)
		if index == -1 {
			break
		}

		startIndex := start + index
		endIndex := startIndex + len(sub)
		positions = append(positions, Occurrence{startIndex, endIndex})
		start = endIndex
	}
	return positions
}

// FindRegexp is like Find, but it uses a regular expression
// to find the substring.
// If the string or the substring is empty, it returns nil.
func FindRegexp(s, regex string) []Occurrence {
	// If either the string or the substring is empty,
	// there are no markers.
	if len(s) == 0 || len(regex) == 0 {
		return []Occurrence{}
	}

	re, err := regexp.Compile(regex)
	if err != nil {
		return []Occurrence{}
	}

	matches := re.FindAllStringIndex(s, -1)
	if len(matches) == 0 {
		return []Occurrence{}
	}

	positions := make([]Occurrence, 0, len(matches))
	for _, match := range matches {
		positions = append(positions, Occurrence{match[0], match[1]})
	}

	return positions
}
