package slices

// Occurrences returns the number of times an element appears in a slice.
func Occurrences[T comparable](s []T, e T) int {
	var count int
	for _, v := range s {
		if v == e {
			count++
		}
	}
	return count
}

// In returns true if an element is in a slice.
// Otherwise, it returns false.
func In[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

// NoneIn returns true if none element is in a slice.
// Otherwise, it returns false.
func NoneIn[T comparable](s []T, ee []T) bool {
	m := make(map[T]struct{}, len(s))
	for _, e := range ee {
		m[e] = struct{}{}
	}

	for _, v := range s {
		if _, exists := m[v]; exists {
			return false
		}
	}

	return true
}

// ValForKey returns the value for a key in a slice.
// It assumes that the slice is a key-value pair.
func ValForKey[T comparable](s []T, e T) (T, bool) {
	var (
		found bool
		def   T
	)

	for _, v := range s {
		if found {
			return v, true
		}

		if v == e {
			found = true
		}
	}

	return def, false
}
