package writer

import "sort"

func sortedKeys(m map[string]struct{ count int }) ([]string, int) {
	total := 0
	keys := make([]string, 0, len(m))
	for k, s := range m {
		total += s.count
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, total
}
