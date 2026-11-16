package apiruntime

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// mergeFileSensitivity merges high-confidence extension classes with data-type
// labels from file-content rules. Values never enter this package.
func mergeFileSensitivity(extension string, detected []string) []string {
	set := map[string]struct{}{}
	for _, dataType := range classifyFileSensitivity(extension) {
		set[dataType] = struct{}{}
	}
	for _, dataType := range detected {
		dataType = strings.ToLower(strings.TrimSpace(dataType))
		if dataType == "" || utf8.RuneCountInString(dataType) > 64 || strings.ContainsFunc(dataType, unicode.IsControl) {
			continue
		}
		set[dataType] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for dataType := range set {
		out = append(out, dataType)
	}
	sort.Strings(out)
	if len(out) > 16 {
		out = out[:16]
	}
	return out
}
