package identitybehavior

import (
	"net/url"
	"strings"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/counters"
)

const maxIdentifierValueLen = 256

var paginationQueryFields = map[string]struct{}{
	"cursor": {}, "limit": {}, "offset": {}, "page": {}, "page_size": {},
	"pagesize": {}, "per_page": {}, "perpage": {},
}

var batchPathSegments = map[string]struct{}{
	"batch": {}, "bulk": {}, "export": {}, "replication": {}, "sync": {},
}

// enumerationExcluded prevents pagination, bulk and synchronization traffic from
// being interpreted as interactive enumeration. Trusted scanners remain covered
// by the existing IP/User-Agent whitelist before Begin reaches this helper.
func enumerationExcluded(path string, query url.Values) bool {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if _, ok := batchPathSegments[strings.ToLower(strings.TrimSpace(segment))]; ok {
			return true
		}
	}
	for name := range query {
		if _, ok := paginationQueryFields[strings.ToLower(strings.TrimSpace(name))]; ok {
			return true
		}
	}
	return false
}

// identifierKey extracts one configured query identifier and returns only a salted
// digest. Raw account/object values never enter the tracker or event payload.
func identifierKey(query url.Values, fields []string) string {
	for _, field := range fields {
		field = strings.ToLower(strings.TrimSpace(field))
		if field == "" {
			continue
		}
		for name, values := range query {
			if strings.ToLower(name) != field {
				continue
			}
			for _, value := range values {
				value = strings.TrimSpace(value)
				if value == "" || len(value) > maxIdentifierValueLen {
					continue
				}
				return counters.HashParts("enum", field, value)
			}
		}
	}
	return ""
}
