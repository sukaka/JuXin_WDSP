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

// enumerationExcludedPath reports whether the path hits a bulk/synchronization segment.
// Such endpoints remain fully excluded from identifier extraction: a forged path segment
// changes routing (the attacker cannot append "/sync" without hitting a different route),
// so path-based exclusion is not a free bypass — unlike query pagination fields, which any
// request can carry (see identifierQuery). Trusted scanners remain covered by the existing
// IP/User-Agent whitelist before Begin reaches this helper.
func enumerationExcludedPath(path string) bool {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if _, ok := batchPathSegments[strings.ToLower(strings.TrimSpace(segment))]; ok {
			return true
		}
	}
	return false
}

// identifierQuery returns a copy of the query without pagination fields. Pagination
// parameters used to exclude the whole request from account/object identifier extraction,
// which made the enumeration rules a one-key bypass (append "&page=1" and
// RECON-ACCOUNT-001/RECON-OBJECT-001 never fire). Degraded semantics instead: pagination
// field churn itself is not counted as identifier rotation, but the remaining account/object
// identifiers are still extracted and tracked.
func identifierQuery(query url.Values) url.Values {
	out := make(url.Values, len(query))
	for name, values := range query {
		if _, ok := paginationQueryFields[strings.ToLower(strings.TrimSpace(name))]; ok {
			continue
		}
		out[name] = values
	}
	return out
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
