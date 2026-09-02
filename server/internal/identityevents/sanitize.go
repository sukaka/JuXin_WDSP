package identityevents

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
)

const (
	maxIdentityEvidenceItems = 16
	maxIdentityEvidenceBytes = 128
	maxSignalMetadataFields  = 24
	maxSignalMetadataBytes   = 4096
	maxSignalMetadataString  = 256
)

// validIdentityEvidence contains explanation tokens only.  Evidence must never
// carry credential values, request samples, or other unbounded data.
var validIdentityEvidence = map[string]struct{}{
	"browser_fingerprint":         {},
	"client_ip":                   {},
	"user_agent:bot":              {},
	"user_agent:browser":          {},
	"credential:api_key_observed": {},
	"credential:cookie":           {},
	"credential:custom":           {},
	"credential:jwt":              {},
	"credential:mtls_verified":    {},
	"credential:oauth":            {},
	"credential:oauth_unverified": {},
	"credential:session":          {},
	"credential:subject":          {},
}

// validSignalMetadataFields is the stable, non-sensitive metadata contract
// emitted by the gateway and accepted by the server collector.
var validSignalMetadataFields = map[string]struct{}{
	"account_enum_count": {}, "auth_fail_count": {}, "distinct_methods": {},
	"hit_count": {}, "matched_prefix": {}, "new_uri_count": {},
	"new_uri_ratio": {}, "not_found_ratio": {}, "object_enum_count": {},
	"parameter_mutation_count": {}, "path": {}, "request_count": {},
	"sensitive_path_hits": {}, "status_404_count": {}, "ua_marker": {},
	"unique_uri_count": {},
}

func sanitizeIdentityEvidence(input []string) []string {
	if len(input) == 0 {
		return nil
	}
	out := make([]string, 0, minInt(len(input), maxIdentityEvidenceItems))
	seen := make(map[string]struct{}, maxIdentityEvidenceItems)
	for _, raw := range input {
		value := strings.TrimSpace(raw)
		if len(value) == 0 || len(value) > maxIdentityEvidenceBytes {
			continue
		}
		if _, ok := validIdentityEvidence[value]; !ok {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) == maxIdentityEvidenceItems {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeSignalMetadata(input map[string]any) map[string]any {
	if len(input) == 0 {
		return nil
	}
	keys := make([]string, 0, len(input))
	for key := range input {
		if _, ok := validSignalMetadataFields[key]; ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	out := make(map[string]any, minInt(len(keys), maxSignalMetadataFields))
	for _, key := range keys {
		if len(out) == maxSignalMetadataFields {
			break
		}
		if value, ok := sanitizeSignalMetadataValue(input[key]); ok {
			out[key] = value
		}
	}
	for len(out) > 0 {
		raw, err := json.Marshal(out)
		if err == nil && len(raw) <= maxSignalMetadataBytes {
			return out
		}
		// Remove the lexicographically last field until the bounded JSON fits.
		ordered := make([]string, 0, len(out))
		for key := range out {
			ordered = append(ordered, key)
		}
		sort.Strings(ordered)
		delete(out, ordered[len(ordered)-1])
	}
	return nil
}

func sanitizeSignalMetadataValue(value any) (any, bool) {
	switch v := value.(type) {
	case string:
		if len(v) > maxSignalMetadataString {
			return nil, false
		}
		return v, true
	case bool:
		return v, true
	case int:
		return v, true
	case int8:
		return int64(v), true
	case int16:
		return int64(v), true
	case int32:
		return int64(v), true
	case int64:
		return v, true
	case uint:
		return uint64(v), true
	case uint8:
		return uint64(v), true
	case uint16:
		return uint64(v), true
	case uint32:
		return uint64(v), true
	case uint64:
		return v, true
	case float32:
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			return nil, false
		}
		return float64(v), true
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, false
		}
		return v, true
	default:
		return nil, false
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
