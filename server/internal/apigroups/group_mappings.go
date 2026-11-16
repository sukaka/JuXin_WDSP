package apigroups

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

func normalizeEndpointGroupCode(raw string) (string, error) {
	code := strings.ToUpper(strings.TrimSpace(raw))
	if utf8.RuneCountInString(code) > maxCodeLength || !codePattern.MatchString(code) {
		return "", invalidf("group_code 须为 1-%d 个字符并匹配 ^[A-Z][A-Z0-9_]*$（自动转为大写）", maxCodeLength)
	}
	return code, nil
}

// ListEndpointGroups 返回 enabled 分组真实成员的 application_id → endpoint_key → 排序去重组码。
func (s *Store) ListEndpointGroups(ctx context.Context) (map[string]map[string][]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT g.application_id, e.application_id, e.endpoint_key, g.code
FROM api_endpoint_groups g
JOIN api_endpoint_group_members m ON m.group_id = g.id
JOIN api_endpoints e ON e.id = m.endpoint_id
WHERE g.enabled = TRUE
ORDER BY g.application_id, e.endpoint_key, g.code`)
	if err != nil {
		return nil, fmt.Errorf("list enabled endpoint group mappings: %w", err)
	}
	defer rows.Close()

	sets := map[string]map[string]map[string]struct{}{}
	for rows.Next() {
		var applicationID uuid.UUID
		var endpointApplicationID *uuid.UUID
		var endpointKey, rawCode string
		if err := rows.Scan(&applicationID, &endpointApplicationID, &endpointKey, &rawCode); err != nil {
			return nil, fmt.Errorf("scan endpoint group mapping: %w", err)
		}
		if endpointApplicationID == nil || *endpointApplicationID != applicationID {
			return nil, fmt.Errorf("接口 %q 的应用归属与分组应用 %s 冲突", endpointKey, applicationID)
		}
		if strings.TrimSpace(endpointKey) == "" {
			return nil, fmt.Errorf("应用 %s 的分组成员 endpoint_key 为空", applicationID)
		}
		code, err := normalizeEndpointGroupCode(rawCode)
		if err != nil {
			return nil, fmt.Errorf("应用 %s 接口 %q: %w", applicationID, endpointKey, err)
		}
		appID := applicationID.String()
		if sets[appID] == nil {
			sets[appID] = map[string]map[string]struct{}{}
		}
		if sets[appID][endpointKey] == nil {
			sets[appID][endpointKey] = map[string]struct{}{}
		}
		sets[appID][endpointKey][code] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate endpoint group mappings: %w", err)
	}

	out := make(map[string]map[string][]string, len(sets))
	for appID, endpoints := range sets {
		out[appID] = make(map[string][]string, len(endpoints))
		for endpointKey, codes := range endpoints {
			list := make([]string, 0, len(codes))
			for code := range codes {
				list = append(list, code)
			}
			sort.Strings(list)
			out[appID][endpointKey] = list
		}
	}
	return out, nil
}
