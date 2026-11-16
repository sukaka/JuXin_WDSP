package apiassets

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

const maxEndpointActionLength = 64

var endpointActionPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)

func normalizeEndpointAction(raw string) (string, error) {
	action := strings.ToUpper(strings.TrimSpace(raw))
	if action == "" {
		return "", fmt.Errorf("API ACTION 不能为空")
	}
	if len(action) > maxEndpointActionLength {
		return "", fmt.Errorf("API ACTION 超过 %d 字节上限", maxEndpointActionLength)
	}
	if !endpointActionPattern.MatchString(action) {
		return "", fmt.Errorf("API ACTION %q 含非法字符", action)
	}
	return action, nil
}

// ListEndpointActions 返回真实 ACTION 分类行的 endpoint_key → 操作动作映射。
func (s *Store) ListEndpointActions(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.Query(ctx, `
SELECT e.endpoint_key, d.value
FROM api_classification_dimensions d
JOIN api_endpoints e ON e.id = d.endpoint_id
WHERE d.dimension = 'ACTION'
ORDER BY e.endpoint_key, d.value`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var key, raw string
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, err
		}
		action, err := normalizeEndpointAction(raw)
		if err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", key, err)
		}
		if previous, ok := out[key]; ok && previous != action {
			return nil, fmt.Errorf("endpoint %q 存在冲突 ACTION：%s / %s", key, previous, action)
		}
		out[key] = action
	}
	return out, rows.Err()
}
