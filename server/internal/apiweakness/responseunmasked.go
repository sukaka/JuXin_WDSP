package apiweakness

import (
	"context"
	"time"
)

// SensitiveResponseUnmasked 响应涉敏且未观察到成功脱敏的事件按端点聚合。
// response.mask_applied 可能只覆盖部分字段并带 skipped_fields；当前没有字段级
// 部分脱敏对账证据，因此同事件出现该明细即保守排除，不推断其已完全脱敏。
func (s *pgSignalSource) SensitiveResponseUnmasked(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' IN ('sensitive.response_field', 'sensitive.response_value')
  )
  AND NOT EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'rule_id' = 'response.mask_applied'
  )
GROUP BY ep.id, e.endpoint_key
HAVING count(*) >= $2`, since, minSamples)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}
