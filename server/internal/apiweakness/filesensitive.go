package apiweakness

import (
	"context"
	"time"
)

func (s *pgSignalSource) FileSensitiveContent(ctx context.Context, since time.Time) ([]EndpointSignal, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.id, e.endpoint_key, count(*) AS hits, min(e.occurred_at), max(e.occurred_at)
FROM api_runtime_events e
JOIN api_endpoints ep ON ep.endpoint_key = e.endpoint_key
WHERE e.occurred_at >= $1
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(e.details_json) m
    WHERE m->>'detector' = 'file'
      AND m->>'rule_id' = 'file.sensitive_content'
  )
GROUP BY ep.id, e.endpoint_key`, since)
	if err != nil {
		return nil, err
	}
	return scanSignals(rows)
}
