// identity.go API 身份画像离线聚合（三微模型身份微模型）：
// api_runtime_events → UPSERT api_identity_profiles（identity_fingerprint × endpoint_id）。
// 纪律：仅非空身份指纹；匿名事件不写身份画像。
package aggregations

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

// RunIdentityProfiles 聚合近 lookback 窗口的运行时事件到 api_identity_profiles。
func (j *Jobs) RunIdentityProfiles(ctx context.Context, now time.Time) error {
	windowEnd := now.UTC()
	windowStart := windowEnd.Add(-24 * time.Hour)
	n, err := j.aggregateIdentityProfiles(ctx, windowStart, windowEnd)
	if err != nil {
		_ = j.store.recordJob(ctx, "IDENTITY", windowStart, windowEnd, "FAILED", n, err.Error())
		return err
	}
	return j.store.recordJob(ctx, "IDENTITY", windowStart, windowEnd, "SUCCESS", n, "")
}

func (j *Jobs) aggregateIdentityProfiles(ctx context.Context, start, end time.Time) (int, error) {
	rows, err := j.store.db.Query(ctx, `
SELECT e.id, ev.identity_fingerprint, ev.auth_type, count(*)::bigint,
       min(ev.occurred_at), max(ev.occurred_at)
FROM api_runtime_events ev
JOIN api_endpoints e ON e.endpoint_key = ev.endpoint_key
WHERE ev.occurred_at >= $1 AND ev.occurred_at < $2
  AND ev.identity_fingerprint <> ''
GROUP BY e.id, ev.identity_fingerprint, ev.auth_type`, start, end)
	if err != nil {
		return 0, fmt.Errorf("query identity events: %w", err)
	}
	defer rows.Close()

	type row struct {
		endpointID  uuid.UUID
		fp          string
		authType    string
		count       int64
		first, last time.Time
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.endpointID, &r.fp, &r.authType, &r.count, &r.first, &r.last); err != nil {
			return 0, err
		}
		list = append(list, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(list) == 0 {
		return 0, nil
	}
	tx, err := j.store.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	n := 0
	for _, r := range list {
		// 增量合并：request_count 取 GREATEST 累计近似（窗口重算覆盖式）
		if _, err := tx.Exec(ctx, `
INSERT INTO api_identity_profiles (identity_fingerprint, endpoint_id, auth_type, request_count, first_seen_at, last_seen_at)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (identity_fingerprint, endpoint_id) DO UPDATE SET
  auth_type = EXCLUDED.auth_type,
  request_count = EXCLUDED.request_count,
  first_seen_at = LEAST(api_identity_profiles.first_seen_at, EXCLUDED.first_seen_at),
  last_seen_at = GREATEST(api_identity_profiles.last_seen_at, EXCLUDED.last_seen_at)`,
			r.fp, r.endpointID, r.authType, r.count, r.first, r.last); err != nil {
			return n, fmt.Errorf("upsert identity profile: %w", err)
		}
		n++
	}
	if err := tx.Commit(ctx); err != nil {
		return n, err
	}
	slog.Info("identity profiles aggregated", "rows", n, "window_start", start, "window_end", end)
	return n, nil
}
