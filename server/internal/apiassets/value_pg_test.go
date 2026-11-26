package apiassets

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestRefreshAssetValuesMalformedComputedAtPGIntegration(t *testing.T) {
	dsn := os.Getenv("APIASSETS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("APIASSETS_TEST_PG_DSN not set, skipping PG integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	appID := uuid.New()
	appCode := "val-malformed-" + appID.String()[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO applications (id, code, name) VALUES ($1, $2, $3)`,
		appID, appCode, "Asset Value Malformed Timestamp Test"); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_endpoints WHERE application_id = $1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id = $1`, appID)
	})

	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// 1) asset_value_computed_at IS NULL + 畸形 computed_at = 'not-a-date'
	// 2) asset_value_computed_at IS NULL + 前缀欺骗畸形值 '2026-11-25Tnot-a-date'
	// 3) asset_value_computed_at IS NULL + 非闰年 02-29 '2026-02-29T10:00:00Z'
	// 4) asset_value_computed_at IS NULL + 0000 年 '0000-01-01T00:00:00Z'
	// 5) asset_value_computed_at IS NULL + 超范围时区偏移 '2026-11-25T10:00:00+16:00'
	// 6) asset_value_computed_at IS NULL + 无 computed_at 字段 '{}'
	// 7) asset_value_computed_at IS NULL + 合法边界时区 '+15:59' 且晚于 last_seen_at（不应重算）
	// 8) asset_value_computed_at IS NULL + 合法闰年 02-29 '2024-02-29T12:00:00Z' 且晚于 last_seen_at（不应重算）
	// 9) asset_value_computed_at IS NULL + 合法晚于 last_seen_at 的 RFC3339（不应重算）
	beforeOffset1559 := time.Date(2026, 11, 24, 18, 0, 0, 0, time.UTC)
	beforeLeap2024 := time.Date(2024, 2, 29, 11, 0, 0, 0, time.UTC)
	seedRows := []struct {
		path    string
		explain string
		seenAt  time.Time
		wantHit bool
	}{
		{"/val-test/not-a-date", `{"computed_at":"not-a-date"}`, past, true},
		{"/val-test/prefix-bad", `{"computed_at":"2026-11-25Tnot-a-date"}`, past, true},
		{"/val-test/non-leap-feb29", `{"computed_at":"2026-02-29T10:00:00Z"}`, past, true},
		{"/val-test/year-zero", `{"computed_at":"0000-01-01T00:00:00Z"}`, past, true},
		{"/val-test/tz-plus16", `{"computed_at":"2026-11-25T10:00:00+16:00"}`, past, true},
		{"/val-test/empty-json", `{}`, past, true},
		{"/val-test/valid-tz-1559", `{"computed_at":"2026-11-25T10:00:00+15:59"}`, beforeOffset1559, false},
		{"/val-test/valid-leap-2024", `{"computed_at":"2024-02-29T12:00:00Z"}`, beforeLeap2024, false},
		{"/val-test/valid-fresh", `{"computed_at":"` + future.Format(time.RFC3339Nano) + `"}`, past, false},
	}

	ids := make(map[string]uuid.UUID, len(seedRows))
	for _, r := range seedRows {
		id := uuid.New()
		ids[r.path] = id
		key := "GET " + r.path
		if _, err := pool.Exec(ctx, `
INSERT INTO api_endpoints (
  id, application_id, host, http_method, normalized_path, raw_path_example, endpoint_key,
  is_api, asset_status, asset_value_explain, asset_value_computed_at, last_seen_at
) VALUES ($1, $2, 'val-test.local', 'GET', $3, $3, $4, TRUE, 'DISCOVERED', $5::jsonb, NULL, $6)`,
			id, appID, r.path, key, r.explain, r.seenAt); err != nil {
			t.Fatalf("seed endpoint %s: %v", r.path, err)
		}
	}

	store := NewStore(pool)
	// 用足够大的 limit 覆盖可能存在的其他待刷新行，至少不得在畸形 JSONB 上报错
	if _, err := store.RefreshAssetValues(ctx, 1000); err != nil {
		t.Fatalf("RefreshAssetValues must not crash on malformed computed_at: %v", err)
	}

	for _, r := range seedRows {
		var computedAt *time.Time
		if err := pool.QueryRow(ctx, `SELECT asset_value_computed_at FROM api_endpoints WHERE id = $1`, ids[r.path]).Scan(&computedAt); err != nil {
			t.Fatalf("query %s: %v", r.path, err)
		}
		if r.wantHit && computedAt == nil {
			t.Fatalf("endpoint %s should have been healed with non-nil asset_value_computed_at", r.path)
		}
		if !r.wantHit && computedAt != nil {
			t.Fatalf("endpoint %s had fresh explain computed_at and should not have been refreshed, got %v", r.path, *computedAt)
		}
	}
}
