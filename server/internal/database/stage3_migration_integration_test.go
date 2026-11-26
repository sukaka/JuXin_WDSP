package database_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/agents"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/ainoise"
	"github.com/jiuzhang-waf/server/internal/analytics"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/partitions"
	"github.com/jiuzhang-waf/server/internal/reports"
	"github.com/jiuzhang-waf/server/internal/securityevents"
	"github.com/jiuzhang-waf/server/internal/settings"
	"github.com/jiuzhang-waf/server/internal/tlssessions"
)

func requireStage3PGPool(t *testing.T, timeZone string) (*pgxpool.Pool, string) {
	t.Helper()
	baseDSN := os.Getenv("DATABASE_TEST_PG_DSN")
	if baseDSN == "" {
		baseDSN = os.Getenv("STAGE3_TEST_PG_DSN")
	}
	if baseDSN == "" {
		t.Skip("DATABASE_TEST_PG_DSN / STAGE3_TEST_PG_DSN not set, skipping Stage 3 PG integration test")
	}

	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, baseDSN)
	if err != nil {
		t.Fatalf("pgxpool.New admin: %v", err)
	}
	t.Cleanup(adminPool.Close)

	dbName := "stage3_it_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	if _, err := adminPool.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, dbName)); err != nil {
		t.Fatalf("create temp db %s: %v", dbName, err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(),
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, dbName)
		_, _ = adminPool.Exec(context.Background(), fmt.Sprintf(`DROP DATABASE IF EXISTS %s`, dbName))
	})

	u, err := url.Parse(baseDSN)
	if err != nil {
		t.Fatalf("parse dsn: %v", err)
	}
	u.Path = "/" + dbName
	cfg, err := pgxpool.ParseConfig(u.String())
	if err != nil {
		t.Fatalf("parse temp db config: %v", err)
	}
	if timeZone != "" {
		if cfg.ConnConfig.RuntimeParams == nil {
			cfg.ConnConfig.RuntimeParams = map[string]string{}
		}
		cfg.ConnConfig.RuntimeParams["TimeZone"] = timeZone
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect temp db %s: %v", dbName, err)
	}
	t.Cleanup(pool.Close)
	return pool, u.String()
}

func copyMigrationsUpTo(t *testing.T, srcDir, dstDir string, maxVersion int) {
	t.Helper()
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		t.Fatalf("read migrations dir %s: %v", srcDir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || len(name) < 6 {
			continue
		}
		ver, err := strconv.Atoi(name[:6])
		if err != nil || ver > maxVersion {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(srcDir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(dstDir, name), raw, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func TestStage3Migration000244UpDownIdempotencyAndPreseededRows(t *testing.T) {
	pool, _ := requireStage3PGPool(t, "Asia/Shanghai")
	ctx := context.Background()

	mig242Dir := t.TempDir()
	copyMigrationsUpTo(t, "../../migrations", mig242Dir, 242)
	if err := database.Migrate(ctx, pool, mig242Dir, "up"); err != nil {
		t.Fatalf("migrate 000001->000242: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	recentTS := now.Add(-2 * time.Hour)
	oldDayTS := now.Add(-48 * time.Hour)
	// Outside 000006's fixed 2026_07/2026_08 partitions -> lands in *_default before 000243.
	defaultMonthTS := now.AddDate(0, -1, 0)
	expiredMonthTS := now.AddDate(0, -7, 0)

	agentID := uuid.New()
	credHash1 := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(ctx, `
INSERT INTO agents (agent_id, hostname, last_status, credential_hash)
VALUES ($1, 'stage3-test-host', 'ONLINE', $2)`,
		agentID, credHash1); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	// Seed security_events (default partition pre-000243) and access_control_events (default partition pre-000243).
	secID1, secID2 := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO security_events (id, request_id, occurred_at, domain, attack_type, severity, action)
VALUES ($1, 'sec-def-1', $2, 'app.test', 'SQL_INJECTION', 'CRITICAL', 'BLOCK'),
       ($3, 'sec-def-2', $4, 'app.test', 'XSS', 'HIGH', 'BLOCK')`,
		secID1, defaultMonthTS, secID2, expiredMonthTS); err != nil {
		t.Fatalf("seed security_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO access_control_events (id, request_id, occurred_at, client_ip, event_type, action)
VALUES ($1, 'ac-def-1', $2, '192.0.2.10', 'IP_DENY_MATCH', 'DENY'),
       ($3, 'ac-def-2', $4, '192.0.2.11', 'CC_REQUEST_REJECTED', 'REJECT')`,
		uuid.New(), defaultMonthTS, uuid.New(), expiredMonthTS); err != nil {
		t.Fatalf("seed access_control_events: %v", err)
	}

	// Seed all 11 append-only tables.
	if _, err := pool.Exec(ctx, `
INSERT INTO access_logs (occurred_at, request_id, domain, request_method, request_uri, response_status, waf_action)
VALUES ($1, 'al-seed-1', 'a.test', 'GET', '/1', 200, 'ALLOW'),
       ($2, 'al-seed-2', 'a.test', 'POST', '/2', 403, 'BLOCK')`,
		recentTS, oldDayTS); err != nil {
		t.Fatalf("seed access_logs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO tls_handshake_events (occurred_at, gateway_node_id, sni, detected_protocol, action)
VALUES ($1, 'gw-1', 'a.test', 'TLS1.3', 'ALLOWED'),
       ($2, 'gw-1', 'b.test', 'TLS1.2', 'ALLOWED')`,
		recentTS, oldDayTS); err != nil {
		t.Fatalf("seed tls_handshake_events: %v", err)
	}
	var httpSeedMaxID, flowSeedMaxID int64
	if err := pool.QueryRow(ctx, `
INSERT INTO agent_http_events (agent_id, flow_id, ts, direction, tls_visibility, method, host, uri, event_id)
VALUES ($1, 'f1', $2, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/1', 'ev-seed-1'),
       ($1, 'f2', $3, 'ingress', 'PLAINTEXT', 'POST', 'a.test', '/2', 'ev-seed-2')
RETURNING id`, agentID, recentTS, oldDayTS).Scan(&httpSeedMaxID); err != nil {
		t.Fatalf("seed agent_http_events: %v", err)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO agent_flow_events (agent_id, ts, event_type, flow_id)
VALUES ($1, $2, 'request', 'fl-1'),
       ($1, $3, 'flow_end', 'fl-2')
RETURNING id`, agentID, recentTS, oldDayTS).Scan(&flowSeedMaxID); err != nil {
		t.Fatalf("seed agent_flow_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value)
VALUES ($1, 'waf_req', '{"app":"a"}', 10),
       ($2, 'waf_req', '{"app":"a"}', 20)`,
		recentTS.Truncate(time.Minute), oldDayTS.Truncate(time.Minute)); err != nil {
		t.Fatalf("seed metric_minute_aggregates: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO source_ip_summaries (bucket_start, client_ip, waf_events)
VALUES ($1, '192.0.2.10', 3),
       ($2, '192.0.2.11', 4)`,
		recentTS.Truncate(time.Minute), oldDayTS.Truncate(time.Minute)); err != nil {
		t.Fatalf("seed source_ip_summaries: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO uri_security_summaries (bucket_start, application_code, uri_path, waf_events)
VALUES ($1, 'app1', '/login', 5),
       ($2, 'app1', '/api', 6)`,
		recentTS.Truncate(time.Minute), oldDayTS.Truncate(time.Minute)); err != nil {
		t.Fatalf("seed uri_security_summaries: %v", err)
	}

	apiEv1, apiEv2 := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO api_runtime_events (id, request_id, endpoint_key, occurred_at)
VALUES ($1, 'api-seed-1', 'GET /v1/a', $2),
       ($3, 'api-seed-2', 'GET /v1/b', $4)`,
		apiEv1, recentTS, apiEv2, expiredMonthTS); err != nil {
		t.Fatalf("seed api_runtime_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_authz_candidate_event_receipts (event_id, processed_at)
VALUES ($1, $2), ($3, $4)`,
		apiEv1, recentTS, apiEv2, expiredMonthTS); err != nil {
		t.Fatalf("seed api_authz_candidate_event_receipts: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO security_event_matches (event_id, event_occurred_at, rule_id, rule_name)
VALUES ($1, $2, 942100, 'SQLi'),
       ($3, $4, 941100, 'XSS')`,
		secID1, defaultMonthTS, secID2, expiredMonthTS); err != nil {
		t.Fatalf("seed security_event_matches: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_behavior_events (identity_key, occurred_at, rule_code, rule_version, signal)
VALUES ('ik-1', $1, 'R1', 'v1', 'SIG_A'),
       ('ik-2', $2, 'R2', 'v1', 'SIG_B')`,
		recentTS, expiredMonthTS); err != nil {
		t.Fatalf("seed identity_behavior_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO coverage_observations (request_id, detector, phase, status, occurred_at)
VALUES ('cov-1', 'sqli', 'request', 'COVERED', $1),
       ('cov-2', 'xss', 'request', 'COVERED', $2)`,
		recentTS, expiredMonthTS); err != nil {
		t.Fatalf("seed coverage_observations: %v", err)
	}

	// Apply 000243 + 000244.
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up to 000244: %v", err)
	}

	all13Tables := []string{
		"security_events", "access_control_events", "security_event_matches",
		"api_runtime_events", "identity_behavior_events", "coverage_observations",
		"access_logs", "tls_handshake_events", "agent_http_events", "agent_flow_events",
		"metric_minute_aggregates", "source_ip_summaries", "uri_security_summaries",
	}
	for _, tbl := range all13Tables {
		var relkind string
		if err := pool.QueryRow(ctx, `
SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relname = $1`, tbl).Scan(&relkind); err != nil {
			t.Fatalf("query relkind %s: %v", tbl, err)
		}
		if relkind != "p" {
			t.Fatalf("%s relkind = %q, want 'p'", tbl, relkind)
		}
		var defCnt int
		if err := pool.QueryRow(ctx, `
SELECT count(*) FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_class p ON p.oid = i.inhparent
JOIN pg_namespace n ON n.oid = p.relnamespace
WHERE n.nspname = current_schema() AND p.relname = $1
  AND pg_get_expr(c.relpartbound, c.oid) = 'DEFAULT'`, tbl).Scan(&defCnt); err != nil {
			t.Fatalf("check DEFAULT partition on %s: %v", tbl, err)
		}
		if defCnt != 0 {
			t.Fatalf("%s still has %d DEFAULT partitions", tbl, defCnt)
		}
		var cnt int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, tbl)).Scan(&cnt); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if cnt != 2 {
			t.Fatalf("%s row count = %d, want 2", tbl, cnt)
		}
	}

	// Verify preserved & newly added indexes.
	for _, idxName := range []string{
		"idx_api_runtime_events_trace_id",
		"idx_api_runtime_events_node",
		"idx_api_authorization_decisions_occurred",
		"idx_access_logs_client_ip_occurred",
		"idx_security_event_matches_effect_stats",
	} {
		var exists bool
		if err := pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM pg_indexes WHERE schemaname = current_schema() AND indexname = $1)`, idxName).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected index %s to exist (exists=%v err=%v)", idxName, exists, err)
		}
	}

	// Verify BIGSERIAL sequences advance cleanly past pre-seeded IDs.
	var nextHTTPID, nextFlowID int64
	if err := pool.QueryRow(ctx, `
INSERT INTO agent_http_events (agent_id, flow_id, ts, direction, tls_visibility, method, host, uri)
VALUES ($1, 'f-next', $2, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/next')
RETURNING id`, agentID, now).Scan(&nextHTTPID); err != nil {
		t.Fatalf("insert next agent_http_events: %v", err)
	}
	if nextHTTPID <= httpSeedMaxID {
		t.Fatalf("agent_http_events seq did not advance: next=%d <= seedMax=%d", nextHTTPID, httpSeedMaxID)
	}
	if err := pool.QueryRow(ctx, `
INSERT INTO agent_flow_events (agent_id, ts, event_type, flow_id)
VALUES ($1, $2, 'request', 'fl-next')
RETURNING id`, agentID, now).Scan(&nextFlowID); err != nil {
		t.Fatalf("insert next agent_flow_events: %v", err)
	}
	if nextFlowID <= flowSeedMaxID {
		t.Fatalf("agent_flow_events seq did not advance: next=%d <= seedMax=%d", nextFlowID, flowSeedMaxID)
	}

	// Verify inbound FK on api_authz_candidate_event_receipts was dropped.
	var fkCount int
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM pg_constraint con
JOIN pg_class src ON src.oid = con.conrelid
JOIN pg_class dst ON dst.oid = con.confrelid
WHERE con.contype = 'f' AND src.relname = 'api_authz_candidate_event_receipts' AND dst.relname = 'api_runtime_events'`).Scan(&fkCount); err != nil {
		t.Fatalf("query inbound fk: %v", err)
	}
	if fkCount != 0 {
		t.Fatalf("expected api_authz_candidate_event_receipts FK to be dropped, got %d", fkCount)
	}

	// Re-exec 000244.up.sql directly for idempotency.
	up244SQL, err := os.ReadFile("../../migrations/000244_append_only_partitions_and_uuidv7.up.sql")
	if err != nil {
		t.Fatalf("read 000244 up sql: %v", err)
	}
	if _, err := pool.Exec(ctx, string(up244SQL)); err != nil {
		t.Fatalf("re-run 000244.up.sql idempotency failed: %v", err)
	}

	// Seed cross-day duplicates and an orphan receipt before rolling back 000244.
	if _, err := pool.Exec(ctx, `
INSERT INTO access_logs (occurred_at, request_id, domain)
VALUES ($1, 'cross-day-req', 'a.test'), ($2, 'cross-day-req', 'a.test')`,
		now, now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("seed cross-day access_logs dup: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO agent_http_events (agent_id, flow_id, ts, direction, tls_visibility, method, host, uri, event_id)
VALUES ($1, 'f-dup1', $2, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/1', 'cross-day-ev'),
       ($1, 'f-dup2', $3, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/2', 'cross-day-ev')`,
		agentID, now, now.Add(-24*time.Hour)); err != nil {
		t.Fatalf("seed cross-day agent_http_events dup: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_authz_candidate_event_receipts (event_id) VALUES ($1)`, uuid.New()); err != nil {
		t.Fatalf("seed orphan receipt: %v", err)
	}

	// Rollback 000244.
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("rollback 000244: %v", err)
	}
	for _, tbl := range all13Tables[2:] {
		var relkind string
		if err := pool.QueryRow(ctx, `
SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relname = $1`, tbl).Scan(&relkind); err != nil {
			t.Fatalf("query relkind after down %s: %v", tbl, err)
		}
		if relkind != "r" {
			t.Fatalf("%s relkind after 000244 down = %q, want 'r'", tbl, relkind)
		}
	}
	if err := pool.QueryRow(ctx, `
SELECT count(*) FROM pg_constraint con
JOIN pg_class src ON src.oid = con.conrelid
JOIN pg_class dst ON dst.oid = con.confrelid
WHERE con.contype = 'f' AND src.relname = 'api_authz_candidate_event_receipts' AND dst.relname = 'api_runtime_events'`).Scan(&fkCount); err != nil {
		t.Fatalf("query fk after 000244 down: %v", err)
	}
	if fkCount != 1 {
		t.Fatalf("expected api_authz_candidate_event_receipts FK restored after 000244 down, got %d", fkCount)
	}

	// Rollback 000243 -> verify *_default restored cleanly.
	if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
		t.Fatalf("rollback 000243: %v", err)
	}
	for _, defTbl := range []string{"security_events_default", "access_control_events_default"} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, defTbl).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected %s restored after 000243 down (exists=%v err=%v)", defTbl, exists, err)
		}
	}

	// Re-apply 000243 + 000244.
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("re-apply 000243+000244: %v", err)
	}
	for _, tbl := range all13Tables {
		var relkind string
		if err := pool.QueryRow(ctx, `
SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relname = $1`, tbl).Scan(&relkind); err != nil || relkind != "p" {
			t.Fatalf("after re-up %s relkind=%q err=%v", tbl, relkind, err)
		}
	}
}

func TestStage3PartitionManagerAndRetentionPG(t *testing.T) {
	pool, _ := requireStage3PGPool(t, "UTC")
	ctx := context.Background()

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	expiredDaily := now.AddDate(0, 0, -45)
	expiredMonthly := now.AddDate(0, -8, 0)
	recentTS := now.Add(-2 * time.Hour)

	agentID := uuid.New()
	credHash2 := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(ctx, `
INSERT INTO agents (agent_id, hostname, last_status, credential_hash)
VALUES ($1, 'stage3-ret-host', 'ONLINE', $2)`,
		agentID, credHash2); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	// Create expired partitions and insert rows into both expired and current partitions.
	createExpiredDaily := func(tbl string, ts time.Time) string {
		dayStart := ts.UTC().Truncate(24 * time.Hour)
		dayEnd := dayStart.Add(24 * time.Hour)
		pName := fmt.Sprintf("%s_%s", tbl, dayStart.Format("2006_01_02"))
		if _, err := pool.Exec(ctx, fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			pName, tbl, dayStart.Format("2006-01-02 15:04:05+00"), dayEnd.Format("2006-01-02 15:04:05+00"))); err != nil {
			t.Fatalf("create expired daily %s: %v", pName, err)
		}
		return pName
	}
	createExpiredMonthly := func(tbl string, ts time.Time) string {
		mStart := time.Date(ts.Year(), ts.Month(), 1, 0, 0, 0, 0, time.UTC)
		mEnd := mStart.AddDate(0, 1, 0)
		pName := fmt.Sprintf("%s_%s", tbl, mStart.Format("2006_01"))
		if _, err := pool.Exec(ctx, fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s FOR VALUES FROM ('%s') TO ('%s')`,
			pName, tbl, mStart.Format("2006-01-02 15:04:05+00"), mEnd.Format("2006-01-02 15:04:05+00"))); err != nil {
			t.Fatalf("create expired monthly %s: %v", pName, err)
		}
		return pName
	}

	expAccessLogPart := createExpiredDaily("access_logs", expiredDaily)
	expTLSPart := createExpiredDaily("tls_handshake_events", expiredDaily)
	expHTTPPart := createExpiredDaily("agent_http_events", expiredDaily)
	expAPIRuntimePart := createExpiredMonthly("api_runtime_events", expiredMonthly)
	expMatchesPart := createExpiredMonthly("security_event_matches", expiredMonthly)

	if _, err := pool.Exec(ctx, `
INSERT INTO access_logs (occurred_at, request_id, domain) VALUES ($1, 'al-exp', 'a.test'), ($2, 'al-keep', 'a.test')`,
		expiredDaily, recentTS); err != nil {
		t.Fatalf("seed access_logs: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO tls_handshake_events (occurred_at, gateway_node_id, sni, detected_protocol, action)
VALUES ($1, 'gw', 'exp.test', 'TLS1.2', 'ALLOWED'), ($2, 'gw', 'keep.test', 'TLS1.3', 'ALLOWED')`,
		expiredDaily, recentTS); err != nil {
		t.Fatalf("seed tls_handshake_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO agent_http_events (agent_id, flow_id, ts, direction, tls_visibility, method, host, uri, created_at)
VALUES ($1, 'exp', $2, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/exp', $2),
       ($1, 'keep', $3, 'ingress', 'PLAINTEXT', 'GET', 'a.test', '/keep', $3)`,
		agentID, expiredDaily, recentTS); err != nil {
		t.Fatalf("seed agent_http_events: %v", err)
	}

	// Verify legacy row-by-row retention cleaners skip cleanly when relkind = 'p',
	// while HTTPEventSweeper still cleans expired agent_capture_overrides.
	if n, err := accesslogs.NewRetentionCleaner(pool, settings.NewService(pool)).CleanOnce(ctx); err != nil || n != 0 {
		t.Fatalf("accesslogs.RetentionCleaner on relkind='p' = (%d, %v), want (0, nil)", n, err)
	}
	if n, err := tlssessions.NewRetentionCleaner(pool, settings.NewService(pool)).CleanOnce(ctx); err != nil || n != 0 {
		t.Fatalf("tlssessions.RetentionCleaner on relkind='p' = (%d, %v), want (0, nil)", n, err)
	}
	agentStore := agents.NewStore(pool)
	if n, err := agentStore.DeleteExpiredHTTPEvents(ctx, now); err != nil || n != 0 {
		t.Fatalf("agents.DeleteExpiredHTTPEvents on relkind='p' = (%d, %v), want (0, nil)", n, err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO agent_capture_overrides (agent_id, match, capture_level, expires_at, created_by)
VALUES ($1, '{"host":"exp.test"}'::jsonb, 'L2', $2, 'test'),
       ($1, '{"host":"keep.test"}'::jsonb, 'L2', $3, 'test')`,
		agentID, now.Add(-40*24*time.Hour), now.Add(24*time.Hour)); err != nil {
		t.Fatalf("seed agent_capture_overrides: %v", err)
	}
	sweeperDeleted, err := agents.NewHTTPEventSweeper(agentStore).SweepOnce(ctx)
	if err != nil || sweeperDeleted != 1 {
		t.Fatalf("HTTPEventSweeper.SweepOnce = (%d, %v), want (1, nil) for expired capture override", sweeperDeleted, err)
	}

	// Seed the 5 CleanupPolicy tables (expired + recent) + operation_audits (must remain untouched).
	expReceiptEventID, keepReceiptEventID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO api_authz_candidate_event_receipts (event_id, processed_at)
VALUES ($1, $2), ($3, $4)`,
		expReceiptEventID, now.AddDate(0, 0, -200), keepReceiptEventID, recentTS); err != nil {
		t.Fatalf("seed receipts: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_schema_violations (id, request_id, violation_type, occurred_at)
VALUES ($1, 'v-exp', 'MISSING_FIELD', $2), ($3, 'v-keep', 'MISSING_FIELD', $4)`,
		uuid.New(), now.AddDate(0, 0, -100), uuid.New(), recentTS); err != nil {
		t.Fatalf("seed api_schema_violations: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_authorization_decisions (id, decision_id, endpoint_key, decision, occurred_at)
VALUES ($1, $2, 'GET /1', 'ALLOW', $3), ($4, $5, 'GET /2', 'ALLOW', $6)`,
		uuid.New(), uuid.New(), now.AddDate(0, 0, -100), uuid.New(), uuid.New(), recentTS); err != nil {
		t.Fatalf("seed api_authorization_decisions: %v", err)
	}
	identID := uuid.New()
	if _, err := pool.Exec(ctx, `
INSERT INTO client_identity (id, identity_key) VALUES ($1, 'stage3-ret-ident')`, identID); err != nil {
		t.Fatalf("seed client_identity: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO behavior_statistics (id, identity_id, window_type, window_start)
VALUES ($1, $2, '1m', $3), ($4, $2, '1m', $5)`,
		uuid.New(), identID, now.AddDate(0, 0, -100), uuid.New(), recentTS); err != nil {
		t.Fatalf("seed behavior_statistics: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO agent_api_observation_asset_events (agent_id, event_id, endpoint_key, projected_at)
VALUES ($1, 'ae-exp', 'GET /1', $2), ($1, 'ae-keep', 'GET /2', $3)`,
		agentID, now.AddDate(0, 0, -40), recentTS); err != nil {
		t.Fatalf("seed agent_api_observation_asset_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO operation_audits (occurred_at, module, action, result, previous_hash, record_hash)
VALUES ($1, 'AUTH', 'LOGIN', 'SUCCESS', 'prev', 'rec-exp'), ($2, 'AUTH', 'LOGOUT', 'SUCCESS', 'rec-exp', 'rec-keep')`,
		now.AddDate(-2, 0, 0), recentTS); err != nil {
		t.Fatalf("seed operation_audits: %v", err)
	}

	// Run PartitionManager with DefaultPartitionPolicies & DefaultCleanupPolicies.
	mgr := partitions.NewManager(pool, settings.NewService(pool), partitions.WithBatchSleep(0))
	res, err := mgr.RunOnce(ctx)
	if err != nil {
		t.Fatalf("PartitionManager.RunOnce: %v", err)
	}
	if res.PartitionsDropped < 5 {
		t.Fatalf("PartitionsDropped = %d, want >= 5", res.PartitionsDropped)
	}
	if res.RowsCleaned != 5 {
		t.Fatalf("RowsCleaned = %d, want 5", res.RowsCleaned)
	}

	for _, droppedPart := range []string{expAccessLogPart, expTLSPart, expHTTPPart, expAPIRuntimePart, expMatchesPart} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, droppedPart).Scan(&exists); err != nil || exists {
			t.Fatalf("expired partition %s should be dropped (exists=%v err=%v)", droppedPart, exists, err)
		}
	}

	// Verify future partitions pre-created (+14d daily, +3m monthly).
	futureDaily := fmt.Sprintf("access_logs_%s", now.AddDate(0, 0, 14).Format("2006_01_02"))
	futureMonthly := fmt.Sprintf("coverage_observations_%s", time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, 3, 0).Format("2006_01"))
	for _, fp := range []string{futureDaily, futureMonthly} {
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, fp).Scan(&exists); err != nil || !exists {
			t.Fatalf("expected future partition %s to exist (exists=%v err=%v)", fp, exists, err)
		}
	}

	// Verify cleanup tables kept recent rows and operation_audits remained completely untouched.
	for tbl, want := range map[string]int{
		"api_authz_candidate_event_receipts": 1,
		"api_schema_violations":              1,
		"api_authorization_decisions":        1,
		"behavior_statistics":                1,
		"agent_api_observation_asset_events": 1,
		"operation_audits":                   2,
	} {
		var cnt int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FROM %s`, tbl)).Scan(&cnt); err != nil {
			t.Fatalf("count %s: %v", tbl, err)
		}
		if cnt != want {
			t.Fatalf("%s count = %d, want %d", tbl, cnt, want)
		}
	}
}

func TestStage3UUIDv7AndGoStoreRoundTripsPG(t *testing.T) {
	pool, _ := requireStage3PGPool(t, "UTC")
	ctx := context.Background()

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	// 1. Verify PG uuid_generate_v7() version, variant, and strict millisecond monotonicity.
	var u1Str, u2Str string
	if err := pool.QueryRow(ctx, `SELECT uuid_generate_v7()::text`).Scan(&u1Str); err != nil {
		t.Fatalf("uuid_generate_v7 #1: %v", err)
	}
	if _, err := pool.Exec(ctx, `SELECT pg_sleep(0.002)`); err != nil {
		t.Fatalf("pg_sleep: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT uuid_generate_v7()::text`).Scan(&u2Str); err != nil {
		t.Fatalf("uuid_generate_v7 #2: %v", err)
	}
	u1, err := uuid.Parse(u1Str)
	if err != nil {
		t.Fatalf("parse u1: %v", err)
	}
	u2, err := uuid.Parse(u2Str)
	if err != nil {
		t.Fatalf("parse u2: %v", err)
	}
	if u1.Version() != 7 || u1.Variant() != uuid.RFC4122 || u2.Version() != 7 || u2.Variant() != uuid.RFC4122 {
		t.Fatalf("unexpected UUIDv7 metadata: u1=(v%d,%v) u2=(v%d,%v)", u1.Version(), u1.Variant(), u2.Version(), u2.Variant())
	}
	var lt bool
	if err := pool.QueryRow(ctx, `SELECT $1::uuid < $2::uuid`, u1Str, u2Str).Scan(&lt); err != nil || !lt {
		t.Fatalf("expected u1 < u2 in PG B-tree ordering: u1=%s u2=%s lt=%v err=%v", u1Str, u2Str, lt, err)
	}

	now := time.Now().UTC().Truncate(time.Second)

	// 2. apiruntime.Store.SavePrimary + List (UUIDv7 + replay merge).
	apiStore := apiruntime.NewStore(pool)
	apiReqID := "api-rt-" + uuid.NewString()
	apiEv := &apiruntime.PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:   apiReqID,
			EndpointKey: "GET /v1/orders",
			FinalAction: "ALLOW",
			OccurredAt:  now,
		},
	}
	if err := apiStore.SavePrimary(ctx, apiEv); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	parsedAPIID, err := uuid.Parse(apiEv.ID)
	if err != nil || parsedAPIID.Version() != 7 || parsedAPIID.Variant() != uuid.RFC4122 {
		t.Fatalf("SavePrimary did not generate UUIDv7: id=%q err=%v", apiEv.ID, err)
	}
	apiReplay := *apiEv
	apiReplay.FinalDecision = json.RawMessage(`{"completion_status":"COMPLETED","security_action":"NONE"}`)
	if err := apiStore.SavePrimary(ctx, &apiReplay); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}
	apiList, apiTotal, err := apiStore.List(ctx, 1, 20)
	if err != nil || apiTotal != 1 || len(apiList) != 1 {
		t.Fatalf("apiStore.List = (%d, %d, %v)", len(apiList), apiTotal, err)
	}

	// 3. accesslogs.Store.Insert (ON CONFLICT (request_id, occurred_at)) + List + GetByID.
	alStore := accesslogs.NewStore(pool)
	alReqID := "al-rt-" + uuid.NewString()
	alEntry := &accesslogs.LogEntry{
		OccurredAt:     now,
		RequestID:      alReqID,
		Domain:         "api.test",
		RequestMethod:  "GET",
		RequestURI:     "/v1/orders",
		ResponseStatus: 200,
	}
	ins1, err := alStore.Insert(ctx, alEntry)
	if err != nil || !ins1 {
		t.Fatalf("accesslogs Insert #1: (%v, %v)", ins1, err)
	}
	ins2, err := alStore.Insert(ctx, alEntry)
	if err != nil || ins2 {
		t.Fatalf("accesslogs Insert replay: (%v, %v), want (false, nil)", ins2, err)
	}
	// Empty request_id allowed multiple times.
	for i := 0; i < 2; i++ {
		if ok, err := alStore.Insert(ctx, &accesslogs.LogEntry{OccurredAt: now, Domain: "api.test"}); err != nil || !ok {
			t.Fatalf("accesslogs empty request_id #%d: (%v, %v)", i, ok, err)
		}
	}
	alItems, alTotal, err := alStore.List(ctx, accesslogs.ListFilter{RequestID: alReqID})
	if err != nil || alTotal != 1 || len(alItems) != 1 {
		t.Fatalf("accesslogs.List = (%d, %d, %v)", len(alItems), alTotal, err)
	}
	gotAL, err := alStore.GetByID(ctx, alItems[0].ID)
	if err != nil || gotAL.RequestID != alReqID {
		t.Fatalf("accesslogs.GetByID = (%+v, %v)", gotAL, err)
	}

	// 4. agents.Store.InsertHTTPEvents (CopyFrom) + InsertHTTPEventsV2 (ON CONFLICT (agent_id, event_id, ts)).
	agentID := uuid.New()
	credHash3 := strings.ReplaceAll(uuid.NewString(), "-", "") + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := pool.Exec(ctx, `
INSERT INTO agents (agent_id, hostname, last_status, credential_hash)
VALUES ($1, 'stage3-rt-host', 'ONLINE', $2)`,
		agentID, credHash3); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	agStore := agents.NewStore(pool)
	reqTS := float64(now.Unix())
	respTS := reqTS + 0.01
	lat := int64(10)
	if err := agStore.InsertHTTPEvents(ctx, agentID, []agents.HTTPRecord{{
		FlowID:        "flow-v1",
		RequestTS:     reqTS,
		ResponseTS:    &respTS,
		LatencyMS:     &lat,
		SrcIP:         "10.0.0.1",
		SrcPort:       12345,
		DstIP:         "10.0.0.2",
		DstPort:       80,
		Direction:     "ingress",
		TLSVisibility: "PLAINTEXT",
		Request:       agents.HTTPRequestPart{Method: "GET", Scheme: "http", Host: "api.test", URI: "/v1/ping"},
	}}); err != nil {
		t.Fatalf("InsertHTTPEvents v1 CopyFrom: %v", err)
	}
	v2Rec := agents.HTTPRecordV2{
		EventID:             "ev-v2-1",
		FlowID:              "flow-v2",
		RequestTS:           reqTS,
		ResponseTS:          &respTS,
		LatencyMS:           &lat,
		CollectionTS:        reqTS,
		SrcIP:               "10.0.0.1",
		SrcPort:             12346,
		DstIP:               "10.0.0.2",
		DstPort:             80,
		Direction:           "ingress",
		TLSVisibility:       "PLAINTEXT",
		SourceType:          agents.SourceTypePassiveHTTP1,
		ObservedHTTPVersion: agents.HTTPVersion11,
		AssociationState:    agents.AssocStateComplete,
		Request:             agents.HTTPRequestPartV2{Method: "POST", Scheme: "http", Host: "api.test", URI: "/v2/orders"},
	}
	accepted, dups, err := agStore.InsertHTTPEventsV2(ctx, agentID, []agents.HTTPRecordV2{v2Rec, v2Rec}, now)
	if err != nil || len(accepted) != 1 || dups != 1 {
		t.Fatalf("InsertHTTPEventsV2 = (%v, %d, %v), want ([0], 1, nil)", accepted, dups, err)
	}
	httpList, httpTotal, err := agStore.ListHTTPEvents(ctx, agentID, agents.HTTPEventFilter{
		Page: agents.PageParams{Page: 1, PageSize: 20},
	})
	if err != nil || httpTotal != 2 || len(httpList) != 2 {
		t.Fatalf("ListHTTPEvents = (%d, %d, %v)", len(httpList), httpTotal, err)
	}
	if _, err := agStore.GetHTTPEvent(ctx, agentID, httpList[0].ID); err != nil {
		t.Fatalf("GetHTTPEvent: %v", err)
	}

	// 5. tlssessions.Store.Insert + List + Summary.
	tlsStore := tlssessions.NewStore(pool)
	if err := tlsStore.Insert(ctx, &tlssessions.HandshakeEntry{
		OccurredAt:         now,
		GatewayNodeID:      "gw-1",
		SNI:                "api.test",
		ClientIP:           "192.0.2.55",
		ClientPort:         44444,
		ServerPort:         443,
		DetectedProtocol:   tlssessions.ProtoTLS13,
		NegotiatedProtocol: tlssessions.ProtoTLS13,
		Action:             tlssessions.ActionAllowed,
	}); err != nil {
		t.Fatalf("tlssessions.Insert: %v", err)
	}
	tlsItems, tlsTotal, err := tlsStore.List(ctx, tlssessions.ListFilter{})
	if err != nil || tlsTotal != 1 || len(tlsItems) != 1 {
		t.Fatalf("tlssessions.List = (%d, %d, %v)", len(tlsItems), tlsTotal, err)
	}
	if tlsItems[0].ID.Version() != 7 {
		t.Fatalf("tlssessions DB default ID version = %d, want 7", tlsItems[0].ID.Version())
	}
	tlsSummary, err := tlsStore.Summary(ctx, tlssessions.SummaryFilter{})
	if err != nil || tlsSummary.TotalHandshakes != 1 {
		t.Fatalf("tlssessions.Summary = (%+v, %v)", tlsSummary, err)
	}

	// 6. securityevents.Store + analytics.Store + reports.Collector + ainoise.SQLEventSource + EXPLAIN partition pruning.
	secStore := securityevents.NewStore(pool)
	secEvt := &securityevents.NormalizedEvent{
		RequestID:    "sec-rt-" + uuid.NewString(),
		OccurredAt:   now,
		ClientIP:     "192.0.2.66",
		ConnectionIP: "192.0.2.66",
		Method:       "GET",
		URI:          "/search?q=1",
		Path:         "/search",
		Host:         "api.test",
		AttackType:   "SQL_INJECTION",
		Severity:     "CRITICAL",
		AnomalyScore: 10,
		Action:       "BLOCK",
		Matches: []securityevents.MatchInfo{{
			RuleID:      942100,
			RuleName:    "SQLi",
			RuleSource:  "OWASP_CRS",
			RuleVersion: "4.26.0",
			Severity:    "CRITICAL",
			Message:     "SQL Injection",
			Phase:       2,
		}},
	}
	secID, secIns, err := secStore.InsertEvent(ctx, secEvt)
	if err != nil || !secIns {
		t.Fatalf("securityevents.InsertEvent = (%s, %v, %v)", secID, secIns, err)
	}
	if secID.Version() != 7 {
		t.Fatalf("security_events DB default ID version = %d, want 7", secID.Version())
	}
	gotSec, gotMatches, err := secStore.GetByID(ctx, secID)
	if err != nil || gotSec == nil || len(gotMatches) != 1 {
		t.Fatalf("securityevents.GetByID = (%+v, len=%d, %v)", gotSec, len(gotMatches), err)
	}

	// Verify EXPLAIN partition pruning on security_event_matches.
	var planLines []string
	planRows, err := pool.Query(ctx,
		`EXPLAIN (FORMAT TEXT) SELECT rule_id FROM security_event_matches WHERE event_id = $1 AND event_occurred_at = $2`,
		secID, gotSec.OccurredAt)
	if err != nil {
		t.Fatalf("EXPLAIN security_event_matches: %v", err)
	}
	for planRows.Next() {
		var line string
		if err := planRows.Scan(&line); err != nil {
			planRows.Close()
			t.Fatalf("scan plan: %v", err)
		}
		planLines = append(planLines, line)
	}
	planRows.Close()
	planText := strings.Join(planLines, "\n")
	activeMatchPart := fmt.Sprintf("security_event_matches_%s", now.Format("2006_01"))
	if !strings.Contains(planText, activeMatchPart) {
		t.Fatalf("expected EXPLAIN plan to target active partition %s, got:\n%s", activeMatchPart, planText)
	}
	otherMonthPart := fmt.Sprintf("security_event_matches_%s", now.AddDate(0, 1, 0).Format("2006_01"))
	if strings.Contains(planText, otherMonthPart) {
		t.Fatalf("expected EXPLAIN plan to prune non-matching partition %s, got:\n%s", otherMonthPart, planText)
	}

	aggStore := aggregations.NewStore(pool)
	anStore := analytics.NewStore(pool, aggStore)
	if _, err := anStore.TopRules(ctx, analytics.Range{Start: now.Add(-time.Hour), End: now.Add(time.Hour)}, nil, 10); err != nil {
		t.Fatalf("analytics.TopRules: %v", err)
	}
	repCol := reports.NewCollector(pool, aggStore, nil)
	if _, err := repCol.Collect(ctx, reports.CollectInput{
		ReportType:   "DAILY",
		ContentScope: "WAF",
		Start:        now.Add(-time.Hour),
		End:          now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("reports.Collector.Collect: %v", err)
	}
	aiSrc := ainoise.NewEventSource(pool, true)
	wafInputs, err := aiSrc.FetchWAF(ctx, now.Add(-time.Hour), now.Add(time.Hour), 10)
	if err != nil || len(wafInputs) != 1 || wafInputs[0].RuleID == nil || *wafInputs[0].RuleID != 942100 {
		t.Fatalf("ainoise.FetchWAF = (%+v, %v)", wafInputs, err)
	}
}
