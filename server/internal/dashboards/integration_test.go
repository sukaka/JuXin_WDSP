package dashboards

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aggregations"
	"github.com/jiuzhang-waf/server/internal/cache"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/database"
	"github.com/jiuzhang-waf/server/internal/metrics"
)

func openIntegrationDeps(t *testing.T) (*pgxpool.Pool, *cache.Client) {
	t.Helper()
	pgDSN := strings.TrimSpace(os.Getenv("DASHBOARDS_TEST_PG_DSN"))
	valkeyAddr := strings.TrimSpace(os.Getenv("DASHBOARDS_TEST_VALKEY_ADDR"))
	if pgDSN == "" || valkeyAddr == "" {
		t.Skip("DASHBOARDS_TEST_PG_DSN or DASHBOARDS_TEST_VALKEY_ADDR not set, skipping integration test")
	}

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)

	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("database.Migrate up: %v", err)
	}

	host, portStr, err := net.SplitHostPort(valkeyAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", valkeyAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", portStr, err)
	}
	c, err := cache.New(ctx, config.CacheConfig{
		Host:     host,
		Port:     port,
		Password: os.Getenv("DASHBOARDS_TEST_VALKEY_PASSWORD"),
		DB:       14,
	})
	if err != nil {
		t.Fatalf("cache.New: %v", err)
	}
	if err := c.Redis().FlushDB(ctx).Err(); err != nil {
		_ = c.Close()
		t.Fatalf("FlushDB: %v", err)
	}
	t.Cleanup(func() {
		_ = c.Redis().FlushDB(context.Background()).Err()
		_ = c.Close()
	})
	return pool, c
}

func truncateDashboardTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `
TRUNCATE TABLE
  metric_minute_aggregates,
  metric_hour_aggregates,
  source_ip_summaries,
  uri_security_summaries,
  temporary_blocks,
  upstream_health_records,
  upstreams,
  application_certificates,
  certificates,
  applications,
  security_events,
  gateway_publish_tasks,
  report_jobs,
  system_health_snapshots,
  aggregation_jobs,
  operation_audits
RESTART IDENTITY CASCADE`)
	if err != nil {
		t.Fatalf("truncate dashboard tables: %v", err)
	}
}

func TestDashboardsPGAndValkeyIntegration(t *testing.T) {
	pool, valkeyClient := openIntegrationDeps(t)
	ctx := context.Background()

	truncateDashboardTables(t, pool)
	t.Cleanup(func() { truncateDashboardTables(t, pool) })

	store := NewStore(pool, aggregations.NewStore(pool))
	h := NewHandler(aggregations.NewStore(pool), pool)
	h.SetCache(valkeyClient)

	// ==================== 1. Empty DB Parity & JSON Slice Safety ====================
	t.Run("empty DB parity and non-nil slices", func(t *testing.T) {
		now := time.Now().UTC()
		dayStart, _ := TodayWindowUTC(now)

		today, err := store.TodayCounters(ctx, dayStart, now)
		if err != nil {
			t.Fatalf("TodayCounters empty: %v", err)
		}
		if *today != (TodayCounters{}) {
			t.Fatalf("TodayCounters empty = %+v, want zero", today)
		}

		audCnt, err := store.AuditCounters(ctx, dayStart, now)
		if err != nil {
			t.Fatalf("AuditCounters empty: %v", err)
		}
		if *audCnt != (AuditCounters{}) {
			t.Fatalf("AuditCounters empty = %+v, want zero", audCnt)
		}

		if comps, err := store.LatestComponentStatuses(ctx); err != nil || comps == nil || len(comps) != 0 {
			t.Fatalf("LatestComponentStatuses empty = (%#v, %v), want non-nil empty", comps, err)
		}
		if issues, err := store.ComponentIssues(ctx); err != nil || issues == nil || len(issues) != 0 {
			t.Fatalf("ComponentIssues empty = (%#v, %v), want non-nil empty", issues, err)
		}
		if gw, err := store.GatewayRuntime(ctx); err != nil || gw.Status != "UNKNOWN" {
			t.Fatalf("GatewayRuntime empty = (%+v, %v), want UNKNOWN", gw, err)
		}

		for _, r := range []string{"1h", "24h", "7d", "30d"} {
			rec := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range="+r, "empty-sec-"+r)
			if rec.Code != http.StatusOK {
				t.Fatalf("empty SecurityOverview(%s) status=%d body=%s", r, rec.Code, rec.Body.String())
			}
			// Verify no `"top":{...null...}` for slices
			if strings.Contains(rec.Body.String(), `"source_ips":null`) ||
				strings.Contains(rec.Body.String(), `"uris":null`) ||
				strings.Contains(rec.Body.String(), `"gateway_issues":null`) {
				t.Fatalf("unexpected null slice in empty SecurityOverview(%s): %s", r, rec.Body.String())
			}
		}

		runRec := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "empty-run")
		if runRec.Code != http.StatusOK {
			t.Fatalf("empty RuntimeOverview status=%d body=%s", runRec.Code, runRec.Body.String())
		}
		if strings.Contains(runRec.Body.String(), `"components":null`) {
			t.Fatalf("unexpected null components in empty RuntimeOverview: %s", runRec.Body.String())
		}
		var runResp struct {
			Data RuntimeOverviewData `json:"data"`
		}
		if err := json.Unmarshal(runRec.Body.Bytes(), &runResp); err != nil {
			t.Fatalf("unmarshal empty RuntimeOverview: %v", err)
		}
		if runResp.Data.Gateway == nil || runResp.Data.Gateway.Status != "UNKNOWN" {
			t.Fatalf("empty RuntimeOverview gateway = %+v, want UNKNOWN", runResp.Data.Gateway)
		}
		if runResp.Data.Storage == nil || runResp.Data.Storage.ValkeyUsedMemoryBytes == nil || *runResp.Data.Storage.ValkeyUsedMemoryBytes <= 0 {
			t.Fatalf("empty RuntimeOverview storage ValkeyUsedMemoryBytes = %+v, want > 0", runResp.Data.Storage)
		}

		audRec := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "empty-aud")
		if audRec.Code != http.StatusOK {
			t.Fatalf("empty AuditOverview status=%d body=%s", audRec.Code, audRec.Body.String())
		}
		if strings.Contains(audRec.Body.String(), `"recent_audits":null`) ||
			strings.Contains(audRec.Body.String(), `"disposition_distribution":null`) ||
			strings.Contains(audRec.Body.String(), `"action_stats":null`) {
			t.Fatalf("unexpected null slice in empty AuditOverview: %s", audRec.Body.String())
		}

		// Clean empty-state cache keys before populated parity tests
		if err := valkeyClient.Redis().FlushDB(ctx).Err(); err != nil {
			t.Fatalf("FlushDB: %v", err)
		}
	})

	// ==================== 2. Populated DB Semantic Parity ====================
	now := time.Now().UTC()
	dayStart, _ := TodayWindowUTC(now)
	todayEventTs := dayStart.Add(5 * time.Minute)
	if todayEventTs.After(now) {
		todayEventTs = now.Add(-time.Second)
	}
	minuteBucket := todayEventTs.Truncate(time.Minute)
	hourBucket := now.Add(-2 * 24 * time.Hour).Truncate(time.Hour)

	// Applications + upstreams + health records
	appActive := uuid.New()
	appDegraded := uuid.New()
	appMirror := uuid.New()
	appDeleted := uuid.New()
	_, err := pool.Exec(ctx, `
INSERT INTO applications (id, code, name, status, health_status, deployment_mode, deleted_at) VALUES
  ($1, 'app-active', '主站应用', 'ACTIVE', 'HEALTHY', 'REVERSE_PROXY', NULL),
  ($2, 'app-degraded', '降级应用', 'ACTIVE', 'DEGRADED', 'REVERSE_PROXY', NULL),
  ($3, 'app-mirror', '镜像应用', 'ACTIVE', 'HEALTHY', 'MIRROR', NULL),
  ($4, 'app-deleted', '已删应用', 'ACTIVE', 'UNHEALTHY', 'REVERSE_PROXY', now())`,
		appActive, appDegraded, appMirror, appDeleted)
	if err != nil {
		t.Fatalf("seed applications: %v", err)
	}

	upBad := uuid.New()
	upGood := uuid.New()
	upNoRec := uuid.New()
	upMirror := uuid.New()
	upDeleted := uuid.New()
	_, err = pool.Exec(ctx, `
INSERT INTO upstreams (id, application_id, name, host, normalized_host, port, status, health_check_enabled, deleted_at) VALUES
  ($1, $6, 'up-bad', '10.0.0.1', '10.0.0.1', 80, 'ACTIVE', TRUE, NULL),
  ($2, $6, 'up-good', '10.0.0.2', '10.0.0.2', 80, 'ACTIVE', TRUE, NULL),
  ($3, $6, 'up-norec', '10.0.0.3', '10.0.0.3', 80, 'ACTIVE', TRUE, NULL),
  ($4, $7, 'up-mirror', '10.0.0.4', '10.0.0.4', 80, 'ACTIVE', TRUE, NULL),
  ($5, $6, 'up-deleted', '10.0.0.5', '10.0.0.5', 80, 'ACTIVE', TRUE, now())`,
		upBad, upGood, upNoRec, upMirror, upDeleted, appActive, appMirror)
	if err != nil {
		t.Fatalf("seed upstreams: %v", err)
	}

	_, err = pool.Exec(ctx, `
INSERT INTO upstream_health_records (upstream_id, checked_at, status) VALUES
  ($1, $5, 'UP'),
  ($1, $6, 'UNHEALTHY'),
  ($2, $5, 'UNHEALTHY'),
  ($2, $6, 'UP'),
  ($3, $6, 'DOWN'),
  ($4, $6, 'DOWN')`,
		upBad, upGood, upMirror, upDeleted, now.Add(-10*time.Minute), now.Add(-time.Minute))
	if err != nil {
		t.Fatalf("seed upstream health: %v", err)
	}

	// Temporary blocks
	_, err = pool.Exec(ctx, `
INSERT INTO temporary_blocks (client_ip, trigger_type, block_expires_at, status) VALUES
  ('198.51.100.10', 'MANUAL', $1, 'ACTIVE'),
  ('198.51.100.11', 'MANUAL', $2, 'ACTIVE'),
  ('198.51.100.12', 'MANUAL', $1, 'EXPIRED')`,
		now.Add(time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("seed temporary_blocks: %v", err)
	}

	// Certificates
	_, err = pool.Exec(ctx, `
INSERT INTO certificates (name, not_after, certificate_reference, encrypted_private_key_reference, deleted_at) VALUES
  ('cert-soon', $1, 'ref1', 'k1', NULL),
  ('cert-later', $2, 'ref2', 'k2', NULL),
  ('cert-expired', $3, 'ref3', 'k3', NULL),
  ('cert-null', NULL, 'ref4', 'k4', NULL),
  ('cert-deleted', $1, 'ref5', 'k5', now())`,
		now.Add(10*24*time.Hour), now.Add(45*24*time.Hour), now.Add(-24*time.Hour))
	if err != nil {
		t.Fatalf("seed certificates: %v", err)
	}

	// Security events (distinct status counts: UNPROCESSED=4, CONFIRMED=2, FALSE_POSITIVE=1)
	yesterdayDisp := dayStart.Add(-2 * time.Hour)
	event2d := now.Add(-48 * time.Hour)
	_, err = pool.Exec(ctx, `
INSERT INTO security_events (request_id, occurred_at, application_id, application_name_snapshot, client_ip, request_path, attack_type, severity, action, disposition_status, disposition_at) VALUES
  ('r1', $1, $4, '主站应用', '203.0.113.10', '/login', 'SQLI', 'HIGH', 'BLOCK', 'UNPROCESSED', NULL),
  ('r2', $1, $4, '主站应用', '203.0.113.10', '/login', 'SQLI', 'HIGH', 'BLOCK', 'UNPROCESSED', NULL),
  ('r3', $1, $4, '主站应用', '203.0.113.20', '/api/v1', 'XSS', 'LOW', 'OBSERVE', 'UNPROCESSED', NULL),
  ('r4', $3, $4, '主站应用', '203.0.113.10', '/admin', 'SQLI', 'MEDIUM', 'BLOCK', 'UNPROCESSED', NULL),
  ('r5', $3, $4, '主站应用', '203.0.113.30', '', 'RCE', 'HIGH', 'BLOCK', 'CONFIRMED', $1),
  ('r6', $3, $4, '主站应用', NULL, '/null-ip', 'XSS', 'LOW', 'OBSERVE', 'CONFIRMED', $2),
  ('r7', $3, $4, '主站应用', '203.0.113.20', '/api/v1', 'XSS', 'MEDIUM', 'OBSERVE', 'FALSE_POSITIVE', $1)`,
		todayEventTs, yesterdayDisp, event2d, appActive)
	if err != nil {
		t.Fatalf("seed security_events: %v", err)
	}

	// Aggregates & summaries
	_, err = pool.Exec(ctx, `
INSERT INTO metric_minute_aggregates (bucket_start, metric, labels, value) VALUES
  ($1, $2, '{"app":"app-active"}'::jsonb, 120),
  ($1, $3, '{"app":"app-active","severity":"HIGH","attack_type":"SQLI"}'::jsonb, 15),
  ($1, $4, '{"app":"app-active"}'::jsonb, 9),
  ($1, $5, '{"app":"app-active"}'::jsonb, 6),
  ($1, $6, '{"app":"app-active"}'::jsonb, 3),
  ($1, $7, '{"app":"app-active"}'::jsonb, 2),
  ($1, 'waf_rule_hits_total', '{"policy":"942100"}'::jsonb, 8),
  ($1, $8, '{}'::jsonb, 1.5)`,
		minuteBucket,
		metrics.HTTPRequestsTotal, metrics.WAFEventsTotal, metrics.WAFBlocksTotal,
		metrics.WAFObserveTotal, metrics.CCExceededTotal, metrics.IPDenyMatchesTotal,
		metrics.EventCollectorLagSec)
	if err != nil {
		t.Fatalf("seed metric_minute_aggregates: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO metric_hour_aggregates (bucket_start, metric, labels, value) VALUES
  ($1, $2, '{"app":"app-active"}'::jsonb, 500),
  ($1, $3, '{"app":"app-active","severity":"MEDIUM","attack_type":"XSS"}'::jsonb, 25)`,
		hourBucket, metrics.HTTPRequestsTotal, metrics.WAFEventsTotal)
	if err != nil {
		t.Fatalf("seed metric_hour_aggregates: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO source_ip_summaries (bucket_start, client_ip, waf_events, deny_hits) VALUES
  ($1, '203.0.113.10', 10, 8),
  ($1, '203.0.113.20', 4, 1)`,
		minuteBucket)
	if err != nil {
		t.Fatalf("seed source_ip_summaries: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO uri_security_summaries (bucket_start, application_code, uri_path, waf_events, waf_blocks) VALUES
  ($1, 'app-active', '/login', 10, 8),
  ($1, 'app-active', '/api/v1', 4, 1)`,
		minuteBucket)
	if err != nil {
		t.Fatalf("seed uri_security_summaries: %v", err)
	}

	// System health snapshots (multiple components & timestamps)
	_, err = pool.Exec(ctx, `
INSERT INTO system_health_snapshots (taken_at, component, status, latency_ms, metrics, message) VALUES
  ($1, 'API', 'UP', 3, '{}'::jsonb, 'ok'),
  ($2, 'API', 'DEGRADED', 42, '{}'::jsonb, 'slow db'),
  ($1, 'gateway-edge', 'DEGRADED', 15, '{"uptime_seconds":100}'::jsonb, 'old edge'),
  ($2, 'GATEWAY', 'UP', 2, '{"uptime_seconds":1234.5}'::jsonb, 'healthy'),
  ($2, 'POSTGRES', 'UP', 1, '{}'::jsonb, 'ok')`,
		now.Add(-15*time.Minute), now.Add(-2*time.Minute))
	if err != nil {
		t.Fatalf("seed system_health_snapshots: %v", err)
	}

	// Publish tasks & report jobs
	_, err = pool.Exec(ctx, `
INSERT INTO gateway_publish_tasks (task_type, status, requested_at, started_at, finished_at, failure_message) VALUES
  ('PUBLISH', 'SUCCESS', $1, $1, $2, ''),
  ('PUBLISH', 'FAILED', $1, $1, $2, 'syntax err'),
  ('PUBLISH', 'SUCCESS', $3, $3, $3, '')`,
		now.Add(-time.Hour), now.Add(-time.Hour+4*time.Second), now.Add(-40*24*time.Hour))
	if err != nil {
		t.Fatalf("seed gateway_publish_tasks: %v", err)
	}
	_, err = pool.Exec(ctx, `
INSERT INTO report_jobs (report_type, time_range_start, time_range_end, status, requested_at) VALUES
  ('DAILY', $1, $2, 'SUCCESS', $2),
  ('WEEKLY', $1, $2, 'FAILED', $2),
  ('MONTHLY', $3, $3, 'SUCCESS', $3)`,
		now.Add(-2*time.Hour), now.Add(-time.Hour), now.Add(-45*24*time.Hour))
	if err != nil {
		t.Fatalf("seed report_jobs: %v", err)
	}

	// Aggregation jobs
	_, err = pool.Exec(ctx, `
INSERT INTO aggregation_jobs (job_type, window_start, window_end, status, rows_written, started_at) VALUES
  ('MINUTE', $1, $2, 'SUCCESS', 10, $2),
  ('HOUR', $1, $2, 'FAILED', 0, $2)`,
		now.Add(-2*time.Hour), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("seed aggregation_jobs: %v", err)
	}

	// Operation audits
	_, err = pool.Exec(ctx, `
INSERT INTO operation_audits (occurred_at, username, module, action, object_name, result, risk_level) VALUES
  ($1, 'admin', 'applications', 'update', 'app-active', 'SUCCESS', 'LOW'),
  ($1, 'admin', 'applications', 'update', 'app-degraded', 'SUCCESS', 'LOW'),
  ($1, 'admin', 'policies', 'create', 'pol-1', 'SUCCESS', 'MEDIUM'),
  ($2, 'admin', 'auth', 'login', 'admin', 'SUCCESS', 'LOW')`,
		todayEventTs, dayStart.Add(-3*time.Hour))
	if err != nil {
		t.Fatalf("seed operation_audits: %v", err)
	}

	t.Run("TodayCounters parity", func(t *testing.T) {
		got, err := store.TodayCounters(ctx, dayStart, now)
		if err != nil {
			t.Fatalf("TodayCounters: %v", err)
		}
		if got.RequestsTotal != 120 || got.WAFEvents != 15 || got.WAFBlocks != 9 ||
			got.WAFObserves != 6 || got.CCExceeded != 3 || got.IPDenyMatches != 2 {
			t.Fatalf("metric sums mismatch: %+v", got)
		}
		if got.TempBlockedIPs != 1 || got.UnprocessedHighEvents != 2 ||
			got.ProtectedApps != 3 || got.AbnormalApps != 1 ||
			got.AbnormalUpstreams != 1 || got.ExpiringCerts != 1 {
			t.Fatalf("live counters mismatch: %+v", got)
		}
	})

	t.Run("LatestComponentStatuses, ComponentIssues & GatewayRuntime parity", func(t *testing.T) {
		gotComps, err := store.LatestComponentStatuses(ctx)
		if err != nil {
			t.Fatalf("LatestComponentStatuses: %v", err)
		}
		if len(gotComps) != 4 {
			t.Fatalf("gotComps len=%d, want 4", len(gotComps))
		}

		// Reference DISTINCT ON query
		refRows, err := pool.Query(ctx, `
SELECT DISTINCT ON (component) component, status
FROM system_health_snapshots ORDER BY component, taken_at DESC`)
		if err != nil {
			t.Fatalf("ref DISTINCT ON: %v", err)
		}
		defer refRows.Close()
		refMap := map[string]string{}
		for refRows.Next() {
			var c, st string
			if err := refRows.Scan(&c, &st); err != nil {
				t.Fatal(err)
			}
			refMap[c] = st
		}
		for _, c := range gotComps {
			if refMap[c.Component] != c.Status {
				t.Fatalf("component %s status=%s, want %s", c.Component, c.Status, refMap[c.Component])
			}
		}

		issues, err := store.ComponentIssues(ctx)
		if err != nil {
			t.Fatalf("ComponentIssues: %v", err)
		}
		if len(issues) != 2 || issues[0].Component != "API" || issues[1].Component != "gateway-edge" {
			t.Fatalf("ComponentIssues = %+v, want [API, gateway-edge]", issues)
		}

		gwDB, err := store.GatewayRuntime(ctx)
		if err != nil {
			t.Fatalf("GatewayRuntime: %v", err)
		}
		gwDerived := deriveGatewayRuntime(gotComps)
		if gwDB.Status != gwDerived.Status || !gwDB.SnapshotAt.Equal(*gwDerived.SnapshotAt) ||
			*gwDB.UptimeSeconds != *gwDerived.UptimeSeconds {
			t.Fatalf("GatewayRuntime mismatch: db=%+v derived=%+v", gwDB, gwDerived)
		}
	})

	t.Run("TopSourceIPs 24h and 7d parity", func(t *testing.T) {
		ips24, err := store.TopSourceIPs(ctx, now.Add(-24*time.Hour), now, 10)
		if err != nil {
			t.Fatalf("TopSourceIPs 24h: %v", err)
		}
		if len(ips24) != 2 || ips24[0].IP != "203.0.113.10" || ips24[0].Events != 10 || ips24[0].Blocks != 8 {
			t.Fatalf("TopSourceIPs 24h = %+v", ips24)
		}

		ips7d, err := store.TopSourceIPs(ctx, now.Add(-7*24*time.Hour), now, 10)
		if err != nil {
			t.Fatalf("TopSourceIPs 7d: %v", err)
		}
		// 203.0.113.10 has 3 events (3 blocks), 203.0.113.20 has 2 events (0 blocks), 203.0.113.30 has 1 event (1 block); NULL excluded
		if len(ips7d) != 3 || ips7d[0] != (SourceIPStat{IP: "203.0.113.10", Events: 3, Blocks: 3}) ||
			ips7d[1] != (SourceIPStat{IP: "203.0.113.20", Events: 2, Blocks: 0}) {
			t.Fatalf("TopSourceIPs 7d = %+v", ips7d)
		}
	})

	t.Run("AuditCounters and AuditOverview parity", func(t *testing.T) {
		cnt, err := store.AuditCounters(ctx, dayStart, now)
		if err != nil {
			t.Fatalf("AuditCounters: %v", err)
		}
		if cnt.TodayDispositions != 2 || cnt.UnprocessedEvents != 4 || cnt.TodayAudits != 3 {
			t.Fatalf("AuditCounters = %+v, want {2, 4, 3}", cnt)
		}

		distStandalone, err := store.DispositionDistribution(ctx)
		if err != nil {
			t.Fatalf("DispositionDistribution: %v", err)
		}
		actStandalone, err := store.AuditActionStats(ctx, dayStart, now, 10)
		if err != nil {
			t.Fatalf("AuditActionStats: %v", err)
		}

		audRec := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "aud-parity")
		if audRec.Code != http.StatusOK {
			t.Fatalf("AuditOverview status=%d body=%s", audRec.Code, audRec.Body.String())
		}
		var audResp struct {
			Data AuditOverviewData `json:"data"`
		}
		if err := json.Unmarshal(audRec.Body.Bytes(), &audResp); err != nil {
			t.Fatalf("unmarshal AuditOverview: %v", err)
		}
		if audResp.Data.TodayDispositions != cnt.TodayDispositions ||
			audResp.Data.UnprocessedEvents != cnt.UnprocessedEvents ||
			audResp.Data.TodayAudits != cnt.TodayAudits {
			t.Fatalf("AuditOverview counters=%+v vs store=%+v", audResp.Data, cnt)
		}
		if len(audResp.Data.DispositionDistribution) != len(distStandalone) {
			t.Fatalf("dist len mismatch: %d vs %d", len(audResp.Data.DispositionDistribution), len(distStandalone))
		}
		for i := range distStandalone {
			if audResp.Data.DispositionDistribution[i] != distStandalone[i] {
				t.Fatalf("dist[%d] mismatch: %+v vs %+v", i, audResp.Data.DispositionDistribution[i], distStandalone[i])
			}
		}
		if len(audResp.Data.ActionStats) != len(actStandalone) {
			t.Fatalf("actions len mismatch: %d vs %d", len(audResp.Data.ActionStats), len(actStandalone))
		}
		for i := range actStandalone {
			if audResp.Data.ActionStats[i] != actStandalone[i] {
				t.Fatalf("actions[%d] mismatch: %+v vs %+v", i, audResp.Data.ActionStats[i], actStandalone[i])
			}
		}
	})

	// ==================== 3. Real Valkey 8.1.8 Cache Integration ====================
	t.Run("Valkey populate, TTL, hit bypasses PG, expiry, and unavailable fallback", func(t *testing.T) {
		if err := valkeyClient.Redis().FlushDB(ctx).Err(); err != nil {
			t.Fatalf("FlushDB: %v", err)
		}

		// 3a. Cold calls populate real Valkey with TTL in (0, 20s]
		secRec := doDashboardReq(h.SecurityOverview, "/api/v1/dashboard/security-overview?range=24h", "vk-sec-1")
		if secRec.Code != http.StatusOK {
			t.Fatalf("SecurityOverview status=%d body=%s", secRec.Code, secRec.Body.String())
		}
		runRec := doDashboardReq(h.RuntimeOverview, "/api/v1/dashboard/runtime-overview", "vk-run-1")
		if runRec.Code != http.StatusOK {
			t.Fatalf("RuntimeOverview status=%d body=%s", runRec.Code, runRec.Body.String())
		}
		audRec := doDashboardReq(h.AuditOverview, "/api/v1/dashboard/audit-overview", "vk-aud-1")
		if audRec.Code != http.StatusOK {
			t.Fatalf("AuditOverview status=%d body=%s", audRec.Code, audRec.Body.String())
		}

		for _, key := range []string{
			"jiuzhang:dashboard:v1:security-overview:24h",
			"jiuzhang:dashboard:v1:runtime-overview",
			"jiuzhang:dashboard:v1:audit-overview",
		} {
			ttl, err := valkeyClient.TTL(ctx, key)
			if err != nil {
				t.Fatalf("TTL(%s): %v", key, err)
			}
			if ttl <= 0 || ttl > 20*time.Second {
				t.Fatalf("TTL(%s) = %v, want in (0, 20s]", key, ttl)
			}
		}

		// Verify RuntimeOverview live Valkey memory & merged stats
		var runResp struct {
			Data RuntimeOverviewData `json:"data"`
		}
		if err := json.Unmarshal(runRec.Body.Bytes(), &runResp); err != nil {
			t.Fatalf("unmarshal RuntimeOverview: %v", err)
		}
		if runResp.Data.Storage == nil || runResp.Data.Storage.ValkeyUsedMemoryBytes == nil || runResp.Data.Storage.ValkeyError != "" {
			t.Fatalf("unexpected RuntimeOverview storage: %+v", runResp.Data.Storage)
		}
		if runResp.Data.Publish.Total != 2 || runResp.Data.Publish.Success != 1 || runResp.Data.Publish.Failed != 1 {
			t.Fatalf("Publish stats mismatch: %+v", runResp.Data.Publish)
		}
		if runResp.Data.Reports.Total != 2 || runResp.Data.Reports.Success != 1 || runResp.Data.Reports.Failed != 1 {
			t.Fatalf("Report stats mismatch: %+v", runResp.Data.Reports)
		}

		// 3b. Modify PG directly + verify cached hit does NOT query PG
		_, err := pool.Exec(ctx, `
INSERT INTO operation_audits (occurred_at, username, module, action, object_name, result, risk_level)
VALUES ($1, 'admin', 'policies', 'update', 'pol-2', 'SUCCESS', 'LOW')`, todayEventTs)
		if err != nil {
			t.Fatalf("insert extra audit: %v", err)
		}

		nilDBHandler := NewHandler(nil, nil)
		nilDBHandler.SetCache(valkeyClient)
		hitRec := doDashboardReq(nilDBHandler.AuditOverview, "/api/v1/dashboard/audit-overview", "vk-aud-hit")
		if hitRec.Code != http.StatusOK {
			t.Fatalf("nilDBHandler cache hit status=%d body=%s", hitRec.Code, hitRec.Body.String())
		}
		var hitResp struct {
			RequestID string            `json:"request_id"`
			Data      AuditOverviewData `json:"data"`
		}
		if err := json.Unmarshal(hitRec.Body.Bytes(), &hitResp); err != nil {
			t.Fatalf("unmarshal hitResp: %v", err)
		}
		if hitResp.RequestID != "vk-aud-hit" {
			t.Fatalf("RequestID = %q, want vk-aud-hit", hitResp.RequestID)
		}
		if hitResp.Data.TodayAudits != 3 {
			t.Fatalf("cached TodayAudits = %d, want 3 (stale within TTL, not 4)", hitResp.Data.TodayAudits)
		}

		// 3c. Short-TTL expiry in real Valkey sees newly inserted PG row
		if err := valkeyClient.Redis().FlushDB(ctx).Err(); err != nil {
			t.Fatalf("FlushDB: %v", err)
		}
		shortHandler := NewHandler(aggregations.NewStore(pool), pool)
		shortHandler.SetCache(valkeyClient)
		shortHandler.cacheTTL = 250 * time.Millisecond

		firstRec := doDashboardReq(shortHandler.AuditOverview, "/api/v1/dashboard/audit-overview", "ttl-1")
		if firstRec.Code != http.StatusOK {
			t.Fatalf("shortHandler cold status=%d", firstRec.Code)
		}
		_, err = pool.Exec(ctx, `
INSERT INTO operation_audits (occurred_at, username, module, action, object_name, result, risk_level)
VALUES ($1, 'admin', 'policies', 'delete', 'pol-3', 'SUCCESS', 'HIGH')`, todayEventTs)
		if err != nil {
			t.Fatalf("insert 5th audit: %v", err)
		}
		time.Sleep(350 * time.Millisecond)

		afterExpiryRec := doDashboardReq(shortHandler.AuditOverview, "/api/v1/dashboard/audit-overview", "ttl-2")
		if afterExpiryRec.Code != http.StatusOK {
			t.Fatalf("shortHandler post-expiry status=%d", afterExpiryRec.Code)
		}
		var afterResp struct {
			Data AuditOverviewData `json:"data"`
		}
		if err := json.Unmarshal(afterExpiryRec.Body.Bytes(), &afterResp); err != nil {
			t.Fatalf("unmarshal afterResp: %v", err)
		}
		if afterResp.Data.TodayAudits != 5 {
			t.Fatalf("TodayAudits after TTL expiry = %d, want 5", afterResp.Data.TodayAudits)
		}

		// 3d. Valkey client closed/unavailable fails open to PG
		host, portStr, _ := net.SplitHostPort(os.Getenv("DASHBOARDS_TEST_VALKEY_ADDR"))
		port, _ := strconv.Atoi(portStr)
		downClient, err := cache.New(ctx, config.CacheConfig{
			Host:     host,
			Port:     port,
			Password: os.Getenv("DASHBOARDS_TEST_VALKEY_PASSWORD"),
			DB:       14,
		})
		if err != nil {
			t.Fatalf("cache.New downClient: %v", err)
		}
		_ = downClient.Close()

		degradedHandler := NewHandler(aggregations.NewStore(pool), pool)
		degradedHandler.SetCache(downClient)
		for _, tc := range []struct {
			fn   http.HandlerFunc
			path string
		}{
			{degradedHandler.SecurityOverview, "/api/v1/dashboard/security-overview?range=7d"},
			{degradedHandler.RuntimeOverview, "/api/v1/dashboard/runtime-overview"},
			{degradedHandler.AuditOverview, "/api/v1/dashboard/audit-overview"},
		} {
			rec := doDashboardReq(tc.fn, tc.path, "vk-down")
			if rec.Code != http.StatusOK {
				t.Fatalf("fail-open %s returned %d: %s", tc.path, rec.Code, rec.Body.String())
			}
		}
	})
}
