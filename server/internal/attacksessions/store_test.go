package attacksessions

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestFetchEventsSQLIncludesPartialIndexPredicate(t *testing.T) {
	const wantPred = "ibe.request_id IS NOT NULL AND ibe.request_id <> ''"
	for name, sqlStr := range map[string]string{
		"FetchSecurityEvents":   fetchSecurityEventsSQL(),
		"FetchAPIRuntimeEvents": fetchAPIRuntimeEventsSQL(),
	} {
		if !strings.Contains(sqlStr, wantPred) {
			t.Fatalf("%s SQL missing partial index predicate %q:\n%s", name, wantPred, sqlStr)
		}
	}
}

func TestFetchEventsPartialIndexPGIntegration(t *testing.T) {
	dsn := os.Getenv("ATTACKSESSIONS_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ATTACKSESSIONS_TEST_PG_DSN not set, skipping PG integration test")
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

	tag := uuid.New().String()[:8]
	identityID := uuid.New()
	identityKey := "att-test-id-" + tag
	targetReqID := "req-att-target-" + tag
	appID := uuid.New()
	appCode := "att-test-app-" + tag

	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_runtime_events WHERE request_id = $1`, targetReqID)
		_, _ = pool.Exec(bg, `DELETE FROM security_events WHERE request_id = $1`, targetReqID)
		_, _ = pool.Exec(bg, `DELETE FROM identity_behavior_events WHERE identity_key LIKE $1`, "att-test-"+tag+"%")
		_, _ = pool.Exec(bg, `DELETE FROM client_identity WHERE id = $1`, identityID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id = $1`, appID)
	})

	if _, err := pool.Exec(ctx, `INSERT INTO applications (id, code, name) VALUES ($1, $2, $3)`,
		appID, appCode, "AttackSessions PG Test"); err != nil {
		t.Fatalf("insert application: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO client_identity (id, identity_key, identity_type, first_seen_at, last_seen_at)
VALUES ($1, $2, 'HUMAN', now(), now())`, identityID, identityKey); err != nil {
		t.Fatalf("insert client_identity: %v", err)
	}

	now := time.Now().UTC()
	// 插入 3,000 条行为事件并 ANALYZE，使 PG 优化器真实评估部分索引 idx_identity_behavior_events_request_id
	if _, err := pool.Exec(ctx, `
INSERT INTO identity_behavior_events (occurred_at, identity_key, identity_id, request_id, rule_code, rule_version, signal, risk_score_delta)
SELECT $1::timestamptz - make_interval(secs => g),
       CASE WHEN g = 1 THEN $2::text ELSE $3::text || '-' || g END,
       CASE WHEN g = 1 THEN $4::uuid ELSE NULL::uuid END,
       CASE WHEN g = 1 THEN $5::text ELSE 'req-noise-' || $6::text || '-' || g END,
       'ENUMERATION',
       'v1',
       'ENUMERATION',
       10
FROM generate_series(1, 3000) g`,
		now, identityKey, "att-test-"+tag, identityID, targetReqID, tag); err != nil {
		t.Fatalf("seed identity_behavior_events: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO security_events (occurred_at, request_id, application_id, domain, client_ip, request_method, request_uri, attack_type, anomaly_score, action)
VALUES ($1, $2, $3, 'att-test.local', '203.0.113.50'::inet, 'GET', '/login', 'SQLI', 15, 'BLOCK')`,
		now, targetReqID, appID); err != nil {
		t.Fatalf("insert security_event: %v", err)
	}
	if _, err := pool.Exec(ctx, `
INSERT INTO api_runtime_events (occurred_at, request_id, application_id, endpoint_key, client_ip, risk_score, details_json)
VALUES ($1, $2, $3, 'GET /login', '203.0.113.50', 20, '[]'::jsonb)`,
		now, targetReqID, appID); err != nil {
		t.Fatalf("insert api_runtime_event: %v", err)
	}
	if _, err := pool.Exec(ctx, `ANALYZE identity_behavior_events`); err != nil {
		t.Fatalf("analyze identity_behavior_events: %v", err)
	}

	store := NewStore(pool)
	since := now.Add(-time.Minute)

	secEvents, err := store.FetchSecurityEvents(ctx, since, 50)
	if err != nil {
		t.Fatalf("FetchSecurityEvents: %v", err)
	}
	var foundSec bool
	for _, ev := range secEvents {
		if ev.RequestID == targetReqID {
			foundSec = true
			if ev.IdentityID == nil || *ev.IdentityID != identityID || ev.IdentityKey != identityKey {
				t.Fatalf("FetchSecurityEvents resolved identity = (%v, %q), want (%s, %q)",
					ev.IdentityID, ev.IdentityKey, identityID, identityKey)
			}
		}
	}
	if !foundSec {
		t.Fatalf("FetchSecurityEvents did not return seeded event %s", targetReqID)
	}

	apiEvents, err := store.FetchAPIRuntimeEvents(ctx, since, 50)
	if err != nil {
		t.Fatalf("FetchAPIRuntimeEvents: %v", err)
	}
	var foundAPI bool
	for _, ev := range apiEvents {
		if ev.RequestID == targetReqID {
			foundAPI = true
			if ev.IdentityID == nil || *ev.IdentityID != identityID || ev.IdentityKey != identityKey {
				t.Fatalf("FetchAPIRuntimeEvents resolved identity = (%v, %q), want (%s, %q)",
					ev.IdentityID, ev.IdentityKey, identityID, identityKey)
			}
		}
	}
	if !foundAPI {
		t.Fatalf("FetchAPIRuntimeEvents did not return seeded event %s", targetReqID)
	}

	// 动态解析当前活跃分区的子索引名称（若未分区则回退至父索引名）
	expectedIndex := "idx_identity_behavior_events_request_id"
	forbiddenSeqScan := "Seq Scan on identity_behavior_events "
	var relkind string
	if err := pool.QueryRow(ctx, `
SELECT c.relkind::text
FROM pg_class c
WHERE c.oid = to_regclass('identity_behavior_events')`).Scan(&relkind); err != nil {
		t.Fatalf("inspect identity_behavior_events relkind: %v", err)
	}
	if relkind == "p" {
		activePart := fmt.Sprintf("identity_behavior_events_%s", now.UTC().Format("2006_01"))
		if err := pool.QueryRow(ctx, `
SELECT child_idx.relname
FROM pg_inherits inh
JOIN pg_index idx ON idx.indexrelid = inh.inhrelid
JOIN pg_class child_idx ON child_idx.oid = idx.indexrelid
WHERE inh.inhparent = to_regclass('idx_identity_behavior_events_request_id')
  AND idx.indrelid = to_regclass($1)`, activePart).Scan(&expectedIndex); err != nil {
			t.Fatalf("resolve child index on partition %s: %v", activePart, err)
		}
		forbiddenSeqScan = "Seq Scan on " + activePart
	}

	// 验证 EXPLAIN (ANALYZE, BUFFERS) 对两条查询均命中期望索引且活跃分区未退化为 Seq Scan
	for name, q := range map[string]string{
		"FetchSecurityEvents":   fetchSecurityEventsSQL(),
		"FetchAPIRuntimeEvents": fetchAPIRuntimeEventsSQL(),
	} {
		planRows, err := pool.Query(ctx, fmt.Sprintf("EXPLAIN (ANALYZE, BUFFERS) %s", q), since, 50)
		if err != nil {
			t.Fatalf("EXPLAIN %s: %v", name, err)
		}
		var planLines []string
		for planRows.Next() {
			var line string
			if err := planRows.Scan(&line); err != nil {
				planRows.Close()
				t.Fatalf("scan plan %s: %v", name, err)
			}
			planLines = append(planLines, line)
		}
		planRows.Close()
		if err := planRows.Err(); err != nil {
			t.Fatalf("plan rows %s: %v", name, err)
		}
		plan := strings.Join(planLines, "\n")
		usedIndex := strings.Contains(plan, "Index Scan using "+expectedIndex) ||
			strings.Contains(plan, "Index Only Scan using "+expectedIndex) ||
			strings.Contains(plan, "Bitmap Index Scan on "+expectedIndex)
		if !usedIndex {
			t.Fatalf("%s plan did not use Index scan on %s:\n%s", name, expectedIndex, plan)
		}
		if strings.Contains(plan, forbiddenSeqScan) {
			t.Fatalf("%s plan fell back to %s:\n%s", name, forbiddenSeqScan, plan)
		}
	}
}
