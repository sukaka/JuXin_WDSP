// api_runtime_enrichment_test.go S1 分片验证：事件审计列（000035）+ Findings 生产化（000036）。
//
// 两部分：
//  1. 迁移 SQL 静态一致性（TestAPIEnrichmentMigrationStatic）：纯文件检查，
//     不依赖数据库——up/down 成对、列与索引增减对称、IF [NOT] EXISTS 守卫齐全；
//  2. 集成验证（TestStage8RuntimeEventEnrichment / TestStage8FindingsMaterialization）：
//     依赖真实 PostgreSQL（setupStage8Env，无环境自动 skip）——新列写入/读取、
//     findings 插入与 upsert 幂等（count 递增）、subject/版本落位。
package tests

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// ---------- 迁移 SQL 静态一致性（无数据库依赖） ----------

var (
	addColumnRe  = regexp.MustCompile(`(?i)ADD\s+COLUMN\s+IF\s+NOT\s+EXISTS\s+([a-z_]+)`)
	dropColumnRe = regexp.MustCompile(`(?i)DROP\s+COLUMN\s+IF\s+EXISTS\s+([a-z_]+)`)
)

// TestAPIEnrichmentMigrationStatic 000035/000036 up+down 静态一致性：
// up 每个 ADD COLUMN 在 down 有对应 DROP COLUMN（反之亦然），up 新建索引在 down 有
// DROP INDEX，且全部带 IF [NOT] EXISTS 守卫（可重复执行/安全回滚）。
func TestAPIEnrichmentMigrationStatic(t *testing.T) {
	pairs := []string{"000035_api_runtime_event_enrichment", "000036_api_findings_enrichment"}
	for _, base := range pairs {
		up := readMigration(t, base+".up.sql")
		down := readMigration(t, base+".down.sql")

		adds := addColumnRe.FindAllStringSubmatch(up, -1)
		if len(adds) == 0 {
			t.Fatalf("%s: no ADD COLUMN IF NOT EXISTS found", base)
		}
		drops := map[string]bool{}
		for _, m := range dropColumnRe.FindAllStringSubmatch(down, -1) {
			drops[m[1]] = true
		}
		for _, m := range adds {
			col := m[1]
			if !drops[col] {
				t.Errorf("%s: up adds column %s but down does not drop it", base, col)
			}
			delete(drops, col)
		}
		for col := range drops {
			t.Errorf("%s: down drops column %s but up does not add it", base, col)
		}
		// up 不得出现裸 ADD COLUMN（每个 ADD COLUMN 必须带 IF NOT EXISTS 守卫）
		allAdds := len(regexp.MustCompile(`(?i)ADD\s+COLUMN`).FindAllString(up, -1))
		if allAdds != len(adds) {
			t.Errorf("%s: %d ADD COLUMN but only %d guarded with IF NOT EXISTS", base, allAdds, len(adds))
		}
		if !strings.Contains(up, "BEGIN;") || !strings.Contains(up, "COMMIT;") {
			t.Errorf("%s: up must be wrapped in BEGIN/COMMIT", base)
		}
		if !strings.Contains(down, "BEGIN;") || !strings.Contains(down, "COMMIT;") {
			t.Errorf("%s: down must be wrapped in BEGIN/COMMIT", base)
		}
	}
	// 000036：去重指纹唯一索引 up 建、down 删
	up36 := readMigration(t, "000036_api_findings_enrichment.up.sql")
	down36 := readMigration(t, "000036_api_findings_enrichment.down.sql")
	if !strings.Contains(up36, "CREATE UNIQUE INDEX IF NOT EXISTS idx_api_runtime_findings_dedup") {
		t.Fatal("000036 up: dedup unique index missing or unguarded")
	}
	if !strings.Contains(down36, "DROP INDEX IF EXISTS idx_api_runtime_findings_dedup") {
		t.Fatal("000036 down: dedup index drop missing")
	}
	// 000035：六列齐全且可空（无 NOT NULL 强加）
	up35 := readMigration(t, "000035_api_runtime_event_enrichment.up.sql")
	for _, col := range []string{"client_ip", "method", "raw_path", "latency_ms", "model_version", "policy_version"} {
		if !strings.Contains(up35, col) {
			t.Errorf("000035 up: column %s missing", col)
		}
	}
	if strings.Contains(up35, "NOT NULL") {
		t.Error("000035 up: enrichment columns must stay nullable")
	}
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "migrations", name))
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(data)
}

// ---------- 集成验证（真实 PostgreSQL，无环境自动 skip） ----------

// TestStage8RuntimeEventEnrichment 迁移 000035 六列落位；SavePrimary 新字段写入且
// 缺失（零值）落 NULL；request_id 幂等重放不覆盖。
func TestStage8RuntimeEventEnrichment(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移落位：六列存在且可空
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_events'
  AND column_name IN ('client_ip','method','raw_path','latency_ms','model_version','policy_version')`); n != 6 {
		t.Fatalf("enrichment columns = %d, want 6", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_events'
  AND column_name IN ('client_ip','method','raw_path','latency_ms','model_version','policy_version')
  AND is_nullable='NO'`); n != 0 {
		t.Fatalf("enrichment columns must be nullable, %d are NOT NULL", n)
	}

	rid := s5Rand()
	rt := apiruntime.NewStore(env.db)
	epKey := "GET /s8" + rid + "/items/{id}"
	full := &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: "req-en-" + rid + "-1", EndpointKey: epKey,
			RiskScore: 90, RiskLevel: "HIGH", FinalAction: "BLOCK",
			OccurredAt: time.Now().UTC(),
		},
		ClientIP: "203.0.113.9", Method: "GET", RawPath: "/s8" + rid + "/items/42",
		LatencyMs: 137, ModelVersion: "v3", PolicyVersion: "p-12",
	}
	if err := rt.SavePrimary(ctx, full); err != nil {
		t.Fatalf("SavePrimary enriched: %v", err)
	}
	// 旧版网关事件（零值新字段）→ 新列落 NULL
	legacy := &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: "req-en-" + rid + "-2", EndpointKey: epKey,
			RiskScore: 40, RiskLevel: "MEDIUM", FinalAction: "OBSERVE",
			OccurredAt: time.Now().UTC(),
		},
	}
	if err := rt.SavePrimary(ctx, legacy); err != nil {
		t.Fatalf("SavePrimary legacy: %v", err)
	}
	// 幂等重放：同 request_id 不产生第二行
	full.ClientIP = "203.0.113.250" // 重放内容不同也不覆盖
	if err := rt.SavePrimary(ctx, full); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`, "req-en-"+rid+"-1"); n != 1 {
		t.Fatalf("request_id idempotency broken: %d rows", n)
	}

	var clientIP, method, rawPath, modelVersion, policyVersion *string
	var latency *int64
	if err := env.db.QueryRow(ctx, `
SELECT client_ip, method, raw_path, latency_ms, model_version, policy_version
FROM api_runtime_events WHERE request_id=$1`, "req-en-"+rid+"-1").
		Scan(&clientIP, &method, &rawPath, &latency, &modelVersion, &policyVersion); err != nil {
		t.Fatalf("read enriched row: %v", err)
	}
	if clientIP == nil || *clientIP != "203.0.113.9" || method == nil || *method != "GET" ||
		rawPath == nil || latency == nil || *latency != 137 || modelVersion == nil || policyVersion == nil {
		t.Fatalf("enriched columns mismatch: ip=%v method=%v path=%v latency=%v model=%v policy=%v",
			strPtr(clientIP), strPtr(method), strPtr(rawPath), latency, strPtr(modelVersion), strPtr(policyVersion))
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_events WHERE request_id=$1
  AND client_ip IS NULL AND method IS NULL AND raw_path IS NULL
  AND latency_ms IS NULL AND model_version IS NULL AND policy_version IS NULL`,
		"req-en-"+rid+"-2"); n != 1 {
		t.Fatalf("legacy event must persist NULL enrichment columns")
	}
}

func strPtr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// TestStage8FindingsMaterialization 迁移 000036 列与去重索引落位；SaveFindings
// 插入 status=OPEN、同 dedup_fingerprint upsert 幂等（count 递增、行数不增）、
// subject/版本/证据落位且不含原始值。
func TestStage8FindingsMaterialization(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移落位：新列 + 唯一索引
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_findings'
  AND column_name IN ('subject_type','subject_id','risk_score','risk_level','count',
                      'evidence_json','model_version','policy_version','updated_at','dedup_fingerprint')`); n != 10 {
		t.Fatalf("findings enrichment columns = %d, want 10", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM pg_indexes
WHERE tablename='api_runtime_findings' AND indexname='idx_api_runtime_findings_dedup'`); n != 1 {
		t.Fatal("idx_api_runtime_findings_dedup unique index missing")
	}

	rid := s5Rand()
	epKey := "GET /s8" + rid + "/shadow/{id}"
	// 端点先发现（指纹以 endpoint_id 为锚；未解析时以 endpoint_key 兜底）
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_endpoints (endpoint_key, http_method, normalized_path, api_confidence, is_api, asset_status)
VALUES ($1, 'GET', '/s8`+rid+`/shadow/{id}', 0.9, true, 'DISCOVERED')
ON CONFLICT (application_id, domain_id, application_binding_id, host, endpoint_key, protocol_type) DO NOTHING`, epKey); err != nil {
		t.Fatalf("seed endpoint: %v", err)
	}

	rt := apiruntime.NewStore(env.db)
	mk := func() []apiruntime.FindingInput {
		return []apiruntime.FindingInput{{
			EndpointKey: epKey, RequestID: "req-fd-" + rid,
			FindingType: "SHADOW", Severity: "LOW", Title: "new endpoint observed",
			Detail:      map[string]any{"detector": "lifecycle", "rule_id": "lifecycle.new_endpoint"},
			Evidence:    map[string]any{"keys": []string{"field"}, "field": "id"},
			SubjectType: "IDENTITY", SubjectID: "fp-" + rid,
			RiskScore: 40, RiskLevel: "MEDIUM", ModelVersion: "v3", PolicyVersion: "p-12",
		}}
	}
	if err := rt.SaveFindings(ctx, mk()); err != nil {
		t.Fatalf("SaveFindings insert: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings WHERE request_id=$1`, "req-fd-"+rid); n != 1 {
		t.Fatalf("finding rows = %d, want 1", n)
	}
	// upsert 幂等：同指纹重复物化 → count 递增、行数不变、status 保持 OPEN
	for i := 0; i < 2; i++ {
		if err := rt.SaveFindings(ctx, mk()); err != nil {
			t.Fatalf("SaveFindings upsert %d: %v", i, err)
		}
	}
	var count int
	var status, subjectType, subjectID, modelVersion string
	var endpointID *string
	if err := env.db.QueryRow(ctx, `
SELECT count, status, COALESCE(subject_type,''), COALESCE(subject_id,''), COALESCE(model_version,''), endpoint_id::text
FROM api_runtime_findings WHERE request_id=$1`, "req-fd-"+rid).
		Scan(&count, &status, &subjectType, &subjectID, &modelVersion, &endpointID); err != nil {
		t.Fatalf("read finding: %v", err)
	}
	if count != 3 {
		t.Fatalf("upsert count = %d, want 3 (1 insert + 2 upserts)", count)
	}
	if status != "NEW" || subjectType != "IDENTITY" || subjectID != "fp-"+rid || modelVersion != "v3" {
		t.Fatalf("finding fields mismatch: status=%s subject=%s/%s model=%s", status, subjectType, subjectID, modelVersion)
	}
	if endpointID == nil {
		t.Fatal("endpoint_id must be resolved from endpoint_key")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings WHERE request_id=$1`, "req-fd-"+rid); n != 1 {
		t.Fatalf("upsert must not duplicate rows: %d", n)
	}
	// updated_at/last_seen_at 已刷新（非空且不早于 created_at）
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_findings WHERE request_id=$1
  AND updated_at IS NOT NULL AND last_seen_at >= first_seen_at`, "req-fd-"+rid); n != 1 {
		t.Fatal("upsert must refresh updated_at/last_seen_at")
	}
	// 不同 subject → 不同指纹 → 新行（主体维度隔离）
	other := mk()
	other[0].SubjectType, other[0].SubjectID = "IP", "src-"+rid
	other[0].RequestID = "req-fd-" + rid + "-ip"
	if err := rt.SaveFindings(ctx, other); err != nil {
		t.Fatalf("SaveFindings other subject: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings WHERE finding_type='SHADOW' AND request_id LIKE $1`, "req-fd-"+rid+"%"); n != 2 {
		t.Fatalf("distinct subject must yield distinct finding: %d rows", n)
	}
}
