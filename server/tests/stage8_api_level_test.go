// stage8_api_level_test.go §8.2 四级识别标签 api_level（迁移 000149）实库验证：
//  1. 迁移 SQL 静态一致性（无数据库依赖）——up/down 成对、IF [NOT] EXISTS 守卫齐全、
//     词表 CHECK 约束存在；
//  2. 集成验证（依赖真实 PostgreSQL，无环境自动 skip）——api_level 落库读回、
//     旧版事件零值落 NULL、词表外非法值拒绝、findings §7 冗余列随发现落库。
package tests

import (
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// TestAPILevelMigrationStatic 000149 up+down 静态一致性（复用 000150 同款对账口径）。
func TestAPILevelMigrationStatic(t *testing.T) {
	up := readMigration(t, "000149_api_events_api_level.up.sql")
	down := readMigration(t, "000149_api_events_api_level.down.sql")

	adds := addColumnRe.FindAllStringSubmatch(up, -1)
	if len(adds) != 3 {
		t.Fatalf("000149 up: want 3 guarded ADD COLUMN, got %v", adds)
	}
	drops := map[string]bool{}
	for _, m := range dropColumnRe.FindAllStringSubmatch(down, -1) {
		drops[m[1]] = true
	}
	for _, m := range adds {
		if !drops[m[1]] {
			t.Errorf("000149: up adds column %s but down does not drop it", m[1])
		}
		delete(drops, m[1])
	}
	for col := range drops {
		t.Errorf("000149: down drops column %s but up does not add it", col)
	}
	allAdds := len(regexp.MustCompile(`(?i)ADD\s+COLUMN`).FindAllString(up, -1))
	if allAdds != len(adds) {
		t.Errorf("000149 up: %d ADD COLUMN but only %d guarded with IF NOT EXISTS", allAdds, len(adds))
	}
	// 词表 CHECK 约束（四值 + NULL）
	if !strings.Contains(up, "chk_api_runtime_events_api_level") {
		t.Error("000149 up: vocabulary CHECK constraint missing")
	}
	for _, lv := range []string{"CONFIRMED_API", "PROBABLE_API", "POSSIBLE_API", "NON_API"} {
		if !strings.Contains(up, lv) {
			t.Errorf("000149 up: vocabulary value %s missing", lv)
		}
	}
	if !strings.Contains(down, "DROP CONSTRAINT IF EXISTS chk_api_runtime_events_api_level") {
		t.Error("000149 down: must drop the vocabulary CHECK constraint")
	}
	if strings.Contains(up, "NOT NULL") {
		t.Error("000149 up: api_level and §7 redundant columns must stay nullable")
	}
	if !strings.Contains(up, "BEGIN;") || !strings.Contains(up, "COMMIT;") ||
		!strings.Contains(down, "BEGIN;") || !strings.Contains(down, "COMMIT;") {
		t.Error("000149 up/down must be wrapped in BEGIN/COMMIT")
	}
}

// TestStage8RuntimeEventAPILevel 迁移 000149 落位；api_level 写入且读回；旧版事件
// 落 NULL；词表外值被拒绝（不落部分事件）；findings §7 冗余列随发现落库且口径
// 与主事件一致（空快照落 NULL，畸形指纹被拒）。
func TestStage8RuntimeEventAPILevel(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移落位：三列存在且可空
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE (table_name='api_runtime_events' AND column_name='api_level')
   OR (table_name='api_runtime_findings' AND column_name IN ('device_fingerprint','object_identifiers'))`); n != 3 {
		t.Fatalf("000149 columns = %d, want 3", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE ((table_name='api_runtime_events' AND column_name='api_level')
   OR (table_name='api_runtime_findings' AND column_name IN ('device_fingerprint','object_identifiers')))
  AND is_nullable='NO'`); n != 0 {
		t.Fatalf("000149 columns must be nullable, %d are NOT NULL", n)
	}
	// 词表 CHECK 约束已落位
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.table_constraints
WHERE table_name='api_runtime_events' AND constraint_name='chk_api_runtime_events_api_level'`); n != 1 {
		t.Fatalf("chk_api_runtime_events_api_level = %d, want 1", n)
	}

	rid := s5Rand()
	rt := apiruntime.NewStore(env.db)
	mk := func(reqID, level string) *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: reqID, EndpointKey: "GET /s8lv" + rid + "/users/{id}",
				RiskScore: 50, RiskLevel: "HIGH", FinalAction: "BLOCK",
				OccurredAt: time.Now().UTC(),
			},
			APILevel: level,
		}
	}
	// 四级词表逐一落库
	levels := []string{"CONFIRMED_API", "PROBABLE_API", "POSSIBLE_API", "NON_API"}
	for i, lv := range levels {
		if err := rt.SavePrimary(ctx, mk("req-lv-"+rid+"-"+string(rune('a'+i)), lv)); err != nil {
			t.Fatalf("SavePrimary api_level=%s: %v", lv, err)
		}
		if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE api_level=$1`, lv); n < 1 {
			t.Fatalf("api_level=%s not persisted", lv)
		}
	}
	// 旧版网关事件（零值 api_level）→ NULL
	if err := rt.SavePrimary(ctx, mk("req-lv-"+rid+"-legacy", "")); err != nil {
		t.Fatalf("SavePrimary legacy: %v", err)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_events WHERE request_id=$1 AND api_level IS NULL`,
		"req-lv-"+rid+"-legacy"); n != 1 {
		t.Fatal("legacy event must persist NULL api_level")
	}
	// 词表外值被拒绝（不落部分事件）
	if err := rt.SavePrimary(ctx, mk("req-lv-"+rid+"-bad", "SOME_API")); err == nil {
		t.Fatal("out-of-vocabulary api_level accepted")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`,
		"req-lv-"+rid+"-bad"); n != 0 {
		t.Fatalf("rejected event must not persist, rows = %d", n)
	}
	// 数据库 CHECK 约束兜底：绕过 Go 校验直写词表外值必须失败
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_runtime_events (request_id, endpoint_key, risk_score, risk_level, final_action, details_json, occurred_at, api_level)
VALUES ($1, 'GET /s8lv-direct', 0, 'NONE', 'ALLOW', '[]', now(), 'SOME_API')`, "req-lv-"+rid+"-direct"); err == nil {
		t.Fatal("CHECK constraint must reject out-of-vocabulary api_level at the database boundary")
	}
	// 幂等重放：同 request_id 不产生第二行
	if err := rt.SavePrimary(ctx, mk("req-lv-"+rid+"-a", "PROBABLE_API")); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`,
		"req-lv-"+rid+"-a"); n != 1 {
		t.Fatalf("request_id idempotency broken: %d rows", n)
	}
	// List 读回：api_level 键存在于输出映射
	items, _, err := rt.List(ctx, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, it := range items {
		if it["request_id"] == "req-lv-"+rid+"-a" {
			found = true
			lv, _ := it["api_level"].(*string)
			if lv == nil || *lv != "CONFIRMED_API" {
				t.Fatalf("List api_level = %v, want CONFIRMED_API", it["api_level"])
			}
		}
	}
	if !found {
		t.Fatal("List must return the api_level event")
	}

	// findings §7 冗余列：随发现落库，口径与主事件一致
	devFP := strings.Repeat("b", 32)
	objHash := strings.Repeat("a", 32)
	fin := apiruntime.FindingInput{
		EndpointKey:       "GET /s8lv" + rid + "/users/{id}",
		RequestID:         "req-lv-" + rid + "-a",
		FindingType:       "WAF_942100",
		Severity:          "HIGH",
		Title:             "sqli " + rid,
		DeviceFingerprint: devFP,
		ObjectIdentifiers: []dsctx.ObjectIdentifier{
			{Source: "path", Param: "id", ValueHash: objHash},
		},
	}
	if err := rt.SaveFindings(ctx, []apiruntime.FindingInput{fin}); err != nil {
		t.Fatalf("SaveFindings: %v", err)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_findings
WHERE request_id=$1 AND device_fingerprint=$2
  AND object_identifiers @> '[{"source":"path","param":"id","value_hash":"`+objHash+`"}]'::jsonb`,
		fin.RequestID, devFP); n != 1 {
		t.Fatalf("finding §7 snapshot not persisted, rows = %d", n)
	}
	// 空快照（主事件缺 §7 字段的发现）→ NULL
	bare := fin
	bare.FindingType = "WAF_941100"
	bare.Title = "xss " + rid
	bare.DeviceFingerprint = ""
	bare.ObjectIdentifiers = nil
	if err := rt.SaveFindings(ctx, []apiruntime.FindingInput{bare}); err != nil {
		t.Fatalf("SaveFindings bare: %v", err)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_findings
WHERE finding_type='WAF_941100' AND title=$1
  AND device_fingerprint IS NULL AND object_identifiers IS NULL`, bare.Title); n != 1 {
		t.Fatal("bare finding must persist NULL §7 redundant columns")
	}
	// 畸形指纹被拒（不落部分发现）
	bad := fin
	bad.FindingType = "WAF_942200"
	bad.DeviceFingerprint = "not-a-fingerprint"
	if err := rt.SaveFindings(ctx, []apiruntime.FindingInput{bad}); err == nil {
		t.Fatal("non-hex finding device_fingerprint accepted")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_findings WHERE finding_type='WAF_942200' AND request_id=$1`,
		fin.RequestID); n != 0 {
		t.Fatalf("rejected finding must not persist, rows = %d", n)
	}
}
