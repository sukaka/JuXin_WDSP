// api_runtime_context_fields_test.go 阶段8 任务书 §7 字段（迁移 000150）实库验证：
//  1. 迁移 SQL 静态一致性（无数据库依赖）——up/down 成对、IF [NOT] EXISTS 守卫齐全；
//  2. 集成验证（依赖真实 PostgreSQL，无环境自动 skip）——新列写入/读回、
//     旧版事件零值落 NULL、request_id 幂等重放不覆盖、明文形态值被拒绝。
package tests

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// TestAPIContextFieldsMigrationStatic 000150 up+down 静态一致性（复用 000035 同款对账口径）。
func TestAPIContextFieldsMigrationStatic(t *testing.T) {
	up := readMigration(t, "000150_api_runtime_context_fields.up.sql")
	down := readMigration(t, "000150_api_runtime_context_fields.down.sql")

	adds := addColumnRe.FindAllStringSubmatch(up, -1)
	if len(adds) != 2 {
		t.Fatalf("000150 up: want 2 guarded ADD COLUMN, got %v", adds)
	}
	drops := map[string]bool{}
	for _, m := range dropColumnRe.FindAllStringSubmatch(down, -1) {
		drops[m[1]] = true
	}
	for _, m := range adds {
		if !drops[m[1]] {
			t.Errorf("000150: up adds column %s but down does not drop it", m[1])
		}
		delete(drops, m[1])
	}
	for col := range drops {
		t.Errorf("000150: down drops column %s but up does not add it", col)
	}
	allAdds := len(regexp.MustCompile(`(?i)ADD\s+COLUMN`).FindAllString(up, -1))
	if allAdds != len(adds) {
		t.Errorf("000150 up: %d ADD COLUMN but only %d guarded with IF NOT EXISTS", allAdds, len(adds))
	}
	for _, col := range []string{"device_fingerprint", "object_identifiers"} {
		if !strings.Contains(up, col) {
			t.Errorf("000150 up: column %s missing", col)
		}
	}
	if strings.Contains(up, "NOT NULL") {
		t.Error("000150 up: §7 columns must stay nullable")
	}
	if !strings.Contains(up, "BEGIN;") || !strings.Contains(up, "COMMIT;") ||
		!strings.Contains(down, "BEGIN;") || !strings.Contains(down, "COMMIT;") {
		t.Error("000150 up/down must be wrapped in BEGIN/COMMIT")
	}
}

// TestStage8RuntimeEventContextFields 迁移 000150 两列落位；SavePrimary §7 字段
// 写入且读回；旧版网关事件（零值）落 NULL；request_id 幂等重放不覆盖；
// 明文形态 value_hash 被拒绝（不落部分事件）。
func TestStage8RuntimeEventContextFields(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()

	// 迁移落位：两列存在且可空
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_events'
  AND column_name IN ('device_fingerprint','object_identifiers')`); n != 2 {
		t.Fatalf("§7 columns = %d, want 2", n)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM information_schema.columns
WHERE table_name='api_runtime_events'
  AND column_name IN ('device_fingerprint','object_identifiers')
  AND is_nullable='NO'`); n != 0 {
		t.Fatalf("§7 columns must be nullable, %d are NOT NULL", n)
	}

	rid := s5Rand()
	rt := apiruntime.NewStore(env.db)
	devFP := strings.Repeat("b", 32)
	objHash := strings.Repeat("a", 32)
	bodyHash := strings.Repeat("c", 32)
	mkFull := func() *apiruntime.PrimaryEvent {
		return &apiruntime.PrimaryEvent{
			PrimaryEvent: events.PrimaryEvent{
				RequestID: "req-cf-" + rid + "-1", EndpointKey: "GET /s8" + rid + "/users/{id}",
				RiskScore: 50, RiskLevel: "HIGH", FinalAction: "BLOCK",
				OccurredAt:        time.Now().UTC(),
				DeviceFingerprint: devFP,
				ObjectIdentifiers: []dsctx.ObjectIdentifier{
					{Source: "path", Param: "id", ValueHash: objHash},
					{Source: "body_json", Param: "meta.user_id", ValueHash: bodyHash},
				},
			},
		}
	}
	if err := rt.SavePrimary(ctx, mkFull()); err != nil {
		t.Fatalf("SavePrimary §7: %v", err)
	}
	// 旧版网关事件（零值新字段）→ 新列落 NULL
	legacy := &apiruntime.PrimaryEvent{
		PrimaryEvent: events.PrimaryEvent{
			RequestID: "req-cf-" + rid + "-2", EndpointKey: "GET /s8" + rid + "/legacy",
			RiskScore: 10, RiskLevel: "LOW", FinalAction: "OBSERVE",
			OccurredAt: time.Now().UTC(),
		},
	}
	if err := rt.SavePrimary(ctx, legacy); err != nil {
		t.Fatalf("SavePrimary legacy: %v", err)
	}
	// 幂等重放：同 request_id 不产生第二行、不覆盖已有列
	replay := mkFull()
	replay.DeviceFingerprint = strings.Repeat("d", 32)
	if err := rt.SavePrimary(ctx, replay); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`, "req-cf-"+rid+"-1"); n != 1 {
		t.Fatalf("request_id idempotency broken: %d rows", n)
	}

	var gotDevFP *string
	var gotObjIDsRaw []byte
	if err := env.db.QueryRow(ctx, `
SELECT device_fingerprint, object_identifiers
FROM api_runtime_events WHERE request_id=$1`, "req-cf-"+rid+"-1").
		Scan(&gotDevFP, &gotObjIDsRaw); err != nil {
		t.Fatalf("read §7 row: %v", err)
	}
	if gotDevFP == nil || *gotDevFP != devFP {
		t.Fatalf("device_fingerprint = %v, want %q", strPtr(gotDevFP), devFP)
	}
	var gotObjIDs []dsctx.ObjectIdentifier
	if err := json.Unmarshal(gotObjIDsRaw, &gotObjIDs); err != nil {
		t.Fatalf("object_identifiers not valid JSON: %v (%s)", err, gotObjIDsRaw)
	}
	if len(gotObjIDs) != 2 || gotObjIDs[0] != (dsctx.ObjectIdentifier{Source: "path", Param: "id", ValueHash: objHash}) ||
		gotObjIDs[1] != (dsctx.ObjectIdentifier{Source: "body_json", Param: "meta.user_id", ValueHash: bodyHash}) {
		t.Fatalf("object_identifiers mismatch: %+v", gotObjIDs)
	}
	if n := s8Count(t, env, `
SELECT count(*) FROM api_runtime_events WHERE request_id=$1
  AND device_fingerprint IS NULL AND object_identifiers IS NULL`, "req-cf-"+rid+"-2"); n != 1 {
		t.Fatal("legacy event must persist NULL §7 columns")
	}

	// 明文形态 value_hash 被拒绝（不落部分事件）
	bad := mkFull()
	bad.RequestID = "req-cf-" + rid + "-3"
	bad.ObjectIdentifiers = []dsctx.ObjectIdentifier{
		{Source: "path", Param: "id", ValueHash: "order-123"},
	}
	if err := rt.SavePrimary(ctx, bad); err == nil {
		t.Fatal("plaintext value_hash accepted")
	}
	if n := s8Count(t, env, `SELECT count(*) FROM api_runtime_events WHERE request_id=$1`, "req-cf-"+rid+"-3"); n != 0 {
		t.Fatalf("rejected event must not persist, rows = %d", n)
	}

	// List 读回：两键存在于输出映射
	items, _, err := rt.List(ctx, 1, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	found := false
	for _, it := range items {
		if it["request_id"] == "req-cf-"+rid+"-1" {
			found = true
			fp, _ := it["device_fingerprint"].(*string)
			if fp == nil || *fp != devFP {
				t.Fatalf("List device_fingerprint = %v", it["device_fingerprint"])
			}
			ids, _ := it["object_identifiers"].([]dsctx.ObjectIdentifier)
			if len(ids) != 2 || ids[0].ValueHash != objHash {
				t.Fatalf("List object_identifiers = %v", it["object_identifiers"])
			}
		}
	}
	if !found {
		t.Fatal("List must return the §7 event")
	}
}
