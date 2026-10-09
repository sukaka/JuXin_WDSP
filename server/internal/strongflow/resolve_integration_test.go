// resolve_integration_test.go 管理恢复 PG 契约测试（NG-FLOW-03 D5/D9，Opt-in
// AUTHZ_TEST_PG_DSN）：迁移 000178 up/up/down/up 幂等与 RESOLVE 词表放宽/回缩；
// resolve 三 action 全链（状态推进+事件落库+version+1+terminated_at）、乐观锁 409、
// 终态重复 409（幂等不误伤）、KEEP_UNKNOWN 不推进+RESOLVE 留痕去重、详情证据裁剪
// 双档与 INDETERMINATE 语义字段、HIGH 审计落行（真 audits.Service 链）。
package strongflow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/database"
)

// TestStrongFlowMigration178PostgresContract 迁移 000178：up 幂等、RESOLVE 词表放宽、
// down 清退 RESOLVE 行并回缩九词、复 up 恢复。
func TestStrongFlowMigration178PostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("rerun migrations: %v", err)
	}
	var applied int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version=178`).Scan(&applied); err != nil {
		t.Fatalf("check migration record: %v", err)
	}
	if applied != 1 {
		t.Fatalf("migration 178 records=%d, want 1", applied)
	}
	// RESOLVE 词表生效（先备实例行承载）
	var appID, defID, instID string
	code := fmt.Sprintf("sf178-%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'f',1,'ACTIVE','/','query:o') RETURNING id`, appID).Scan(&defID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_instances(application_id,definition_id,definition_version,instance_key,status) VALUES ($1,$2,1,$3,'INDETERMINATE') RETURNING id`,
		appID, defID, "sfref:"+strings.Repeat("a1", 32)).Scan(&instID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id=$1`, instID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE id=$1`, instID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE id=$1`, defID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_step_events(instance_id,step_key,action,fencing_token,result,reason_code,occurred_at) VALUES ($1,'','RESOLVE',0,'UNKNOWN','FLOW-RESOLVE-001',now())`, instID); err != nil {
		t.Fatalf("RESOLVE 词表应被 178 放宽: %v", err)
	}
	// down 八步：先回滚 000185（升级任务 executor_deadline 列，NG-REL-02 F7）、
	// 000184/000183（NG-ID 机器身份四表）、000182/000181（NG-MCP 批次 B1 两表）、
	// 000180/000179（NG-GRPC 绑定两迁移），再回滚 178：
	// 清退 RESOLVE 行 + 词表回缩（再插 RESOLVE 必拒）
	for _, v := range []int{185, 184, 183, 182, 181, 180, 179, 178} {
		if err := database.Migrate(ctx, pool, "../../migrations", "down"); err != nil {
			t.Fatalf("migrate down %d: %v", v, err)
		}
	}
	var resolveRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_strong_flow_step_events WHERE instance_id=$1 AND action='RESOLVE'`, instID).Scan(&resolveRows); err != nil {
		t.Fatal(err)
	}
	if resolveRows != 0 {
		t.Fatalf("down 应清退 RESOLVE 行: %d", resolveRows)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO api_strong_flow_step_events(instance_id,step_key,action,fencing_token,result,reason_code,occurred_at) VALUES ($1,'','RESOLVE',0,'UNKNOWN','FLOW-RESOLVE-001',now())`, instID); err == nil {
		t.Fatal("down 后 RESOLVE 应被 CHECK 拒收")
	}
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("migrate up again: %v", err)
	}
}

// TestStrongFlowResolvePostgresContract 管理恢复全链（真事务语义）。
func TestStrongFlowResolvePostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sfrs-%d", time.Now().UnixNano())
	var appID, defID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'下单支付',2,'ACTIVE','/','query:order_id') RETURNING id`, appID).Scan(&defID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM operation_audits WHERE module='api_security' AND action='resolve' AND username='tester'`)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	mkInstance := func(status string, seq int) uuid.UUID {
		var id uuid.UUID
		if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_instances(application_id,definition_id,definition_version,instance_key,status) VALUES ($1,$2,2,$3,$4) RETURNING id`,
			appID, defID, fmt.Sprintf("sfref:%064x", seq), status).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	store := NewStore(pool)

	// ① INDETERMINATE + CONFIRM_SUCCEEDED：推 CONFIRMED、version+1、terminated_at、
	//    INSTANCE_CONFIRMED 事件落库（reason_code=FLOW-RESOLVE-001）
	ind := mkInstance("INDETERMINATE", 1)
	res, err := store.ResolveInstance(ctx, ind, ResolveInput{Action: "CONFIRM_SUCCEEDED", Reason: "源站对账已入账", ExpectedVersion: 1}, "req-resolve-1")
	if err != nil {
		t.Fatalf("CONFIRM_SUCCEEDED: %v", err)
	}
	if res.BeforeStatus != "INDETERMINATE" || res.AfterStatus != "CONFIRMED" || res.AfterVersion != 2 {
		t.Fatalf("推进结果: %+v", res)
	}
	var status string
	var version int
	var terminated *time.Time
	if err := pool.QueryRow(ctx, `SELECT status, version, terminated_at FROM api_strong_flow_instances WHERE id=$1`, ind).Scan(&status, &version, &terminated); err != nil {
		t.Fatal(err)
	}
	if status != "CONFIRMED" || version != 2 || terminated == nil {
		t.Fatalf("实例行: %s/%d/%v", status, version, terminated)
	}
	var evAction, evResult, evReason, evReq string
	if err := pool.QueryRow(ctx, `SELECT action, result, reason_code, request_id FROM api_strong_flow_step_events WHERE instance_id=$1`, ind).
		Scan(&evAction, &evResult, &evReason, &evReq); err != nil {
		t.Fatal(err)
	}
	if evAction != "INSTANCE_CONFIRMED" || evResult != "OK" || evReason != "FLOW-RESOLVE-001" || evReq != "req-resolve-1" {
		t.Fatalf("推进事件: %s/%s/%s/%s", evAction, evResult, evReason, evReq)
	}
	// 终态重复恢复 409（幂等不误伤——任何 action 一律拒）
	if _, err := store.ResolveInstance(ctx, ind, ResolveInput{Action: "CONFIRM_NOT_EXECUTED", Reason: "x", ExpectedVersion: 2}, "r2"); err != ErrInstanceTerminal {
		t.Fatalf("终态 CONFIRM_NOT_EXECUTED 应 ErrInstanceTerminal: %v", err)
	}
	if _, err := store.ResolveInstance(ctx, ind, ResolveInput{Action: "KEEP_UNKNOWN", Reason: "x", ExpectedVersion: 2}, "r3"); err != ErrInstanceTerminal {
		t.Fatalf("终态 KEEP_UNKNOWN 应 ErrInstanceTerminal: %v", err)
	}
	// 不存在 404
	if _, err := store.ResolveInstance(ctx, uuid.New(), ResolveInput{Action: "KEEP_UNKNOWN", Reason: "x", ExpectedVersion: 1}, "r4"); err != ErrInstanceNotFound {
		t.Fatalf("不存在应 ErrInstanceNotFound: %v", err)
	}

	// ② ACTIVE + CONFIRM_NOT_EXECUTED：推 FAILED（明确证据进入）
	act := mkInstance("ACTIVE", 2)
	res, err = store.ResolveInstance(ctx, act, ResolveInput{Action: "CONFIRM_NOT_EXECUTED", Reason: "源站无该单记录", ExpectedVersion: 1}, "r5")
	if err != nil {
		t.Fatalf("CONFIRM_NOT_EXECUTED: %v", err)
	}
	if res.AfterStatus != "FAILED" || res.AfterVersion != 2 {
		t.Fatalf("推进结果: %+v", res)
	}
	if err := pool.QueryRow(ctx, `SELECT action FROM api_strong_flow_step_events WHERE instance_id=$1`, act).Scan(&evAction); err != nil {
		t.Fatal(err)
	}
	if evAction != "INSTANCE_FAILED" {
		t.Fatalf("事件动作: %s", evAction)
	}

	// ③ 乐观锁：版本不匹配 409 实例不动
	unk := mkInstance("INDETERMINATE", 3)
	if _, err := store.ResolveInstance(ctx, unk, ResolveInput{Action: "CONFIRM_SUCCEEDED", Reason: "x", ExpectedVersion: 7}, "r6"); err != ErrVersionConflict {
		t.Fatalf("版本冲突应 ErrVersionConflict: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT status, version FROM api_strong_flow_instances WHERE id=$1`, unk).Scan(&status, &version); err != nil {
		t.Fatal(err)
	}
	if status != "INDETERMINATE" || version != 1 {
		t.Fatalf("冲突后实例不得动: %s/%d", status, version)
	}

	// ④ KEEP_UNKNOWN：状态/version 不动 + RESOLVE 事件落库；重复重申唯一键去重仍 200 语义
	res, err = store.ResolveInstance(ctx, unk, ResolveInput{Action: "KEEP_UNKNOWN", Reason: "证据不足保持未知", ExpectedVersion: 1}, "r7")
	if err != nil {
		t.Fatalf("KEEP_UNKNOWN: %v", err)
	}
	if res.AfterStatus != "INDETERMINATE" || res.AfterVersion != 1 {
		t.Fatalf("KEEP_UNKNOWN 不得推进: %+v", res)
	}
	if err := pool.QueryRow(ctx, `SELECT action, result, reason_code FROM api_strong_flow_step_events WHERE instance_id=$1`, unk).
		Scan(&evAction, &evResult, &evReason); err != nil {
		t.Fatal(err)
	}
	if evAction != "RESOLVE" || evResult != "UNKNOWN" || evReason != "FLOW-RESOLVE-001" {
		t.Fatalf("留痕事件: %s/%s/%s", evAction, evResult, evReason)
	}
	if _, err := store.ResolveInstance(ctx, unk, ResolveInput{Action: "KEEP_UNKNOWN", Reason: "再次复核仍未知", ExpectedVersion: 1}, "r8"); err != nil {
		t.Fatalf("重复 KEEP_UNKNOWN 应仍成功（事件去重）: %v", err)
	}
	var resolveEvents int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM api_strong_flow_step_events WHERE instance_id=$1 AND action='RESOLVE'`, unk).Scan(&resolveEvents); err != nil {
		t.Fatal(err)
	}
	if resolveEvents != 1 {
		t.Fatalf("重复重申事件应去重为 1: %d", resolveEvents)
	}

	// ⑤ 详情：INDETERMINATE 语义字段 + 证据裁剪双档（PG 真读）
	d, err := store.GetInstance(ctx, unk, false)
	if err != nil {
		t.Fatal(err)
	}
	if d.StatusSemantics != "UNKNOWN_NOT_CONFIRMED" || d.StatusMessage != "未知，不显示安全通过" {
		t.Fatalf("语义字段: %q/%q", d.StatusSemantics, d.StatusMessage)
	}
	if len(d.Steps) != 1 || d.Steps[0].FencingToken != nil || d.Steps[0].ReasonCode != "" || d.Steps[0].RequestID != "" {
		t.Fatalf("无 evidence_read 明细档必须缺席: %+v", d.Steps)
	}
	d2, err := store.GetInstance(ctx, unk, true)
	if err != nil {
		t.Fatal(err)
	}
	if d2.Steps[0].FencingToken == nil || d2.Steps[0].ReasonCode != "FLOW-RESOLVE-001" || d2.Steps[0].RequestID != "r7" {
		t.Fatalf("evidence_read 明细档应带出: %+v", d2.Steps[0])
	}

	// ⑥ 审计链（真 audits.Service + httptest 全链）：resolve 成功落 HIGH 审计，
	//    after 含 action/reason/前后状态
	h := NewHandler(store, audits.NewService(pool))
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms(PermFlowRead, PermFlowManage), h)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/api-security/strong-flows/instances/"+unk.String()+"/resolve",
		strings.NewReader(`{"action":"CONFIRM_SUCCEEDED","reason":"最终确认已执行","expected_version":1}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("resolve http: %d %s", rr.Code, rr.Body.String())
	}
	var auditAction, objType, risk, before, after string
	err = pool.QueryRow(ctx, `SELECT action, object_type, risk_level, before_summary, after_summary FROM operation_audits
		WHERE object_type='api_strong_flow_instance' AND object_id=$1 ORDER BY occurred_at DESC LIMIT 1`, unk.String()).
		Scan(&auditAction, &objType, &risk, &before, &after)
	if err != nil {
		t.Fatalf("审计行: %v", err)
	}
	if auditAction != "resolve" || risk != "HIGH" {
		t.Fatalf("审计动作/风险: %s/%s", auditAction, risk)
	}
	if before != `{"status":"INDETERMINATE"}` {
		t.Fatalf("审计 before: %q", before)
	}
	for _, want := range []string{"CONFIRM_SUCCEEDED", "最终确认已执行", "INDETERMINATE", "CONFIRMED"} {
		if !strings.Contains(after, want) {
			t.Fatalf("审计 after 缺 %q: %q", want, after)
		}
	}
}

// TestStrongFlowEventTokenSemanticsPostgresContract 事件 token 语义（联调裁决 §8.4-2
// 闭环，server 消费侧核对）：fencing_token 恒为本事件自己持有的 token——
// ① F05 形态：COMMIT OK f=3 与 COMMIT REJECTED FENCE-001 f=1（被拒旧 token）
// 不同键双行在册（不再碰撞）；② 202 受理形态：首 RESERVE OK f=2 与受理
// RESERVE OK f=3（轮换新 token）不同键双行在册。
func TestStrongFlowEventTokenSemanticsPostgresContract(t *testing.T) {
	pool, ctx := openStrongFlowPG(t)
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatalf("apply migrations: %v", err)
	}
	code := fmt.Sprintf("sftk-%d", time.Now().UnixNano())
	var appID, defID string
	if err := pool.QueryRow(ctx, `INSERT INTO applications(code,name) VALUES ($1,$2) RETURNING id`, code, code).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO api_strong_flow_definitions(application_id,name,version,status,binding_path_prefix,instance_key_param) VALUES ($1,'f',1,'ACTIVE','/','query:o') RETURNING id`, appID).Scan(&defID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_step_events WHERE instance_id IN (SELECT id FROM api_strong_flow_instances WHERE application_id=$1)`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_instances WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM api_strong_flow_definitions WHERE application_id=$1`, appID)
		_, _ = pool.Exec(bg, `DELETE FROM applications WHERE id=$1`, appID)
	})
	store := NewStrongFlowEventStore(pool)
	now := time.Now().UTC()
	mkEv := func(sfref, stepKey, action, result, reason string, fencing int64) *StrongFlowEvent {
		return &StrongFlowEvent{
			DefinitionID: defID, DefinitionVersion: 1, InstanceID: sfref,
			StepKey: stepKey, Action: action, FencingToken: fencing,
			Result: result, ReasonCode: reason, RequestID: "req-" + sfref[len(sfref)-4:],
			ApplicationID: appID, OccurredAt: now,
		}
	}
	// ① F05 形态：reserve f=1 → 接管 reserve f=3（EXPIRE f=1 随行）→ commit OK f=3 →
	//    迟到 commit REJECTED FENCE-001 f=1（被拒旧 token——与 COMMIT OK f=3 不同键）
	s1 := "sfref:" + strings.Repeat("b2", 32)
	for _, ev := range []*StrongFlowEvent{
		mkEv(s1, "pay", ActionReserve, ResultOK, "", 1),
		mkEv(s1, "pay", ActionExpire, ResultOK, "", 1),
		mkEv(s1, "pay", ActionReserve, ResultOK, "", 3),
		mkEv(s1, "pay", ActionCommit, ResultOK, "", 3),
		mkEv(s1, "pay", ActionCommit, ResultRejected, "FENCE-001", 1),
	} {
		if err := store.RecordStrongFlow(ctx, ev); err != nil {
			t.Fatalf("record %s f=%d: %v", ev.Action, ev.FencingToken, err)
		}
	}
	var rows []string
	r, err := pool.Query(ctx, `SELECT action || ':' || result || ':' || fencing_token || ':' || COALESCE(reason_code,'') FROM api_strong_flow_step_events
		WHERE instance_id=(SELECT id FROM api_strong_flow_instances WHERE instance_key=$1) ORDER BY occurred_at, action, fencing_token`, s1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for r.Next() {
		var s string
		if err := r.Scan(&s); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, s)
	}
	want := map[string]bool{
		"RESERVE:OK:1:": true, "EXPIRE:OK:1:": true, "RESERVE:OK:3:": true,
		"COMMIT:OK:3:": true, "COMMIT:REJECTED:1:FENCE-001": true,
	}
	if len(rows) != len(want) {
		t.Fatalf("F05 形态事件行数=%d want %d: %v", len(rows), len(want), rows)
	}
	for _, s := range rows {
		if !want[s] {
			t.Fatalf("意外事件行 %q（rows=%v）", s, rows)
		}
	}
	// ② 202 受理形态：reserve f=2 → 受理 RESERVE OK f=3（轮换新 token，FLOW-ACCEPTED-202）
	s2 := "sfref:" + strings.Repeat("c3", 32)
	for _, ev := range []*StrongFlowEvent{
		mkEv(s2, "pay", ActionReserve, ResultOK, "", 2),
		mkEv(s2, "pay", ActionReserve, ResultOK, "FLOW-ACCEPTED-202", 3),
	} {
		if err := store.RecordStrongFlow(ctx, ev); err != nil {
			t.Fatalf("record 202 %s f=%d: %v", ev.Action, ev.FencingToken, err)
		}
	}
	var n202, nReason int
	if err := pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE reason_code='FLOW-ACCEPTED-202') FROM api_strong_flow_step_events
		WHERE instance_id=(SELECT id FROM api_strong_flow_instances WHERE instance_key=$1) AND action='RESERVE'`, s2).Scan(&n202, &nReason); err != nil {
		t.Fatal(err)
	}
	if n202 != 2 || nReason != 1 {
		t.Fatalf("202 双 RESERVE 应在册 2 行（含 1 行 FLOW-ACCEPTED-202）: rows=%d reason=%d", n202, nReason)
	}
}
