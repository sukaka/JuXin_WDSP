// WDSP P0-04 工作流 C 接口测试：final_decision（请求最终处置上下文）server 侧
// 落库与合并契约（契约冻结 docs/tasks/wdsp-p0/S4_DESIGN_BASELINE.md §2/§7）。
// 覆盖：api_runtime_events.final_decision 落列与「已确认拦截优先」条件补全、
// security_events.final_decision 从审计行重建（例外命中分流）与去重条件更新、
// access_control_events.details.final_decision 解析合并、ListRuntimeEvents 投影。
package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/apiruntime"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/securityevents"
)

// fdJSON 构造最小合法 final_decision JSON。
func fdJSON(completion, action string) json.RawMessage {
	return json.RawMessage(fmt.Sprintf(`{"schema_version":1,"request_id":"x","gateway_node":"n1","completion_status":%q,"security_action":%q,"executor_module":"API","response_source":"ORIGIN","response_committed":true,"findings":{"observed":0,"enforced":0,"excepted":0,"skipped":0},"finalized_at":"2026-09-07T10:00:00Z"}`, completion, action))
}

// ---------- api_runtime_events.final_decision（apiruntime SavePrimary） ----------

func TestFinalDecisionAPISavePrimary(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := apiruntime.NewStore(env.db)
	reqID := "fd-api-" + uuid.NewString()

	ev := &apiruntime.PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:   reqID,
			EndpointKey: "POST /api/orders",
			FinalAction: "ALLOW",
			OccurredAt:  time.Now().UTC(),
		},
		FinalDecision: fdJSON("COMPLETED", "NONE"),
	}
	if err := store.SavePrimary(ctx, ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	var got []byte
	if err := env.db.QueryRow(ctx,
		`SELECT final_decision FROM api_runtime_events WHERE request_id = $1`, reqID).Scan(&got); err != nil {
		t.Fatalf("query final_decision: %v", err)
	}
	var probe struct {
		CompletionStatus string `json:"completion_status"`
		SecurityAction   string `json:"security_action"`
	}
	if err := json.Unmarshal(got, &probe); err != nil {
		t.Fatalf("final_decision 非法 JSON: %v", err)
	}
	if probe.CompletionStatus != "COMPLETED" || probe.SecurityAction != "NONE" {
		t.Errorf("final_decision = %s", got)
	}

	// request_id 幂等：重放不产生重复行
	ev2 := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID, EndpointKey: "POST /api/orders", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
		FinalDecision: fdJSON("COMPLETED", "NONE"),
	}
	if err := store.SavePrimary(ctx, ev2); err != nil {
		t.Fatalf("SavePrimary replay: %v", err)
	}
	var cnt int
	if err := env.db.QueryRow(ctx,
		`SELECT count(*) FROM api_runtime_events WHERE request_id = $1`, reqID).Scan(&cnt); err != nil {
		t.Fatalf("count: %v", err)
	}
	if cnt != 1 {
		t.Errorf("重放后行数 = %d, 期望 1", cnt)
	}

	// 无 final_decision 的事件落 NULL
	reqID2 := "fd-api-null-" + uuid.NewString()
	ev3 := &apiruntime.PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{RequestID: reqID2, EndpointKey: "GET /api/x", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
	}
	if err := store.SavePrimary(ctx, ev3); err != nil {
		t.Fatalf("SavePrimary null fd: %v", err)
	}
	if err := env.db.QueryRow(ctx,
		`SELECT final_decision FROM api_runtime_events WHERE request_id = $1`, reqID2).Scan(&got); err != nil {
		t.Fatalf("query null fd: %v", err)
	}
	if got != nil {
		t.Errorf("未上报 final_decision 应落 NULL, got %s", got)
	}

	// 非法 final_decision JSON 显式报错（不静默落库）
	ev4 := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: "fd-api-bad-" + uuid.NewString(), EndpointKey: "GET /api/x", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
		FinalDecision: json.RawMessage(`{invalid`),
	}
	if err := store.SavePrimary(ctx, ev4); err == nil {
		t.Error("非法 final_decision 应报错")
	}
}

func TestFinalDecisionAPIConditionalMerge(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := apiruntime.NewStore(env.db)

	// 场景1：先落 PENDING_CORRELATION（WAF 归因，NONE 动作）→ 真实证据 ABORTED 允许更新
	reqID := "fd-merge-pending-" + uuid.NewString()
	pending := fdJSON("PENDING_CORRELATION", "NONE")
	ev := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID, EndpointKey: "GET /api/dl", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
		FinalDecision: pending,
	}
	if err := store.SavePrimary(ctx, ev); err != nil {
		t.Fatalf("SavePrimary pending: %v", err)
	}
	evConfirm := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID, EndpointKey: "GET /api/dl", FinalAction: "BLOCK", OccurredAt: time.Now().UTC()},
		FinalDecision: fdJSON("ABORTED", "BLOCK"),
	}
	if err := store.SavePrimary(ctx, evConfirm); err != nil {
		t.Fatalf("SavePrimary confirm: %v", err)
	}
	var got []byte
	if err := env.db.QueryRow(ctx, `SELECT final_decision FROM api_runtime_events WHERE request_id = $1`, reqID).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	var probe struct {
		CompletionStatus string `json:"completion_status"`
	}
	if err := json.Unmarshal(got, &probe); err != nil || probe.CompletionStatus != "ABORTED" {
		t.Errorf("PENDING_CORRELATION 应被 ABORTED 更新, got %s (err=%v)", got, err)
	}

	// 场景2：已确认拦截（ABORTED+BLOCK）不被晚到观察（COMPLETED+NONE）覆盖
	reqID2 := "fd-merge-blocked-" + uuid.NewString()
	evBlock := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID2, EndpointKey: "POST /api/x", FinalAction: "BLOCK", OccurredAt: time.Now().UTC()},
		FinalDecision: fdJSON("ABORTED", "BLOCK"),
	}
	if err := store.SavePrimary(ctx, evBlock); err != nil {
		t.Fatalf("SavePrimary blocked: %v", err)
	}
	evLate := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID2, EndpointKey: "POST /api/x", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
		FinalDecision: fdJSON("COMPLETED", "NONE"),
	}
	if err := store.SavePrimary(ctx, evLate); err != nil {
		t.Fatalf("SavePrimary late: %v", err)
	}
	if err := env.db.QueryRow(ctx, `SELECT final_decision FROM api_runtime_events WHERE request_id = $1`, reqID2).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := json.Unmarshal(got, &probe); err != nil || probe.CompletionStatus != "ABORTED" {
		t.Errorf("已确认拦截不得被覆盖, got %s (err=%v)", got, err)
	}

	// 场景3：现有行 final_decision IS NULL 时补全
	reqID3 := "fd-merge-null-" + uuid.NewString()
	evNull := &apiruntime.PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{RequestID: reqID3, EndpointKey: "GET /api/y", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
	}
	if err := store.SavePrimary(ctx, evNull); err != nil {
		t.Fatalf("SavePrimary null: %v", err)
	}
	evFill := &apiruntime.PrimaryEvent{
		PrimaryEvent:  dsevents.PrimaryEvent{RequestID: reqID3, EndpointKey: "GET /api/y", FinalAction: "ALLOW", OccurredAt: time.Now().UTC()},
		FinalDecision: fdJSON("COMPLETED", "NONE"),
	}
	if err := store.SavePrimary(ctx, evFill); err != nil {
		t.Fatalf("SavePrimary fill: %v", err)
	}
	if err := env.db.QueryRow(ctx, `SELECT final_decision FROM api_runtime_events WHERE request_id = $1`, reqID3).Scan(&got); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := json.Unmarshal(got, &probe); err != nil || probe.CompletionStatus != "COMPLETED" {
		t.Errorf("NULL 行应被补全, got %s (err=%v)", got, err)
	}
}

// ---------- security_events.final_decision（securityevents ParseAuditLine + InsertEvent） ----------

// 含例外效果规则命中（id 8000002 + exc:/excv: tag）与真实攻击命中的审计行。
const fdAuditLine = `{"transaction":{"timestamp":"2026/09/07 10:00:00","unix_timestamp":1788775200,"id":"txfd1","client_ip":"192.0.2.30","client_port":41000,"request":{"method":"POST","protocol":"HTTP/1.1","uri":"/api/orders?q=1' OR '1'='1","headers":{"host":["api.test"],"x-request-id":["%s"]}},"response":{"status":0},"producer":{"rule_engine":"On","rulesets":["OWASP_CRS/4.26.0"]},"is_interrupted":true},"messages":[{"error_message":"[client \"192.0.2.30\"] Coraza: Warning. SQL Injection [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"critical\"] [tag \"attack-sqli\"]"},{"error_message":"[client \"192.0.2.30\"] Coraza: Warning. exception applied [id \"8000002\"] [msg \"jiuzhang exception effect\"] [tag \"jiuzhang-exception\"] [tag \"exc:11111111-2222-3333-4444-555555555555\"] [tag \"excv:2\"]"}]}`

func TestFinalDecisionSecurityEventNormalize(t *testing.T) {
	reqID := "fd-sec-" + uuid.NewString()
	evt, err := securityevents.ParseAuditLine([]byte(fmt.Sprintf(fdAuditLine, reqID)), "gw-node-1")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	// 例外命中分流：Matches 只含真实攻击规则
	if len(evt.Matches) != 1 || evt.Matches[0].RuleID != 942100 {
		t.Errorf("Matches = %+v（例外命中不得进入）", evt.Matches)
	}
	if evt.AttackType != "SQL_INJECTION" {
		t.Errorf("AttackType = %q", evt.AttackType)
	}
	fd := evt.FinalDecision
	if fd == nil {
		t.Fatal("FinalDecision 缺失")
	}
	if fd.CompletionStatus != "ABORTED" || fd.SecurityAction != "BLOCK" ||
		fd.ExecutorModule != "WAF" || fd.ResponseSource != "GATEWAY" {
		t.Errorf("终止事实不符: %+v", fd)
	}
	if fd.HTTPStatus != 403 || !fd.ResponseCommitted {
		t.Errorf("status/committed = %d/%v", fd.HTTPStatus, fd.ResponseCommitted)
	}
	if len(fd.RuleRefs) != 1 || fd.RuleRefs[0].RuleID != "942100" || fd.RuleRefs[0].Module != "WAF" {
		t.Errorf("rule_refs = %+v", fd.RuleRefs)
	}
	if len(fd.MatchedExceptions) != 1 {
		t.Fatalf("matched_exceptions = %+v", fd.MatchedExceptions)
	}
	me := fd.MatchedExceptions[0]
	if me.ExceptionID != "11111111-2222-3333-4444-555555555555" || me.Version != 2 || me.Target != "WAF" {
		t.Errorf("matched_exception = %+v", me)
	}
}

func TestFinalDecisionSecurityEventStore(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := securityevents.NewStore(env.db)
	reqID := "fd-sec-store-" + uuid.NewString()

	evt, err := securityevents.ParseAuditLine([]byte(fmt.Sprintf(fdAuditLine, reqID)), "gw-node-1")
	if err != nil {
		t.Fatalf("ParseAuditLine: %v", err)
	}
	id, inserted, err := store.InsertEvent(ctx, evt)
	if err != nil || !inserted {
		t.Fatalf("InsertEvent: id=%v inserted=%v err=%v", id, inserted, err)
	}
	var fdRaw []byte
	if err := env.db.QueryRow(ctx,
		`SELECT final_decision FROM security_events WHERE request_id = $1 AND occurred_at = $2`,
		reqID, evt.OccurredAt).Scan(&fdRaw); err != nil {
		t.Fatalf("query final_decision: %v", err)
	}
	var probe struct {
		CompletionStatus  string `json:"completion_status"`
		MatchedExceptions []struct {
			ExceptionID string `json:"exception_id"`
		} `json:"matched_exceptions"`
	}
	if err := json.Unmarshal(fdRaw, &probe); err != nil {
		t.Fatalf("final_decision 非法 JSON: %v", err)
	}
	if probe.CompletionStatus != "ABORTED" || len(probe.MatchedExceptions) != 1 {
		t.Errorf("final_decision = %s", fdRaw)
	}

	// 去重命中 + 「已确认拦截优先」：已有 ABORTED/BLOCK，晚到 COMPLETED/NONE 不覆盖
	dup, err := securityevents.ParseAuditLine([]byte(fmt.Sprintf(fdAuditLine, reqID)), "gw-node-1")
	if err != nil {
		t.Fatalf("ParseAuditLine dup: %v", err)
	}
	dup.FinalDecision.CompletionStatus = "COMPLETED"
	dup.FinalDecision.SecurityAction = "NONE"
	_, inserted2, err := store.InsertEvent(ctx, dup)
	if err != nil {
		t.Fatalf("InsertEvent dup: %v", err)
	}
	if inserted2 {
		t.Error("同 request_id+occurred_at 应去重")
	}
	var probe2 struct {
		CompletionStatus string `json:"completion_status"`
	}
	if err := env.db.QueryRow(ctx,
		`SELECT final_decision FROM security_events WHERE request_id = $1 AND occurred_at = $2`,
		reqID, evt.OccurredAt).Scan(&fdRaw); err != nil {
		t.Fatalf("query: %v", err)
	}
	if err := json.Unmarshal(fdRaw, &probe2); err != nil || probe2.CompletionStatus != "ABORTED" {
		t.Errorf("已确认拦截不得被覆盖, got %s (err=%v)", fdRaw, err)
	}

	// GetByID 详情投影 final_decision（P0-04 事件详情 API 证据链）
	got, _, err := store.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.FinalDecision == nil {
		t.Fatal("GetByID final_decision 投影为空")
	}
	if got.FinalDecision.CompletionStatus != "ABORTED" || got.FinalDecision.SecurityAction != "BLOCK" {
		t.Errorf("GetByID final_decision = %+v", got.FinalDecision)
	}
	if len(got.FinalDecision.MatchedExceptions) != 1 ||
		got.FinalDecision.MatchedExceptions[0].ExceptionID != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("GetByID matched_exceptions = %+v", got.FinalDecision.MatchedExceptions)
	}
}

// ---------- access_control_events.details.final_decision（accesscontrolevents） ----------

func TestFinalDecisionAccessControlParse(t *testing.T) {
	// 普通 CC 拦截事件带 final_decision → 合并进 Details
	line := fmt.Sprintf(`{"request_id":"req-fd-1","occurred_at":"2026-09-07T10:00:00Z","client_ip":"192.0.2.40","event_type":"CC_REQUEST_REJECTED","action":"REJECT","response_status":429,"final_decision":%s}`, fdJSON("ABORTED", "RATE_LIMIT"))
	evt, err := accesscontrolevents.ParseEventLine([]byte(line), "node-1")
	if err != nil {
		t.Fatalf("ParseEventLine: %v", err)
	}
	fd, ok := evt.Details["final_decision"].(map[string]interface{})
	if !ok {
		t.Fatalf("details.final_decision 缺失: %+v", evt.Details)
	}
	if fd["completion_status"] != "ABORTED" || fd["security_action"] != "RATE_LIMIT" {
		t.Errorf("final_decision = %+v", fd)
	}

	// RISK_POLICY 实断事件带 final_decision → risk 证据载荷保留 + final_decision 合并（不覆盖）
	riskLine := fmt.Sprintf(`{"request_id":"req-fd-2","occurred_at":"2026-09-07T10:01:00Z","client_ip":"192.0.2.41","event_type":"RISK_POLICY_BLOCK","action":"blocked","response_status":403,"risk":{"identity_key":"ik-1","score":80,"risk_level":"HIGH","threshold":60,"mode":"PROTECT","policy_version":3,"action_taken":"blocked","reason":"identity_risk_policy","signals":[{"type":"HEADLESS-001","score":80,"at":"2026-09-07T10:00:59Z"}]},"final_decision":%s}`, fdJSON("ABORTED", "BLOCK"))
	evt2, err := accesscontrolevents.ParseEventLine([]byte(riskLine), "node-1")
	if err != nil {
		t.Fatalf("ParseEventLine risk: %v", err)
	}
	if evt2.Details["identity_key"] != "ik-1" {
		t.Errorf("risk details 被覆盖: %+v", evt2.Details)
	}
	if _, ok := evt2.Details["final_decision"]; !ok {
		t.Errorf("risk 事件 final_decision 未合并: %+v", evt2.Details)
	}

	// 非法 final_decision → 解析失败（入错误文件纪律，不静默落库）
	badLine := `{"request_id":"req-fd-3","occurred_at":"2026-09-07T10:02:00Z","client_ip":"192.0.2.42","event_type":"CC_REQUEST_REJECTED","action":"REJECT","final_decision":{invalid}}`
	if _, err := accesscontrolevents.ParseEventLine([]byte(badLine), "node-1"); err == nil {
		t.Error("非法 final_decision 应解析失败")
	}

	// 无 final_decision 的历史事件：Details 保持空（零变化）
	oldLine := `{"request_id":"req-fd-4","occurred_at":"2026-09-07T10:03:00Z","client_ip":"192.0.2.43","event_type":"IP_DENY_MATCH","action":"DENY","response_status":403}`
	evt4, err := accesscontrolevents.ParseEventLine([]byte(oldLine), "node-1")
	if err != nil {
		t.Fatalf("ParseEventLine old: %v", err)
	}
	if _, ok := evt4.Details["final_decision"]; ok {
		t.Error("历史事件不应有 final_decision 键")
	}
}

// ---------- ListRuntimeEvents final_decision 投影（apisecurity） ----------

func TestFinalDecisionRuntimeEventProjection(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()
	store := apiruntime.NewStore(env.db)
	reqID := "fd-proj-" + uuid.NewString()
	ev := &apiruntime.PrimaryEvent{
		PrimaryEvent: dsevents.PrimaryEvent{
			RequestID:   reqID,
			EndpointKey: "POST /api/proj",
			FinalAction: "BLOCK",
			OccurredAt:  time.Now().UTC(),
		},
		FinalDecision: fdJSON("ABORTED", "BLOCK"),
	}
	if err := store.SavePrimary(ctx, ev); err != nil {
		t.Fatalf("SavePrimary: %v", err)
	}
	sec := apisecurity.NewStore(env.db)
	list, _, err := sec.ListRuntimeEvents(ctx, "POST /api/proj", "", "", 1, 50)
	if err != nil {
		t.Fatalf("ListRuntimeEvents: %v", err)
	}
	var found *apisecurity.RuntimeEvent
	for i := range list {
		if list[i].RequestID == reqID {
			found = &list[i]
			break
		}
	}
	if found == nil {
		t.Fatal("事件未在列表中")
	}
	if len(found.FinalDecision) == 0 {
		t.Fatal("final_decision 投影为空")
	}
	var probe struct {
		CompletionStatus string `json:"completion_status"`
	}
	if err := json.Unmarshal(found.FinalDecision, &probe); err != nil || probe.CompletionStatus != "ABORTED" {
		t.Errorf("final_decision = %s (err=%v)", found.FinalDecision, err)
	}
}
