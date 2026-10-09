// apistrongflow_runtime_test.go NG-FLOW-02 装配与请求链测试：运行时装配（D8）、
// BLOCK 分支 403 统一 JSON（committed 直写）、OBSERVE 只记录、UNKNOWN 放行+披露、
// 事件 strong_flow 冻结形状、能力自报 flow/1、v1 快照（无 api_strong_flows 段）零变化。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
)

// fakeSFlowEval 模块级可编程 Eval 替身（flowguard.Evaluator 结构化满足；
// 按脚本特征分派——reserve 用 reply，commit 用 commitReply（nil 回落 reply），
// err 非空时全部失败）。
type fakeSFlowEval struct {
	reply       []interface{}
	commitReply []interface{}
	err         error
}

func (f *fakeSFlowEval) Eval(_ context.Context, script string, _ []string, _ []string) ([]interface{}, error) {
	if f.err != nil {
		return nil, f.err
	}
	if strings.Contains(script, "confirmed_ms") && f.commitReply != nil {
		return f.commitReply, nil
	}
	return f.reply, nil
}

// newStrongFlowTestGuard 构造带强流程运行时的 Guard（不经过 Provision——与
// newAPITestGuard 同形态直接注入装配产物；定义经 flowguard.BuildRegistry 真实校验）。
func newStrongFlowTestGuard(t *testing.T, defMode, engineMode string, eval *fakeSFlowEval) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, engineMode, nil)
	def := flowguard.Definition{
		ID: "d-sf-1", ApplicationID: "app-1", Name: "checkout", Version: 3,
		Status: flowguard.StatusActive, BindingPathPrefix: "/v1/orders",
		InstanceKeyParam: "query:order_id", Mode: defMode,
		Steps: []flowguard.Step{
			{StepKey: "create", EndpointKey: "POST /v1/orders", Sequence: 1,
				SuccessRule:    json.RawMessage(`{"status_codes":[200]}`),
				TimeoutSeconds: 60, RetrySemantics: flowguard.RetryIdempotent, LeaseSeconds: 30},
			{StepKey: "pay", EndpointKey: "POST /v1/orders/{id}/pay", Sequence: 2,
				SuccessRule:    json.RawMessage(`{"status_codes":[200]}`),
				TimeoutSeconds: 60, RetrySemantics: flowguard.RetryNotRetryable, LeaseSeconds: 30},
		},
	}
	reg, err := flowguard.BuildRegistry([]flowguard.Definition{def})
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	g.apiStrongFlows = reg
	g.apiStrongFlowIndex = flowguard.IndexByEndpoint(reg)
	g.strongFlowRuntime = &flowguard.Runtime{
		Store:   flowguard.NewStore(eval, nil),
		HMACKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	return g, logPath
}

// TestStrongFlowProtectViolationDenied PROTECT 双闸全真：违规 403 统一 JSON
// committed 直写（源站不到达）；事件 details 含 reason_code，strong_flow 条目冻结形状。
func TestStrongFlowProtectViolationDenied(t *testing.T) {
	eval := &fakeSFlowEval{reply: []interface{}{int64(3), "FLOW-RESERVE-001", int64(0), "predecessor_unconfirmed", int64(0), int64(0)}}
	g, logPath := newStrongFlowTestGuard(t, flowguard.ModeProtect, "PROTECT", eval)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders/7/pay?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-sf-block-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if called {
		t.Fatal("违规请求不得到达源站")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	wantBody := `{"code":"FLOW_VIOLATION_DENIED","message":"流程状态不允许该操作","request_id":"req-sf-block-1"}`
	if rec.Body.String() != wantBody {
		t.Fatalf("body = %q，应精确等于 %q（不泄露实例细节）", rec.Body.String(), wantBody)
	}
	if rec.Header().Get("X-Jiuzhang-Request-ID") != "req-sf-block-1" {
		t.Fatalf("request id header = %q", rec.Header().Get("X-Jiuzhang-Request-ID"))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	if recs[0].FinalAction != "BLOCK" || recs[0].ResponseStatus != 403 {
		t.Fatalf("事件 final_action/status = %s/%d", recs[0].FinalAction, recs[0].ResponseStatus)
	}
	// strong_flow 冻结字段形状（字段名逐一钉死——server 采集轨按名消费）
	if len(recs[0].StrongFlow) != 1 {
		t.Fatalf("strong_flow 条目数 = %d", len(recs[0].StrongFlow))
	}
	entry := recs[0].StrongFlow[0]
	if entry.Action != "RESERVE" || entry.Result != "REJECTED" || entry.ReasonCode != "FLOW-RESERVE-001" ||
		entry.DefinitionID != "d-sf-1" || entry.DefinitionVersion != 3 || entry.StepKey != "pay" ||
		entry.LeaseSeconds != 30 || !strings.HasPrefix(entry.InstanceID, "sfref:") || entry.OccurredAt.IsZero() {
		t.Fatalf("strong_flow 条目 = %+v", entry)
	}
	// 原始 JSON 键名冻结核对（采集契约逐字）
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(mustReadRawLine(t, logPath)), &raw); err != nil {
		t.Fatal(err)
	}
	var sf []map[string]json.RawMessage
	if err := json.Unmarshal(raw["strong_flow"], &sf); err != nil {
		t.Fatalf("strong_flow 原始形状: %v", err)
	}
	for _, k := range []string{"definition_id", "definition_version", "instance_id", "step_key", "action",
		"fencing_token", "lease_seconds", "result", "reason_code", "occurred_at"} {
		if _, ok := sf[0][k]; !ok {
			t.Fatalf("strong_flow 缺冻结键 %q: %v", k, sf[0])
		}
	}
}

// TestStrongFlowObserveRecordsOnly OBSERVE 定义：违规只记录不实断（源站到达）。
func TestStrongFlowObserveRecordsOnly(t *testing.T) {
	eval := &fakeSFlowEval{reply: []interface{}{int64(3), "FLOW-RESERVE-001", int64(0), "predecessor_unconfirmed", int64(0), int64(0)}}
	g, logPath := newStrongFlowTestGuard(t, flowguard.ModeObserve, "PROTECT", eval)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders/7/pay?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-sf-obs-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("OBSERVE 应放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || len(recs[0].StrongFlow) != 1 || recs[0].StrongFlow[0].Result != "REJECTED" {
		t.Fatalf("OBSERVE 事件应如实记录违规: %+v", recs)
	}
	if recs[0].FinalAction == "BLOCK" {
		t.Fatal("OBSERVE 定义绝不定案 BLOCK")
	}
}

// TestStrongFlowUnknownPasses D8：Valkey 故障 → UNKNOWN 放行 + dependency_unavailable
// 披露，绝不映射 403（PROTECT 定义 + PROTECT 引擎双闸下依然放行）。
func TestStrongFlowUnknownPasses(t *testing.T) {
	eval := &fakeSFlowEval{err: errors.New("valkey down")}
	g, logPath := newStrongFlowTestGuard(t, flowguard.ModeProtect, "PROTECT", eval)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders/7/pay?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-sf-unknown-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("UNKNOWN 应放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || len(recs[0].StrongFlow) != 1 || recs[0].StrongFlow[0].Result != "UNKNOWN" ||
		recs[0].StrongFlow[0].ReasonCode != "UNKNOWN-001" {
		t.Fatalf("UNKNOWN 事件 = %+v", recs)
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "flowguard.unknown" && m.Evidence["dependency_unavailable"] == "true" {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺 dependency_unavailable 披露: %+v", recs[0].Details)
	}
}

// TestStrongFlowReserveOKEvent 合法首步预留+响应回程 commit（NG-FLOW-03 接线后
// 完整链）：INSTANCE_NEW + RESERVE + COMMIT 条目，请求照常放行（ALLOW 无定案明细）。
func TestStrongFlowReserveOKEvent(t *testing.T) {
	eval := &fakeSFlowEval{
		reply:       []interface{}{int64(0), "", int64(1), "reserved", int64(1), int64(0)},
		commitReply: []interface{}{int64(0), "", int64(1), "instance_confirmed", int64(4), int64(0)},
	}
	g, logPath := newStrongFlowTestGuard(t, flowguard.ModeProtect, "PROTECT", eval)

	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-42", nil)
	req.Header.Set("X-Request-Id", "req-sf-ok-1")
	req.Header.Set("Idempotency-Key", "op-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("合法预留应放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || len(recs[0].StrongFlow) != 4 {
		t.Fatalf("条目 = %+v", recs)
	}
	chain := []string{"INSTANCE_NEW", "RESERVE", "COMMIT", "INSTANCE_CONFIRMED"}
	for i, want := range chain {
		if recs[0].StrongFlow[i].Action != want || recs[0].StrongFlow[i].Result != "OK" {
			t.Fatalf("条目[%d] = %+v，应 %s/OK", i, recs[0].StrongFlow[i], want)
		}
	}
	if recs[0].StrongFlow[1].FencingToken != 1 {
		t.Fatalf("RESERVE token = %d", recs[0].StrongFlow[1].FencingToken)
	}
}

// TestStrongFlowAbsentZeroBehavior v1 快照（无 api_strong_flows 段）零变化：
// 装配产物 nil、请求链无 strong_flow 键、无 violation 明细。
func TestStrongFlowAbsentZeroBehavior(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	if g.apiStrongFlowIndex != nil || g.strongFlowRuntime != nil {
		t.Fatal("段缺失时装配产物必须为 nil")
	}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-42", nil)
	req.Header.Set("X-Request-Id", "req-sf-none-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("v1 快照应零变化放行: called=%v code=%d", called, rec.Code)
	}
	data := mustReadRawLine(t, logPath)
	if strings.Contains(data, "strong_flow") || strings.Contains(data, "flowguard") {
		t.Fatalf("无定义事件不得含 strong_flow/flowguard 痕迹: %s", data)
	}
}

// TestProvisionStrongFlowRuntimeNoValkey D8 装配纪律：定义存在但无 Valkey 连接 →
// 运行时装配为「恒 UNKNOWN」而非拒载/本地内存（Warn 留痕）；请求放行+披露。
func TestProvisionStrongFlowRuntimeNoValkey(t *testing.T) {
	raw := `{"app_id":"app-1","app_code":"shop","events_log":"` + t.TempDir() + `/events.log",
		"api_dynamic_protection":true,"api_protection_mode":"PROTECT",
		"api_authz_object_hmac_key_hex":"3031323334353637383961626364656630313233343536373839616263646566",
		"api_strong_flows":[{"id":"d1","application_id":"app-1","name":"f","version":1,"status":"ACTIVE",
			"binding_path_prefix":"/v1","instance_key_param":"query:order_id","mode":"PROTECT",
			"steps":[{"step_key":"a","endpoint_key":"POST /v1/orders","sequence":1,
				"success_rule":{"status_codes":[200]},"timeout_seconds":15,"retry_semantics":"IDEMPOTENT","lease_seconds":15}]}]}`
	var g Guard
	if err := json.Unmarshal([]byte(raw), &g); err != nil {
		t.Fatal(err)
	}
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("无 Valkey 不应拒载（D8 UNKNOWN 语义）: %v", err)
	}
	t.Cleanup(func() { _ = g.Cleanup() })
	if g.strongFlowRuntime == nil || g.strongFlowRuntime.Store == nil {
		t.Fatal("运行时应装配（恒 UNKNOWN 承载）")
	}
	res := g.strongFlowRuntime.Store.Reserve("sfref:x", "a", nil, 15, "", "", true)
	if res.Outcome != "UNKNOWN" || res.Detail != "valkey_unconfigured" {
		t.Fatalf("无 Valkey 应恒 UNKNOWN: %+v", res)
	}
}

// TestCapabilityReportFlowguard 能力自报含 flowguard=flow/1（D12 能力门承载）。
func TestCapabilityReportFlowguard(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "n1"}, time.Now())
	for _, d := range m.Detectors {
		if d.Name == "flowguard" && d.Version == "flow/1" {
			return
		}
	}
	t.Fatalf("能力清单缺 flowguard/flow/1: %+v", m.Detectors)
}

// mustReadRawLine 读事件文件末行（原始 JSON 键名核对用）。
func mustReadRawLine(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		t.Fatal("事件文件为空")
	}
	return lines[len(lines)-1]
}
