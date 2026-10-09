// apistrongflow_finalize_test.go NG-FLOW-03 响应回程端到端：判定命中 commit /
// fencing 过期拒绝 / allows_202 受理待完成 / 体超限与下游错误 INDETERMINATE /
// 记录器透传纪律 / NG-T-C01 零行为。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// newSFReqCtx/newSFParsed 强流程测试最小上下文与解析产物。
func newSFReqCtx(t *testing.T, reqID string) *dsctx.RequestContext {
	t.Helper()
	return dsctx.New(reqID, dsctx.DefaultParseLimits())
}

func newSFParsed(rawPath string, query map[string]string) *parser.Parsed {
	return &parser.Parsed{Method: "POST", RawPath: rawPath, NormalizedPath: rawPath, Query: query}
}

// finalizeEval 按 Lua 脚本特征分派罐装结果（reserve/commit/accepted/indeterminate）。
type finalizeEval struct {
	byKind map[string][]interface{}
}

func (f *finalizeEval) Eval(_ context.Context, script string, _, _ []string) ([]interface{}, error) {
	switch {
	case strings.Contains(script, "accepted_ms"):
		return f.byKind["accepted"], nil
	case strings.Contains(script, "indeterminate_ms"):
		return f.byKind["indeterminate"], nil
	case strings.Contains(script, "confirmed_ms"):
		return f.byKind["commit"], nil
	default:
		return f.byKind["reserve"], nil
	}
}

// newFinalizeGuard 构造带成功判定式定义的 Guard（响应回程测试）。
// ruleJSON 为步骤 success_rule 原文；allows202 控制步骤 allows_202。
func newFinalizeGuard(t *testing.T, ruleJSON string, allows202 bool, eval *finalizeEval) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	def := flowguard.Definition{
		ID: "d-fin-1", ApplicationID: "app-1", Name: "checkout", Version: 1,
		Status: flowguard.StatusActive, BindingPathPrefix: "/v1/orders",
		InstanceKeyParam: "query:order_id", Mode: flowguard.ModeProtect,
		Steps: []flowguard.Step{
			{StepKey: "create", EndpointKey: "POST /v1/orders", Sequence: 1,
				SuccessRule:    json.RawMessage(ruleJSON),
				TimeoutSeconds: 60, RetrySemantics: flowguard.RetryIdempotent,
				LeaseSeconds: 30, Allows202: allows202},
		},
	}
	reg, err := flowguard.BuildRegistry([]flowguard.Definition{def})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	g.apiStrongFlows = reg
	g.apiStrongFlowIndex = flowguard.IndexByEndpoint(reg)
	g.strongFlowRuntime = &flowguard.Runtime{
		Store:   flowguard.NewStore(eval, nil),
		HMACKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	return g, logPath
}

func reserveOKReply() []interface{} {
	return []interface{}{int64(0), "", int64(1), "reserved", int64(1), int64(0)}
}

// TestFinalizeRuleHitCommitsE2E 判定命中 → commit OK（INSTANCE_NEW+RESERVE+COMMIT
// 条目链完整；响应透传不受影响）。
func TestFinalizeRuleHitCommitsE2E(t *testing.T) {
	eval := &finalizeEval{byKind: map[string][]interface{}{
		"reserve": reserveOKReply(),
		"commit":  {int64(0), "", int64(1), "instance_confirmed", int64(4), int64(0)},
	}}
	g, logPath := newFinalizeGuard(t, `{"status_codes":[200],"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`, false, eval)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"PAID"}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", strings.NewReader(`{"amount":100}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-fin-hit-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"PAID"`) {
		t.Fatalf("响应应原样透传: code=%d body=%q", rec.Code, rec.Body.String())
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var actions []string
	for _, e := range recs[0].StrongFlow {
		actions = append(actions, fmt.Sprintf("%s/%s", e.Action, e.Result))
	}
	want := []string{"INSTANCE_NEW/OK", "RESERVE/OK", "COMMIT/OK", "INSTANCE_CONFIRMED/OK"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Fatalf("动作链 = %v，应 %v", actions, want)
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "flowguard.step_confirmed" && m.Evidence["jsonpath_actual"] == "PAID" {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺 step_confirmed 判定读数: %+v", recs[0].Details)
	}
}

// TestFinalizeCommitFenceStaleE2E commit fencing 过期被拒：COMMIT REJECTED
// FENCE-001 如实（不静默），不入 INDETERMINATE。
func TestFinalizeCommitFenceStaleE2E(t *testing.T) {
	eval := &finalizeEval{byKind: map[string][]interface{}{
		"reserve": reserveOKReply(),
		"commit":  {int64(3), "FENCE-001", int64(2), "stale_token", int64(0), int64(0)},
	}}
	g, logPath := newFinalizeGuard(t, `{"status_codes":[200]}`, false, eval)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-fin-fence-1")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	last := recs[0].StrongFlow[len(recs[0].StrongFlow)-1]
	if last.Action != "COMMIT" || last.Result != "REJECTED" || last.ReasonCode != "FENCE-001" || last.FencingToken != 2 {
		t.Fatalf("末条目 = %+v", last)
	}
	for _, e := range recs[0].StrongFlow {
		if e.Action == "INSTANCE_INDETERMINATE" {
			t.Fatal("fencing 拒绝不得入 INDETERMINATE")
		}
	}
}

// TestFinalizeAccepted202E2E allows_202：202 → 受理待完成（RESERVE OK
// FLOW-ACCEPTED-202），不自动完成（无 COMMIT/INSTANCE_CONFIRMED）。
func TestFinalizeAccepted202E2E(t *testing.T) {
	eval := &finalizeEval{byKind: map[string][]interface{}{
		"reserve":  reserveOKReply(),
		"accepted": {int64(0), "", int64(1), "accepted_202", int64(0), int64(0)},
	}}
	g, logPath := newFinalizeGuard(t, `{"status_codes":[200]}`, true, eval)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"PENDING"}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-fin-202-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("202 应透传: %d", rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var accepted, committed, confirmed bool
	for _, e := range recs[0].StrongFlow {
		if e.Action == "RESERVE" && e.ReasonCode == "FLOW-ACCEPTED-202" {
			accepted = true
		}
		if e.Action == "COMMIT" {
			committed = true
		}
		if e.Action == "INSTANCE_CONFIRMED" {
			confirmed = true
		}
	}
	if !accepted || committed || confirmed {
		t.Fatalf("202 应受理不完成: accepted=%v committed=%v confirmed=%v", accepted, committed, confirmed)
	}
}

// TestFinalizeBodyOverLimitE2E 体超 64KB：判定不命中 UNKNOWN → INDETERMINATE；
// 原响应完整透传不截断（fail-open 不影响响应本身）。
func TestFinalizeBodyOverLimitE2E(t *testing.T) {
	eval := &finalizeEval{byKind: map[string][]interface{}{
		"reserve":       reserveOKReply(),
		"indeterminate": {int64(0), "", int64(0), "marked", int64(0), int64(0)},
	}}
	g, logPath := newFinalizeGuard(t, `{"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`, false, eval)

	big := `{"status":"PAID","pad":"` + strings.Repeat("x", 128<<10) + `"}`
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(big))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-fin-big-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Body.Len() != len(big) {
		t.Fatalf("响应体必须完整透传: got %d want %d", rec.Body.Len(), len(big))
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var ind bool
	for _, e := range recs[0].StrongFlow {
		if e.Action == "INSTANCE_INDETERMINATE" && e.Result == "UNKNOWN" {
			ind = true
		}
	}
	if !ind {
		t.Fatalf("缺 INDETERMINATE 条目: %+v", recs[0].StrongFlow)
	}
	var detail string
	for _, m := range recs[0].Details {
		if m.RuleID == "flowguard.step_unknown" {
			detail = m.Evidence["detail"]
		}
	}
	if detail != "body_over_limit" {
		t.Fatalf("detail = %q，应 body_over_limit", detail)
	}
}

// TestFinalizeDownstreamErrorE2E 下游错误（超时/连接失败）：F04 UNKNOWN →
// INDETERMINATE，绝不自动 release（事件链无 RELEASE）。
func TestFinalizeDownstreamErrorE2E(t *testing.T) {
	eval := &finalizeEval{byKind: map[string][]interface{}{
		"reserve":       reserveOKReply(),
		"indeterminate": {int64(0), "", int64(0), "marked", int64(0), int64(0)},
	}}
	g, logPath := newFinalizeGuard(t, `{"status_codes":[200]}`, false, eval)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		return errors.New("origin dial timeout")
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-fin-err-1")
	_ = g.serveNext(httptest.NewRecorder(), req, next) // 错误传播给 caddy 错误链

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var ind bool
	for _, e := range recs[0].StrongFlow {
		if e.Action == "RELEASE" {
			t.Fatal("F04 红线：绝不自动 release")
		}
		if e.Action == "INSTANCE_INDETERMINATE" {
			ind = true
		}
	}
	if !ind {
		t.Fatalf("缺 INDETERMINATE: %+v", recs[0].StrongFlow)
	}
	var detail string
	for _, m := range recs[0].Details {
		if m.RuleID == "flowguard.step_unknown" {
			detail = m.Evidence["detail"]
		}
	}
	if detail != "downstream_error" {
		t.Fatalf("detail = %q，应 downstream_error", detail)
	}
}

// TestFinalizeAbsentZeroBehaviorE2E NG-T-C01：无定义 → 不包装记录器，
// 响应与事件与历史版本完全一致。
func TestFinalizeAbsentZeroBehaviorE2E(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"PAID"}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders?order_id=o-1", nil)
	req.Header.Set("X-Request-Id", "req-fin-none-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Code != http.StatusOK || rec.Body.String() != `{"status":"PAID"}` {
		t.Fatalf("响应不一致: %d %q", rec.Code, rec.Body.String())
	}
	recs := readAPIRecords(t, logPath)
	for _, r := range recs {
		if len(r.StrongFlow) != 0 {
			t.Fatalf("无定义不得有 strong_flow: %+v", r.StrongFlow)
		}
	}
}

// TestStrongFlowRecorderPassthrough 记录器透传纪律单测：状态行/体逐字节一致、
// 1xx 处理、超限直通、重复 WriteHeader 忽略。
func TestStrongFlowRecorderPassthrough(t *testing.T) {
	g := &Guard{}
	// 无运行时：原 writer 直返（零包装）
	base := httptest.NewRecorder()
	if w, rec := g.wrapStrongFlowResponse(base, nil); rec != nil || w != base {
		t.Fatal("无运行时应原样返回 writer")
	}
	// 经请求相位 Evaluate 产出真实预留（body 判定式 → 记录器采集体）
	fe := &finalizeEval{byKind: map[string][]interface{}{"reserve": reserveOKReply()}}
	rt := &flowguard.Runtime{
		Store:   flowguard.NewStore(fe, nil),
		HMACKey: []byte("0123456789abcdef0123456789abcdef"),
	}
	def := flowguard.Definition{
		ID: "d-rec-1", ApplicationID: "app-1", Name: "f", Version: 1,
		Status: flowguard.StatusActive, BindingPathPrefix: "/v1",
		InstanceKeyParam: "query:order_id", Mode: flowguard.ModeObserve,
		Steps: []flowguard.Step{{StepKey: "create", EndpointKey: "POST /v1/orders", Sequence: 1,
			SuccessRule:    json.RawMessage(`{"body_jsonpath_equals":{"path":"$.status","value":"PAID"}}`),
			TimeoutSeconds: 60, RetrySemantics: flowguard.RetryIdempotent, LeaseSeconds: 30}},
	}
	rc := newSFReqCtx(t, "req-rec-1")
	parsed := newSFParsed("/v1/orders", map[string]string{"order_id": "o-1"})
	flowguard.Evaluate(rc, httptest.NewRequest("POST", "/v1/orders?order_id=o-1", nil), parsed, "POST /v1/orders",
		[]flowguard.BoundStep{{Definition: def, Step: def.Steps[0]}}, rt, nil, "key:abc", false)
	if flowguard.ReservationFromContext(rc) == nil {
		t.Fatal("预留未产出")
	}
	g.strongFlowRuntime = rt
	w, rec := g.wrapStrongFlowResponse(base, rc)
	if rec == nil || !rec.captureBody {
		t.Fatal("有预留且 body 判定式应包装并采集体")
	}
	w.WriteHeader(http.StatusContinue) // 1xx 透传不采集
	w.WriteHeader(http.StatusOK)
	w.WriteHeader(http.StatusInternalServerError) // 重复忽略
	if rec.status != http.StatusOK {
		t.Fatalf("记录器状态 = %d，应 200（1xx 不采集、重复忽略）", rec.status)
	}
	if base.Code != http.StatusContinue {
		t.Fatalf("1xx 应透传底层（httptest 记录首码 100）: %d", base.Code)
	}
	payload := strings.Repeat("a", 70<<10)
	if _, err := w.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if base.Body.Len() != len(payload) {
		t.Fatalf("体必须完整透传: %d", base.Body.Len())
	}
	if !rec.truncated || rec.body.Len() != 64<<10 {
		t.Fatalf("采样应有界 64KB 并置 truncated: %d %v", rec.body.Len(), rec.truncated)
	}
	// status-codes-only 判定：不采集体（零体开销纪律）
	fe2 := &finalizeEval{byKind: map[string][]interface{}{"reserve": reserveOKReply()}}
	rt2 := &flowguard.Runtime{Store: flowguard.NewStore(fe2, nil), HMACKey: rt.HMACKey}
	def2 := def
	def2.Steps[0].SuccessRule = json.RawMessage(`{"status_codes":[200]}`)
	rc2 := newSFReqCtx(t, "req-rec-2")
	flowguard.Evaluate(rc2, httptest.NewRequest("POST", "/v1/orders?order_id=o-1", nil), parsed, "POST /v1/orders",
		[]flowguard.BoundStep{{Definition: def2, Step: def2.Steps[0]}}, rt2, nil, "key:abc", false)
	g.strongFlowRuntime = rt2
	if _, rec2 := g.wrapStrongFlowResponse(httptest.NewRecorder(), rc2); rec2 == nil || rec2.captureBody {
		t.Fatal("纯码判定应包装但不采集体")
	}
}
