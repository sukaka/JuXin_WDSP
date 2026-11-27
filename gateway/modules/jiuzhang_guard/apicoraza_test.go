package jiuzhang_guard

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// corazaInterruption 识别矩阵：仅「HandlerError + 哨兵消息」命中（与 coraza-caddy v2.6.0
// 实际返回形态一致：值类型 HandlerError{StatusCode, ID, Err: errInterruptionTriggered}）；
// 包装链经 errors.As 穿透；nil/普通错误/其他 HandlerError（反代 502、guard 自身 4xx）一律不命中。
func TestCorazaInterruption(t *testing.T) {
	if _, _, ok := corazaInterruption(nil); ok {
		t.Fatal("nil error must not match")
	}
	if _, _, ok := corazaInterruption(errors.New("interruption triggered")); ok {
		t.Fatal("bare sentinel message without HandlerError must not match")
	}
	// guard 自身阻断错误（同消息不同源不存在，这里验普通 HandlerError 不命中）
	if _, _, ok := corazaInterruption(caddyhttp.Error(http.StatusForbidden, errors.New("request blocked by api protection"))); ok {
		t.Fatal("guard's own block error must not match")
	}
	if _, _, ok := corazaInterruption(caddyhttp.Error(http.StatusBadGateway, errors.New("dial tcp: connection refused"))); ok {
		t.Fatal("upstream 502 must not match")
	}
	// 命中：coraza-caddy 实际形态（值类型 HandlerError + 哨兵消息）
	txID, status, ok := corazaInterruption(caddyhttp.HandlerError{
		StatusCode: http.StatusForbidden, ID: "tx-abc123", Err: errors.New("interruption triggered"),
	})
	if !ok || txID != "tx-abc123" || status != http.StatusForbidden {
		t.Fatalf("coraza interruption = (%q,%d,%v), want (tx-abc123,403,true)", txID, status, ok)
	}
	// 包装链穿透（中间件层 fmt.Errorf %w 包装后仍可识别）
	txID, status, ok = corazaInterruption(fmt.Errorf("route: %w", caddyhttp.HandlerError{
		StatusCode: http.StatusNotAcceptable, ID: "tx-wrapped", Err: errors.New("interruption triggered"),
	}))
	if !ok || txID != "tx-wrapped" || status != http.StatusNotAcceptable {
		t.Fatalf("wrapped interruption = (%q,%d,%v), want (tx-wrapped,406,true)", txID, status, ok)
	}
}

// attributeWAFIntercept：管线非阻断 + Coraza 中断 → 补记 waf 明细并按实记 BLOCK；
// 管线已判阻断类（BLOCK/RATE_LIMIT/TEMP_BLOCK）不重复归因；非 Coraza 错误不归因；nil 上下文安全。
func TestAttributeWAFIntercept(t *testing.T) {
	corazaErr := caddyhttp.HandlerError{
		StatusCode: http.StatusForbidden, ID: "tx-1", Err: errors.New("interruption triggered"),
	}

	// 归因主路径：ALLOW + 中断 → waf/BLOCK 明细 + final_action=BLOCK
	ctx := dsctx.New("r-attr-1", dsctx.DefaultParseLimits())
	ctx.PolicyVersion = "pv-9" // 版本快照应盖章到补记明细
	act, code, ok := attributeWAFIntercept(ctx, dsctx.ActionAllow, corazaErr)
	if !ok || act != dsctx.ActionBlock || code != http.StatusForbidden {
		t.Fatalf("attribute = (%q,%d,%v), want (BLOCK,403,true)", act, code, ok)
	}
	if ctx.GetFinalAction() != dsctx.ActionBlock {
		t.Fatalf("ctx final_action = %q, want BLOCK", ctx.GetFinalAction())
	}
	m := ctx.CopyMatches()
	if len(m) != 1 {
		t.Fatalf("want 1 waf match, got %+v", m)
	}
	d := m[0]
	if d.Detector != "waf" || d.RuleID != "waf.downstream_intercept" || d.Category != "BLOCK" || d.Severity != "HIGH" {
		t.Fatalf("bad waf match identity: %+v", d)
	}
	if d.Evidence["attribution"] != "downstream_intercept" || d.Evidence["coraza_tx_id"] != "tx-1" ||
		d.Evidence["status_code"] != "403" || d.Evidence["uncertainty"] == "" {
		t.Fatalf("bad waf match evidence: %+v", d.Evidence)
	}
	if d.Confidence != 0.9 {
		t.Fatalf("confidence = %v, want 0.9（显式覆盖 waf 默认 0.8）", d.Confidence)
	}
	if d.PolicyVersion != "pv-9" {
		t.Fatalf("policy_version = %q, want pv-9（AddMatch 快照盖章）", d.PolicyVersion)
	}

	// drop 动作形态（coraza-caddy 对非 deny 中断回退默认码 200）：归因状态码按 403 修正，
	// 原始值留证据 coraza_raw_status（记 200 会把 BLOCK 事件误标为成功响应）
	ctxDrop := dsctx.New("r-attr-drop", dsctx.DefaultParseLimits())
	act, code, ok = attributeWAFIntercept(ctxDrop, dsctx.ActionAllow, caddyhttp.HandlerError{
		StatusCode: http.StatusOK, ID: "tx-drop", Err: errors.New("interruption triggered"),
	})
	if !ok || act != dsctx.ActionBlock || code != http.StatusForbidden {
		t.Fatalf("drop attribute = (%q,%d,%v), want (BLOCK,403,true)", act, code, ok)
	}
	dm := ctxDrop.CopyMatches()
	if len(dm) != 1 || dm[0].Evidence["status_code"] != "403" || dm[0].Evidence["coraza_raw_status"] != "200" {
		t.Fatalf("drop evidence mismatch: %+v", dm)
	}
	// 合法拒绝码不修正、不留原始值（deny 真实中断码 406）
	ctxDeny := dsctx.New("r-attr-deny", dsctx.DefaultParseLimits())
	if _, code, ok = attributeWAFIntercept(ctxDeny, dsctx.ActionAllow, caddyhttp.HandlerError{
		StatusCode: http.StatusNotAcceptable, ID: "tx-deny", Err: errors.New("interruption triggered"),
	}); !ok || code != http.StatusNotAcceptable {
		t.Fatalf("deny attribute = (%d,%v), want (406,true)", code, ok)
	}
	if ev := ctxDeny.CopyMatches()[0].Evidence; ev["status_code"] != "406" || ev["coraza_raw_status"] != "" {
		t.Fatalf("deny evidence must keep real code without raw fallback: %+v", ev)
	}

	// 不重复归因：管线已判阻断类动作（含 OBSERVE 模式的 BLOCK 明细不归此列——此处按 final_action 判）
	for _, fa := range []dsctx.FinalAction{dsctx.ActionBlock, dsctx.ActionRateLimit, dsctx.ActionTempBlock} {
		ctxB := dsctx.New("r-attr-dup", dsctx.DefaultParseLimits())
		act, _, ok := attributeWAFIntercept(ctxB, fa, corazaErr)
		if ok || act != fa {
			t.Fatalf("final_action=%q must not be re-attributed: (%q,%v)", fa, act, ok)
		}
		if ctxB.MatchCount() != 0 {
			t.Fatalf("final_action=%q must not add waf match: %+v", fa, ctxB.CopyMatches())
		}
	}

	// 非 Coraza 错误不归因
	ctxO := dsctx.New("r-attr-other", dsctx.DefaultParseLimits())
	if _, _, ok := attributeWAFIntercept(ctxO, dsctx.ActionAllow, caddyhttp.Error(http.StatusBadGateway, errors.New("dial"))); ok {
		t.Fatal("non-coraza error must not attribute")
	}
	if ctxO.MatchCount() != 0 || ctxO.GetFinalAction() != dsctx.ActionUnset {
		t.Fatalf("non-coraza error must leave ctx untouched: %+v", ctxO.CopyMatches())
	}

	// nil 上下文安全（不 panic、不归因）
	if _, _, ok := attributeWAFIntercept(nil, dsctx.ActionAllow, corazaErr); ok {
		t.Fatal("nil ctx must not attribute")
	}
}

// Coraza 合流集成：统一管线放行（ALLOW）但下游 coraza-caddy 中断（403 哨兵错误）
// → 事件按实记 final_action=BLOCK、response_status=403，details 含 detector="waf" 归因明细。
func TestServeNext_CorazaDownstreamIntercept(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		// 模拟 coraza-caddy 请求相位中断：不写响应，直接返回哨兵错误
		return caddyhttp.HandlerError{
			StatusCode: http.StatusForbidden, ID: "tx-coraza-1", Err: errors.New("interruption triggered"),
		}
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-coraza-1")
	err := g.serveNext(httptest.NewRecorder(), req, next)
	if err == nil {
		t.Fatal("downstream interruption error must propagate")
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction != "BLOCK" {
		t.Fatalf("final_action = %q, want BLOCK（下游阻断按实记录）", rec.FinalAction)
	}
	if rec.ResponseStatus != http.StatusForbidden {
		t.Fatalf("response_status = %d, want 403（中断码）", rec.ResponseStatus)
	}
	found := false
	for _, d := range rec.Details {
		if d.Detector == "waf" && d.RuleID == "waf.downstream_intercept" {
			found = true
			if d.Category != "BLOCK" || d.Evidence["attribution"] != "downstream_intercept" ||
				d.Evidence["coraza_tx_id"] != "tx-coraza-1" {
				t.Fatalf("bad waf detail: %+v", d)
			}
		}
	}
	if !found {
		t.Fatalf("waf.downstream_intercept detail missing: %+v", rec.Details)
	}
}

// Coraza drop 动作合流：下游中断但 HandlerError 状态码为 200（coraza-caddy 对非 deny 中断
// 回退默认码）→ 事件按实记 final_action=BLOCK 且 response_status 修正为 403（不得记 200 冒充成功响应）。
func TestServeNext_CorazaDropNormalizedTo403(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		// 模拟 coraza-caddy drop 中断：不写响应，返回 200 状态码的哨兵错误
		return caddyhttp.HandlerError{
			StatusCode: http.StatusOK, ID: "tx-coraza-drop", Err: errors.New("interruption triggered"),
		}
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("downstream interruption error must propagate")
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction != "BLOCK" || rec.ResponseStatus != http.StatusForbidden {
		t.Fatalf("drop must record BLOCK+403, got %q+%d", rec.FinalAction, rec.ResponseStatus)
	}
	found := false
	for _, d := range rec.Details {
		if d.Detector == "waf" && d.RuleID == "waf.downstream_intercept" {
			found = true
			if d.Evidence["status_code"] != "403" || d.Evidence["coraza_raw_status"] != "200" {
				t.Fatalf("bad drop evidence: %+v", d.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("waf.downstream_intercept detail missing: %+v", rec.Details)
	}
}

// guard 自身阻断（统一引擎定案 BLOCK）：handled 提前返回不走归因路径，事件无 waf 明细、不重复归因。
func TestServeNext_GuardOwnBlockNotAttributed(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":"abc"}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("expect guard block")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 || recs[0].FinalAction != "BLOCK" {
		t.Fatalf("want 1 BLOCK event, got %+v", recs)
	}
	for _, d := range recs[0].Details {
		if d.Detector == "waf" || d.RuleID == "waf.downstream_intercept" {
			t.Fatalf("guard's own block must not carry waf attribution: %+v", d)
		}
	}
}

// 下游非 Coraza 错误（反代 502）：不误归因——无 waf 明细，final_action 维持管线结论（ALLOW），
// response_status 按原样捕获值（0 = 未采集到）。
func TestServeNext_DownstreamNonCorazaErrorNotAttributed(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("dial tcp 10.0.0.1: connection refused"))
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err == nil {
		t.Fatal("downstream error must propagate")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction == "BLOCK" {
		t.Fatalf("non-coraza error must not flip final_action to BLOCK: %+v", rec)
	}
	for _, d := range rec.Details {
		if d.Detector == "waf" {
			t.Fatalf("non-coraza error must not produce waf detail: %+v", d)
		}
	}
}

// 正常 200 放行：无误判——无 waf 明细，final_action 非 BLOCK。
func TestServeNext_NormalResponseNoWafFinding(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders", strings.NewReader(`{"id":1}`))
	req.Header.Set("Content-Type", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	rec := recs[0]
	if rec.FinalAction == "BLOCK" || rec.ResponseStatus != http.StatusOK {
		t.Fatalf("normal 200 misjudged: final_action=%q status=%d", rec.FinalAction, rec.ResponseStatus)
	}
	for _, d := range rec.Details {
		if d.Detector == "waf" {
			t.Fatalf("normal 200 must not produce waf detail: %+v", d)
		}
	}
}
