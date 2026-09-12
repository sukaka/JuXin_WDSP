// apiunified_test.go §207 统一决策关键场景（任务书 W5-C 分片）：
// 一个请求同时命中「schema 偏离 + 敏感字段 + 行为突增（统一引擎内）+ 下游 Coraza 阻断（WAF）」，
// 断言统一事件契约：1 RequestContext / 4+ Findings / 1 Verdict / 1 主事件，且 Coraza 归因明细存在（G2 合流）。
//
// 覆盖边界（如实声明）：
//   - 本测试为 jiuzhang_guard 模块级全链模拟：统一管线真实执行（parser→检测器→decision），
//     WAF 腿以 coraza-caddy v2.5.0 中断哨兵错误的真实返回形态模拟（见 apicoraza.go 调查结论）；
//   - 行为突增用脚本化滑窗存储确定性触发（真实 1 分钟窗口基线由 detectors/behavior_test.go 覆盖）；
//   - 真网关 + 真 Coraza + 管理面入库的端到端形态见 test/waf/scripts/stage8-unified-decision-tests.sh。
package jiuzhang_guard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// scriptedWindow 脚本化滑窗计数存储：返回固定计数与历史样本，
// 用于确定性触发 behavior.rate_spike（阈值 = max(20, 3×历史均值)，见 detectors/behavior.go）。
type scriptedWindow struct {
	count   int
	history []int
}

func (w scriptedWindow) AddAndCount(string) (int, []int) { return w.count, w.history }

// §207 统一决策：单请求四检测器命中 → 单事件、单裁决、Coraza 归因。
func TestServeNext_UnifiedDecisionMultiDetector(t *testing.T) {
	// FORMAL 模型仅含 id:number；请求体 id 为 string（类型偏离）且携带未定义字段 password（敏感字段名）
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "OBSERVE", schemas)
	g.APIPolicyVersion = "pv-ud-1"
	// 行为突增：5 个历史窗口均值 2 → 阈值 20；当前窗口第 25 次命中突增
	g.behaviorStores = &detectors.StoreOverrides{
		BehaviorWindow: scriptedWindow{count: 25, history: []int{2, 2, 2, 2, 2}},
	}
	// 下游 Coraza 请求相位阻断：coraza-caddy 中断的真实错误形态
	// （caddyhttp.HandlerError{StatusCode: 中断码, ID: 事务 ID, Err: 哨兵 "interruption triggered"}）
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusForbidden,
			ID:         "tx-ud-1",
			Err:        errors.New(corazaInterruptionMessage),
		}
	})
	// 单请求同时携带：SQLi 载荷（由下游 WAF 判定）+ 类型偏离（id string）+ 未定义且敏感的字段（password）
	req := httptest.NewRequest(http.MethodPost, "/v1/orders",
		strings.NewReader(`{"id":"1' OR '1'='1","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-ud-1")
	req.RemoteAddr = "203.0.113.66:6001"

	err := g.serveNext(httptest.NewRecorder(), req, next)
	// Coraza 中断错误原样上抛（由 Caddy 错误处理流程回 403，统一引擎不拦截该错误）
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want downstream 403 HandlerError, got %v", err)
	}

	// 单 RequestContext 贯穿：管线产物随请求传递，且归因补记写在同一上下文上
	rc := RequestContextFrom(req)
	if rc == nil {
		t.Fatal("RequestContext not injected into request context")
	}
	if rc.GetFinalAction() != dsctx.ActionBlock {
		t.Fatalf("context final action = %q, want BLOCK（Coraza 归因按实记录）", rc.GetFinalAction())
	}

	// 恰好 1 条主事件（1 Request / 1 主事件）
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 api event, got %d: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec.RequestID != "req-ud-1" || rec.EndpointKey != "POST /v1/orders" {
		t.Fatalf("bad record identity: %+v", rec)
	}
	// 唯一裁决：final_action 单值且按实记 BLOCK（阻断在下游真实发生）；状态码取中断码 403
	if rec.FinalAction != "BLOCK" {
		t.Fatalf("final_action = %q, want BLOCK（waf 归因）", rec.FinalAction)
	}
	if rec.ResponseStatus != http.StatusForbidden {
		t.Fatalf("response_status = %d, want 403（Coraza 中断码）", rec.ResponseStatus)
	}

	// 4+ Findings：逐检测器核对明细（事件明细与上下文 matches 同一份拷贝）
	if len(rec.Details) != rc.MatchCount() {
		t.Fatalf("event details (%d) must mirror context matches (%d)", len(rec.Details), rc.MatchCount())
	}
	byRule := map[string]dsctx.DetectorMatch{}
	detectorsHit := map[string]bool{}
	for _, d := range rec.Details {
		byRule[d.RuleID] = d
		detectorsHit[d.Detector] = true
	}
	for _, ruleID := range []string{
		"schema.type_mismatch",     // schema 偏离：id 期望 number 实得 string
		"schema.undefined_field",   // schema 偏离：password 不在 FORMAL 模型
		"sensitive.field",          // 敏感字段名：password → credential
		"behavior.rate_spike",      // 行为突增：滑窗计数超阈值
		"waf.downstream_intercept", // WAF：下游 Coraza 阻断归因（G2 合流）
	} {
		if _, ok := byRule[ruleID]; !ok {
			t.Errorf("detail %s missing: %+v", ruleID, rec.Details)
		}
	}
	if len(detectorsHit) < 4 {
		t.Fatalf("detectors hit = %v, want ≥4 families", detectorsHit)
	}
	// Coraza 归因明细：detector=waf、BLOCK 类、证据注明归因方式与事务 ID（不得冒充引擎决策）
	waf := byRule["waf.downstream_intercept"]
	if waf.Detector != "waf" || waf.Category != "BLOCK" {
		t.Fatalf("bad waf attribution attrs: %+v", waf)
	}
	if waf.Evidence["attribution"] != "downstream_intercept" || waf.Evidence["coraza_tx_id"] != "tx-ud-1" {
		t.Fatalf("bad waf attribution evidence: %+v", waf.Evidence)
	}
	// 行为突增证据：计数与阈值可见（基线维度不落明文身份）
	if spike := byRule["behavior.rate_spike"]; spike.Evidence["window_count"] != "25" || spike.Evidence["threshold"] != "20" {
		t.Fatalf("bad spike evidence: %+v", spike.Evidence)
	}
	// 敏感字段证据不落值（password 明文不出现在任何证据中）
	for _, d := range rec.Details {
		for _, v := range d.Evidence {
			if strings.Contains(v, `"x"`) || strings.Contains(v, "OR '1'=") {
				t.Fatalf("evidence must not contain raw values: %+v", d.Evidence)
			}
		}
	}
}

// 旁证：同一多命中请求在 PROTECT 模式下由统一引擎自身定案阻断（不依赖下游 WAF），
// 仍恰好 1 条主事件、final_action 唯一为 BLOCK——裁决唯一性与 WAF 是否介入无关。
func TestServeNext_UnifiedDecisionProtectSingleVerdict(t *testing.T) {
	schemas := map[string]map[string]string{"POST /v1/orders": {"id": "number"}}
	g, logPath := newAPITestGuard(t, "PROTECT", schemas)
	g.behaviorStores = &detectors.StoreOverrides{
		BehaviorWindow: scriptedWindow{count: 25, history: []int{2, 2, 2, 2, 2}},
	}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/orders",
		strings.NewReader(`{"id":"1' OR '1'='1","password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-ud-2")

	err := g.serveNext(httptest.NewRecorder(), req, next)
	var he caddyhttp.HandlerError
	if !errors.As(err, &he) || he.StatusCode != http.StatusForbidden {
		t.Fatalf("want guard 403 HandlerError, got %v", err)
	}
	if called {
		t.Fatal("next handler must not run when unified engine blocks")
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want exactly 1 api event, got %d: %+v", len(recs), recs)
	}
	if recs[0].FinalAction != "BLOCK" || recs[0].ResponseStatus != http.StatusForbidden {
		t.Fatalf("single verdict mismatch: %+v", recs[0])
	}
	// 统一引擎自身定案：无 waf 归因明细（阻断非下游发生）
	for _, d := range recs[0].Details {
		if d.RuleID == "waf.downstream_intercept" {
			t.Fatalf("guard-blocked request must not carry waf attribution: %+v", recs[0].Details)
		}
	}
	// 多检测器明细仍在同一事件（schema/sensitive/behavior）
	detectorsHit := map[string]bool{}
	for _, d := range recs[0].Details {
		detectorsHit[d.Detector] = true
	}
	for _, want := range []string{"api_schema", "sensitive_data", "behavior"} {
		if !detectorsHit[want] {
			t.Errorf("detector %s missing in protect-mode event: %+v", want, recs[0].Details)
		}
	}
}
