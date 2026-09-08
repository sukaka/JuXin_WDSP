// disposition.go 单测（WDSP P0-04 工作流 C；契约 §2/§10 锁定行为）。
package jiuzhang_guard

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// decodeDisposition Finalize 后解析 JSON 为通用 map（断言序列化形态与契约一致）。
func decodeDisposition(t *testing.T, d *Disposition) map[string]any {
	t.Helper()
	raw := d.JSON()
	if raw == nil {
		t.Fatal("JSON() 返回 nil")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("final_decision JSON 解析失败: %v", err)
	}
	return m
}

func TestDispositionLifecycle_Terminal(t *testing.T) {
	ctx, d := WithDisposition(context.Background(), "node-1")
	if DispositionFrom(ctx) != d {
		t.Fatal("DispositionFrom 未取回同一实例")
	}
	d.SetRequest("req-1", "app-1")
	d.RecordTerminal(ExecutorCC, DisActionRateLimit, 429, true, []string{"CC_THRESHOLD"}, []string{"cc-rule-1"})
	d.RecordTerminal(ExecutorWAF, DisActionBlock, 403, true, nil, nil) // 先到先得：应忽略

	m := decodeDisposition(t, d)
	if m["completion_status"] != CompletionAborted {
		t.Errorf("completion_status=%v, 期望 ABORTED", m["completion_status"])
	}
	if m["security_action"] != DisActionRateLimit {
		t.Errorf("security_action=%v, 期望 RATE_LIMIT", m["security_action"])
	}
	if m["executor_module"] != ExecutorCC {
		t.Errorf("executor_module=%v, 期望 CC", m["executor_module"])
	}
	if m["response_source"] != ResponseSourceGateway {
		t.Errorf("response_source=%v, 期望 GATEWAY", m["response_source"])
	}
	if m["http_status"].(float64) != 429 || m["response_committed"] != true {
		t.Errorf("http_status/committed=%v/%v", m["http_status"], m["response_committed"])
	}
	if m["request_id"] != "req-1" || m["application_id"] != "app-1" || m["gateway_node"] != "node-1" {
		t.Errorf("标识字段不符: %v %v %v", m["request_id"], m["application_id"], m["gateway_node"])
	}
	if m["schema_version"].(float64) != 1 {
		t.Errorf("schema_version=%v", m["schema_version"])
	}
	// 终止后模块补 SKIPPED：CC 之后的 BOT/API/WAF 未记录 → SKIPPED
	steps := m["steps"].([]any)
	var apiSkipped, wafSkipped, botSkipped, ccExecuted bool
	for _, s := range steps {
		sm := s.(map[string]any)
		switch sm["module"] {
		case ExecutorAPI:
			if sm["result"] == StepSkipped {
				apiSkipped = true
			}
		case ExecutorWAF:
			if sm["result"] == StepSkipped {
				wafSkipped = true
			}
		case ExecutorBot:
			if sm["result"] == StepSkipped {
				botSkipped = true
			}
		case ExecutorCC:
			if sm["result"] == StepExecuted {
				ccExecuted = true
			}
		}
	}
	if !ccExecuted || !botSkipped || !apiSkipped || !wafSkipped {
		t.Errorf("steps 不符: ccExecuted=%v botSkipped=%v apiSkipped=%v wafSkipped=%v steps=%v", ccExecuted, botSkipped, apiSkipped, wafSkipped, steps)
	}
	// findings：实断 1、skipped 含补记的 BOT+API+WAF
	findings := m["findings"].(map[string]any)
	if findings["enforced"].(float64) != 1 {
		t.Errorf("findings.enforced=%v", findings["enforced"])
	}
	if findings["skipped"].(float64) != 3 {
		t.Errorf("findings.skipped=%v, 期望 3（BOT+API+WAF）", findings["skipped"])
	}
	if m["finalized_at"] == nil {
		t.Error("finalized_at 缺失")
	}
}

func TestDispositionLifecycle_OriginCompleted(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.SetRequest("req-2", "")
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	if m["completion_status"] != CompletionCompleted || m["response_source"] != ResponseSourceOrigin {
		t.Errorf("completion/source=%v/%v", m["completion_status"], m["response_source"])
	}
	if m["security_action"] != DisActionNone || m["executor_module"] != ExecutorNone {
		t.Errorf("action/executor=%v/%v", m["security_action"], m["executor_module"])
	}
	if m["http_status"].(float64) != 200 {
		t.Errorf("http_status=%v", m["http_status"])
	}
}

func TestDispositionLifecycle_MaskResponse(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.RecordMaskResponse()
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	if m["security_action"] != DisActionMaskResponse {
		t.Errorf("security_action=%v, 期望 MASK_RESPONSE", m["security_action"])
	}
	if m["response_source"] != ResponseSourceOrigin {
		t.Errorf("response_source=%v, 期望 ORIGIN（脱敏注明 ORIGIN 来源）", m["response_source"])
	}
	if m["findings"].(map[string]any)["enforced"].(float64) != 1 {
		t.Errorf("enforced=%v, 期望 1（脱敏实改写）", m["findings"])
	}
}

func TestDispositionLifecycle_PendingCorrelation(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.RecordTerminal(ExecutorWAF, DisActionBlock, 403, false, []string{"WAF_INTERCEPT"}, nil)
	d.NotePendingCorrelation()
	m := decodeDisposition(t, d)
	if m["completion_status"] != CompletionPendingCorrelation {
		t.Errorf("completion_status=%v, 期望 PENDING_CORRELATION", m["completion_status"])
	}
	if m["security_action"] != DisActionBlock || m["executor_module"] != ExecutorWAF {
		t.Errorf("action/executor=%v/%v", m["security_action"], m["executor_module"])
	}
}

func TestDispositionLifecycle_Error(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.RecordError(ExecutorAPI, "upstream dial failed")
	m := decodeDisposition(t, d)
	if m["completion_status"] != CompletionError || m["response_source"] != ResponseSourceUnknown {
		t.Errorf("completion/source=%v/%v", m["completion_status"], m["response_source"])
	}
	if m["security_action"] != DisActionNone {
		t.Errorf("security_action=%v, 期望 NONE（错误不硬映射 BLOCK）", m["security_action"])
	}
}

func TestDispositionLifecycle_Unknown(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	m := decodeDisposition(t, d) // 无任何记录（客户端取消/panic 路径）
	if m["completion_status"] != CompletionUnknown || m["executor_module"] != ExecutorUnknown {
		t.Errorf("completion/executor=%v/%v", m["completion_status"], m["executor_module"])
	}
	if m["security_action"] != DisActionNone || m["response_source"] != ResponseSourceUnknown {
		t.Errorf("action/source=%v/%v", m["security_action"], m["response_source"])
	}
}

func TestDispositionFinalizeIdempotent(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.RecordOrigin(200, true)
	d.Finalize()
	first := string(d.JSON())
	d.Finalize()
	d.RecordTerminal(ExecutorCC, DisActionBlock, 429, true, nil, nil) // finalized 后记录应忽略
	d.RecordStep(ExecutorAPI, StepExecuted, "late")
	second := string(d.JSON())
	if first != second {
		t.Errorf("Finalize 非幂等:\n%s\n%s", first, second)
	}
}

func TestDispositionNilReceiverSafe(t *testing.T) {
	var d *Disposition
	d.SetRequest("r", "a")
	d.RecordTerminal(ExecutorCC, DisActionBlock, 429, true, nil, nil)
	d.RecordStep(ExecutorAPI, StepExecuted, "")
	d.RecordMatchedException("id", 1, "API", nil, "", nil, nil)
	d.RecordOrigin(200, true)
	d.RecordMaskResponse()
	d.RecordError(ExecutorAPI, "x")
	d.NotePendingCorrelation()
	d.SetIdentityVerification("VERIFIED", "p")
	d.SetAPIPolicyVersion("v1")
	d.NoteExceptionVersion("id", 1)
	d.AddEvidenceRef("tx-1")
	d.Finalize()
	if d.JSON() != nil {
		t.Error("nil 接收者 JSON() 应返回 nil")
	}
	if DispositionFrom(context.Background()) != nil {
		t.Error("空 ctx 应返回 nil")
	}
}

func TestDispositionMatchedExceptionsMerge(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	from := time.Unix(1000, 0)
	until := time.Unix(2000, 999) // 秒精度归一
	d.RecordMatchedException("exc-1", 2, "API", []string{"api_schema:REQ-1"}, "app=demo path=/x", &from, &until)
	d.RecordMatchedException("exc-1", 2, "API", []string{"api_schema:REQ-2"}, "ignored", nil, nil) // 同例外同目标合并 ruleRefs
	d.RecordMatchedException("exc-2", 1, "WAF", []string{"942100"}, "", nil, nil)
	d.RecordOrigin(200, true)

	m := decodeDisposition(t, d)
	excs := m["matched_exceptions"].([]any)
	if len(excs) != 2 {
		t.Fatalf("matched_exceptions=%d, 期望 2", len(excs))
	}
	e1 := excs[0].(map[string]any)
	refs := e1["rule_refs"].([]any)
	if len(refs) != 2 || refs[0] != "api_schema:REQ-1" || refs[1] != "api_schema:REQ-2" {
		t.Errorf("合并 rule_refs 不符: %v", refs)
	}
	if e1["effective_from"] != time.Unix(1000, 0).UTC().Format(time.RFC3339) {
		t.Errorf("effective_from=%v", e1["effective_from"])
	}
	if e1["effective_until"] != time.Unix(2000, 0).UTC().Format(time.RFC3339) {
		t.Errorf("effective_until=%v（应秒精度归一）", e1["effective_until"])
	}
	// exception_versions 合并命中例外
	vers := m["effective_config"].(map[string]any)["exception_versions"].(map[string]any)
	if vers["exc-1"].(float64) != 2 || vers["exc-2"].(float64) != 1 {
		t.Errorf("exception_versions=%v", vers)
	}
	if m["findings"].(map[string]any)["excepted"].(float64) != 2 {
		t.Errorf("excepted=%v", m["findings"])
	}
}

func TestDispositionNoteApplicableExceptionVersions(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.NoteExceptionVersion("exc-applicable", 3) // 适用未命中也进 effective_config
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	vers := m["effective_config"].(map[string]any)["exception_versions"].(map[string]any)
	if vers["exc-applicable"].(float64) != 3 {
		t.Errorf("exception_versions=%v", vers)
	}
	if _, ok := m["matched_exceptions"]; ok {
		t.Error("未命中不应出现 matched_exceptions")
	}
}

func TestDispositionStepsTruncation(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	for i := 0; i < maxDispositionSteps+10; i++ {
		d.RecordStep(ExecutorAPI, StepExecuted, "step")
	}
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	steps := m["steps"].([]any)
	if len(steps) != maxDispositionSteps {
		t.Fatalf("steps=%d, 期望 %d", len(steps), maxDispositionSteps)
	}
	last := steps[len(steps)-1].(map[string]any)
	if last["module"] != "TRUNCATED" || last["result"] != StepSkipped {
		t.Errorf("末位应为 TRUNCATED/SKIPPED: %v", last)
	}
	if last["detail"] != "dropped=11" { // 10 条丢弃 + 末位被替换的 1 条
		t.Errorf("detail=%v", last["detail"])
	}
}

func TestDispositionRuleRefsTruncation(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	refs := make([]string, 0, maxDispositionRuleRefs+5)
	for i := 0; i < maxDispositionRuleRefs+5; i++ {
		refs = append(refs, "rule")
	}
	d.RecordTerminal(ExecutorWAF, DisActionBlock, 403, true, nil, refs)
	m := decodeDisposition(t, d)
	if got := len(m["rule_refs"].([]any)); got != maxDispositionRuleRefs {
		t.Errorf("rule_refs=%d, 期望 %d（截断）", got, maxDispositionRuleRefs)
	}
	rr := m["rule_refs"].([]any)[0].(map[string]any)
	if rr["module"] != ExecutorWAF || rr["rule_id"] != "rule" {
		t.Errorf("rule_ref 形态不符: %v", rr)
	}
	var truncFound bool
	for _, s := range m["steps"].([]any) {
		sm := s.(map[string]any)
		if sm["module"] == "TRUNCATED" && strings.Contains(sm["detail"].(string), "rule_refs dropped=5") {
			truncFound = true
		}
	}
	if !truncFound {
		t.Error("缺少 rule_refs 截断 TRUNCATED 步骤")
	}
}

func TestDispositionEnumNormalization(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.RecordTerminal("BOGUS_MODULE", "BOGUS_ACTION", 403, false, nil, nil)
	d.RecordStep(ExecutorAPI, "BOGUS_RESULT", "")
	m := decodeDisposition(t, d)
	if m["executor_module"] != ExecutorUnknown {
		t.Errorf("非法 executor 应归一 UNKNOWN: %v", m["executor_module"])
	}
	if m["security_action"] != DisActionBlock {
		t.Errorf("非法终止 action 应归一 BLOCK: %v", m["security_action"])
	}
	// 未知 executor 不在模块词表：不补 SKIPPED（无法定位执行序）
	for _, s := range m["steps"].([]any) {
		sm := s.(map[string]any)
		if sm["module"] == ExecutorAPI && sm["result"] != StepExecuted {
			t.Errorf("非法 step result 应归一 EXECUTED: %v", sm)
		}
	}
}

func TestDispositionIdentityAndPolicyVersion(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	d.SetIdentityVerification("VERIFIED", "fp:abc")
	d.SetAPIPolicyVersion("2026.09.07-1")
	d.SetAPIPolicyVersion("later-ignored") // 先到先得
	d.AddEvidenceRef("tx-123")
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	iv := m["identity_verification"].(map[string]any)
	if iv["status"] != "VERIFIED" || iv["verified_principal_id"] != "fp:abc" {
		t.Errorf("identity_verification=%v", iv)
	}
	ec := m["effective_config"].(map[string]any)
	if ec["api_policy_version"] != "2026.09.07-1" {
		t.Errorf("api_policy_version=%v", ec["api_policy_version"])
	}
	refs := m["evidence_refs"].([]any)
	if len(refs) != 1 || refs[0] != "tx-123" {
		t.Errorf("evidence_refs=%v", refs)
	}
}

func TestDispositionTerminalSkipsRecordedModules(t *testing.T) {
	_, d := WithDisposition(context.Background(), "node-1")
	// 白名单 allow 场景：显式记录绕过步骤后白名单"之后"被绕过模块已 recorded，
	// 但若更晚发生终止（不应发生——白名单已放行；此处锁定 recorded 去重语义）。
	d.RecordStep(StepModuleIPAllowlist, StepExecuted, "allow hit")
	d.RecordStep(ExecutorIPBlacklist, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordStep(ExecutorL7ACL, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordStep(ExecutorAutoBan, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordStep(ExecutorRiskPolicy, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordStep(ExecutorLicenseQuota, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordStep(ExecutorCC, StepSkipped, "bypassed by IP_ALLOWLIST")
	d.RecordOrigin(200, true)
	m := decodeDisposition(t, d)
	// 无终止：不补 SKIPPED；skipped 计数 = 显式记录的 6 条
	if m["findings"].(map[string]any)["skipped"].(float64) != 6 {
		t.Errorf("skipped=%v", m["findings"])
	}
	if m["completion_status"] != CompletionCompleted {
		t.Errorf("completion=%v", m["completion_status"])
	}
}
