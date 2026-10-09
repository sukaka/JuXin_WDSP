// pipeline_admission_test.go API 准入检测器 pipeline 装配测试（WDSP P1）：
// 仅 API 分类流量判定、检测段最前执行、PROTECT 短路、lifecycle 去重、统一决策定案。
package pipeline

import (
	"net/http"
	"testing"

	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

func admPolicy(mode string, confirmed ...string) *detectors.AdmissionPolicy {
	p := &detectors.AdmissionPolicy{Mode: mode, Confirmed: map[string]struct{}{}}
	for _, ek := range confirmed {
		p.Confirmed[ek] = struct{}{}
	}
	return p
}

// PROTECT 命中未确认端点（基线 DISCOVERED）：定案 BLOCK、短路后续重检测器
// （冻结模型类型偏离不再计算）、lifecycle 不重复产出。
func TestProcessAdmissionProtectShortCircuits(t *testing.T) {
	// asmBearerReq POST 体为 {"a":1}：若未短路，observed number 对冻结 string 模型
	// 必产 schema.type_mismatch（BLOCK 类）——短路断言因此非平凡
	r := asmBearerReq(t, http.MethodPost, "http://h/v1/discovered", "", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeProtect,
		FormalSchema:   map[string]string{"a": "string"},
		KnownEndpoints: map[string]string{"POST /v1/discovered": "DISCOVERED"},
		Admission:      admPolicy(detectors.AdmissionModeProtect, "GET /v1/confirmed"),
	})
	if res.FinalAction != "BLOCK" {
		t.Fatalf("expected BLOCK, got %s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	if !hasRule(res, "admission.unconfirmed_endpoint") {
		t.Fatalf("expected admission.unconfirmed_endpoint, got %+v", res.Context.CopyMatches())
	}
	if hasRule(res, "schema.type_mismatch") {
		t.Fatal("short-circuit must skip schema deviation (heavy detector)")
	}
	if hasRule(res, "lifecycle.new_endpoint") {
		t.Fatal("in-baseline endpoint must not produce lifecycle.new_endpoint")
	}
}

// PROTECT 命中未知端点（基线无）：定案 BLOCK；lifecycle.new_endpoint 被准入覆盖跳过
// （去重策略：同语义 finding 不并存）。
func TestProcessAdmissionProtectUnknownSkipsLifecycle(t *testing.T) {
	r := asmBearerReq(t, http.MethodGet, "http://h/v1/never-seen", "", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeProtect,
		KnownEndpoints: map[string]string{"GET /v1/discovered": "DISCOVERED"},
		Admission:      admPolicy(detectors.AdmissionModeProtect, "GET /v1/confirmed"),
	})
	if res.FinalAction != "BLOCK" || !hasRule(res, "admission.unknown_endpoint") {
		t.Fatalf("expected BLOCK + admission.unknown_endpoint, got %s %+v", res.FinalAction, res.Context.CopyMatches())
	}
	if hasRule(res, "lifecycle.new_endpoint") {
		t.Fatal("admission.unknown_endpoint must cover lifecycle.new_endpoint (dedup)")
	}
}

// OBSERVE 命中：定案 OBSERVE（BLOCK 类资格不升级）、不短路（schema 偏离照常计算）、
// lifecycle 去重生效（admission.unknown_endpoint 覆盖 new_endpoint）。
func TestProcessAdmissionObserveRecordsWithoutShortCircuit(t *testing.T) {
	r := asmBearerReq(t, http.MethodPost, "http://h/v1/never-seen", "", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeObserve,
		FormalSchema:   map[string]string{"a": "string"},
		KnownEndpoints: map[string]string{"GET /v1/discovered": "DISCOVERED"},
		Admission:      admPolicy(detectors.AdmissionModeObserve, "GET /v1/confirmed"),
	})
	if res.FinalAction != "OBSERVE" {
		t.Fatalf("expected OBSERVE, got %s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	if !hasRule(res, "admission.unknown_endpoint") {
		t.Fatalf("expected admission.unknown_endpoint, got %+v", res.Context.CopyMatches())
	}
	if hasRule(res, "lifecycle.new_endpoint") {
		t.Fatal("dedup: lifecycle.new_endpoint must be skipped when admission covered unknown")
	}
	if !hasRule(res, "schema.type_mismatch") {
		t.Fatal("OBSERVE admission must not short-circuit subsequent detectors (learning needs full signals)")
	}
}

// 已确认端点：无 admission finding，正常进入后续管线（行为与未配置准入一致）。
func TestProcessAdmissionConfirmedPasses(t *testing.T) {
	// 强凭据避免 auth.unauthenticated_api 观测噪音（与 asm 既有测试同一纪律）
	r := asmBearerReq(t, http.MethodGet, "http://h/v1/confirmed", "s3cr3t-token-0123456789abcdef", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeProtect,
		KnownEndpoints: map[string]string{"GET /v1/confirmed": "CONFIRMED"},
		Admission:      admPolicy(detectors.AdmissionModeProtect, "GET /v1/confirmed"),
	})
	if res.FinalAction != "ALLOW" {
		t.Fatalf("expected ALLOW, got %s matches=%+v", res.FinalAction, res.Context.CopyMatches())
	}
	if hasRule(res, "admission.unknown_endpoint") || hasRule(res, "admission.unconfirmed_endpoint") {
		t.Fatalf("confirmed endpoint must not produce admission finding, got %+v", res.Context.CopyMatches())
	}
}

// 非 API 分类流量不受准入判定（§4.3 决策点 4：页面/静态资源不默认拒绝）。
func TestProcessAdmissionSkipsNonAPI(t *testing.T) {
	r, _ := http.NewRequest(http.MethodGet, "http://h/docs", nil)
	r.Header.Set("Content-Type", "text/html")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeProtect,
		KnownEndpoints: map[string]string{},
		Admission:      admPolicy(detectors.AdmissionModeProtect, "GET /v1/confirmed"),
	})
	if res.API.IsAPI {
		t.Fatal("fixture must classify as non-API")
	}
	if hasRule(res, "admission.unknown_endpoint") || hasRule(res, "admission.unconfirmed_endpoint") {
		t.Fatalf("non-API traffic must not be admission-judged, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction == "BLOCK" {
		t.Fatal("non-API traffic must not be admission-blocked")
	}
}

// 应用无策略（Admission nil）：准入零行为——lifecycle 既有行为不变（未知端点照产 new_endpoint）。
func TestProcessAdmissionNilPolicyKeepsLifecycle(t *testing.T) {
	r := asmBearerReq(t, http.MethodGet, "http://h/v1/never-seen", "", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeProtect,
		KnownEndpoints: map[string]string{"GET /v1/discovered": "DISCOVERED"},
	})
	if !hasRule(res, "lifecycle.new_endpoint") {
		t.Fatalf("nil admission policy must keep lifecycle behavior, got %+v", res.Context.CopyMatches())
	}
	if res.FinalAction == "BLOCK" {
		t.Fatal("nil admission policy must not block")
	}
}

// 全局管线模式 OBSERVE + 准入 PROTECT：BLOCK 类 finding 由统一决策按全局模式降级为
// OBSERVE（引擎既有降级逻辑；全局模式是 API 管线统一实断阀门，检测器不擅自执行）。
func TestProcessAdmissionProtectDowngradedByGlobalObserve(t *testing.T) {
	r := asmBearerReq(t, http.MethodGet, "http://h/v1/never-seen", "", "")
	res := asmProcess(t, r, Config{
		Enabled:        true,
		Mode:           decision.ModeObserve,
		KnownEndpoints: map[string]string{},
		Admission:      admPolicy(detectors.AdmissionModeProtect),
	})
	if res.FinalAction != "OBSERVE" {
		t.Fatalf("global OBSERVE must downgrade admission BLOCK to OBSERVE, got %s", res.FinalAction)
	}
	if !hasRule(res, "admission.unknown_endpoint") {
		t.Fatalf("admission finding must still be recorded, got %+v", res.Context.CopyMatches())
	}
}
