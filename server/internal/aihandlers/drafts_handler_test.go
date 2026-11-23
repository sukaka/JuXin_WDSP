// drafts_handler_test.go AI 草稿列表端点测试：NOISE_REDUCTION 白名单、非法类型/状态 400、无权限 403。
package aihandlers

import (
	"net/http"
	"testing"
)

func TestDraftTypesIncludesNoiseReduction(t *testing.T) {
	for _, want := range []string{
		"EXCEPTION", "BLACKLIST", "CC_POLICY", "CUSTOM_RULE",
		"POLICY_CHANGE", "REPORT_SUMMARY", "NOISE_REDUCTION",
	} {
		if !draftTypes[want] {
			t.Errorf("draftTypes missing %q", want)
		}
	}
}

func TestDraftListValidationAndPermissions(t *testing.T) {
	d := NewDeps(Deps{})
	// 无任何 ai.draft.* 权限 → 403
	hForbidden := noiseMux(d, noisePrincipal("ai.chat.use"))
	for _, path := range []string{"/api/v1/ai/drafts", "/api/v1/ai/recommendations"} {
		rec := doRequest(t, hForbidden, http.MethodGet, path, "")
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s forbidden status=%d want 403", path, rec.Code)
		}
	}

	// 持 draft 权限：非法 recommendation_type / status 先行返回 400（不触达 DB）
	hAllowed := noiseMux(d, noisePrincipal("ai.draft.exception"))
	for _, path := range []string{
		"/api/v1/ai/drafts?recommendation_type=BOGUS_TYPE",
		"/api/v1/ai/recommendations?recommendation_type=BOGUS_TYPE",
		"/api/v1/ai/drafts?status=BOGUS_STATUS",
	} {
		rec := doRequest(t, hAllowed, http.MethodGet, path, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s invalid filter status=%d want 400 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}
