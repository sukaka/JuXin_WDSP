package applications

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestDefaultMode(t *testing.T) {
	for _, m := range []string{ModeOff, ModeObserve, ModeProtect, ModeBypass} {
		if got := defaultMode(m); got != m {
			t.Errorf("defaultMode(%s) = %s, want %s", m, got, m)
		}
	}
	for _, m := range []string{"", "INVALID", "bypass"} {
		if got := defaultMode(m); got != ModeObserve {
			t.Errorf("defaultMode(%q) = %s, want %s", m, got, ModeObserve)
		}
	}
}

// 创建接口对非法 api_admission_mode 明确 400（冻结契约；校验先于配额与 store，
// nil store 即可驱动——与 quota_test 同一纪律）
func TestCreateRejectsInvalidAdmissionModeHTTP(t *testing.T) {
	h := NewHandler(nil, deadAudits(t), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/applications",
		strings.NewReader(`{"code":"shop-x","name":"测试应用","api_admission_mode":"STRICT"}`))
	req.Header.Set("Content-Type", "application/json")
	p := &authz.Principal{UserID: uuid.New(), Username: "tester"}
	req = req.WithContext(authz.WithPrincipal(req.Context(), p))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 api_admission_mode 应 400，got %d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非 JSON: %v", err)
	}
	if body.Code != "INVALID_ARGUMENT" {
		t.Fatalf("业务码应为 INVALID_ARGUMENT，got %s", body.Code)
	}
}
