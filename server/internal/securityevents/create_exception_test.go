package securityevents

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// TestCreateExceptionRejectsUnknownFields 校验从事件创建例外接口拒绝客户端试图覆盖的受控字段（如 application_id/scope_type）。
func TestCreateExceptionRejectsUnknownFields(t *testing.T) {
	h := NewHandler(nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security-events/"+uuid.New().String()+"/create-exception",
		strings.NewReader(`{"application_id":"11111111-1111-1111-1111-111111111111","scope_type":"GLOBAL"}`))
	req.SetPathValue("id", uuid.New().String())
	req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "secops",
	}))
	rec := httptest.NewRecorder()

	h.CreateException(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 when unknown/spoofed fields supplied; body=%s", rec.Code, rec.Body.String())
	}
}
