package aihandlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestH20ProviderCreateRejectsLoopbackAndMetadataAllowedTargets(t *testing.T) {
	d := &Deps{} // 校验应在触达数据库前返回 400
	badTargets := []string{
		`["127.0.0.0/8"]`,
		`["127.0.0.1/32"]`,
		`["::1/128"]`,
		`["169.254.169.254/32"]`,
		`["169.254.170.2/32"]`,
		`["100.100.100.200/32"]`,
		`["fd00:ec2::254/128"]`,
		`["0.0.0.0/0"]`,
		`["localhost"]`,
	}
	for _, targets := range badTargets {
		body := `{"name":"p1","provider_type":"openai_compatible","base_url":"https://api.example.com","allowed_targets":` + targets + `}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ai/models/providers", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{UserID: uuid.New(), Username: "admin"}))
		rr := httptest.NewRecorder()
		d.ProviderCreate(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("allowed_targets=%s status=%d, want 400 (body=%s)", targets, rr.Code, rr.Body.String())
		}
	}
}
