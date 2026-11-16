// feedback_handler_test.go 反馈质量聚合端点测试：路由注册无冲突、权限校验（401/403）、
// days 参数口径（默认 7、上限夹取 90）。200 聚合路径依赖真实数据库，由集成测试覆盖
// （server/tests，本包无 DB mock 设施，与 details_handler_test.go 同口径）。
package aihandlers

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const feedbackSummaryPath = "/api/v1/ai/feedback/summary"

// TestFeedbackSummaryUnauthenticated 未登录（无 Principal）一律 401。
func TestFeedbackSummaryUnauthenticated(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, nil)
	if rec := doRequest(t, h, "GET", feedbackSummaryPath, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET %s status=%d want 401", feedbackSummaryPath, rec.Code)
	}
}

// TestFeedbackSummaryForbidden 已登录但无 ai.usage.read 一律 403（不触达 handler 与数据库）。
func TestFeedbackSummaryForbidden(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, noisePrincipal("ai.chat.use", "ai.evaluations.run"))
	if rec := doRequest(t, h, "GET", feedbackSummaryPath, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("GET %s status=%d want 403", feedbackSummaryPath, rec.Code)
	}
}

// TestFeedbackSummaryDaysClamp days 参数：缺省 7、非法回退 7、上限夹取 90。
func TestFeedbackSummaryDaysClamp(t *testing.T) {
	cases := []struct {
		raw  string
		want int
	}{
		{"", 7},
		{"?days=3", 3},
		{"?days=abc", 7},
		{"?days=-5", 7},
		{"?days=0", 7},
		{"?days=90", 90},
		{"?days=365", 90},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", feedbackSummaryPath+c.raw, nil)
		if got := feedbackSummaryDays(r); got != c.want {
			t.Errorf("days %q = %d, want %d", c.raw, got, c.want)
		}
	}
}
