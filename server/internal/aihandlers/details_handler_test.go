// details_handler_test.go 详情 GET 端点测试：路由注册无模式冲突、权限校验（401/403）、参数校验（400）。
// 404（pgx.ErrNoRows 映射）与 200 路径依赖真实数据库，本包无 DB mock 设施，由集成测试覆盖。
package aihandlers

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
)

// detailMux 构造与 app.go 一致的详情路由注册（先 RegisterRoutes 验证无模式冲突；
// authChain 打桩：注入 Principal 后走真实权限中间件）。
func detailMux(d *Deps, p *authz.Principal) http.Handler {
	inject := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, inject)
	rp := middleware.RequirePermission
	mux.Handle("GET /api/v1/ai/models/{id}", inject(rp("ai.models.read")(http.HandlerFunc(d.ModelGet))))
	mux.Handle("GET /api/v1/ai/agents/{id}", inject(rp("ai.agents.read")(http.HandlerFunc(d.AgentGet))))
	mux.Handle("GET /api/v1/ai/tools/{id}", inject(rp("ai.tools.read")(http.HandlerFunc(d.ToolGet))))
	mux.Handle("GET /api/v1/ai/audits/{id}", inject(rp("ai.audits.read")(http.HandlerFunc(d.AuditGet))))
	mux.Handle("GET /api/v1/ai/evaluations/{id}", inject(requireAnyPerm("ai.evaluations.run", "ai.usage.read", "ai.audits.read")(http.HandlerFunc(d.EvalRunGet))))
	return mux
}

// detailPaths 五条详情路由（{id} 已替换为给定值）。
func detailPaths(id string) []string {
	return []string{
		"/api/v1/ai/models/" + id,
		"/api/v1/ai/agents/" + id,
		"/api/v1/ai/tools/" + id,
		"/api/v1/ai/audits/" + id,
		"/api/v1/ai/evaluations/" + id,
	}
}

// TestDetailRoutesUnauthenticated 未登录（无 Principal）一律 401。
func TestDetailRoutesUnauthenticated(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, nil)
	for _, path := range detailPaths(uuid.NewString()) {
		if rec := doRequest(t, h, "GET", path, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s status=%d want 401", path, rec.Code)
		}
	}
}

// TestDetailRoutesForbidden 已登录但无对应读权限一律 403（不触达 handler 与数据库）。
func TestDetailRoutesForbidden(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, noisePrincipal("ai.chat.use"))
	for _, path := range detailPaths(uuid.NewString()) {
		if rec := doRequest(t, h, "GET", path, ""); rec.Code != http.StatusForbidden {
			t.Fatalf("GET %s status=%d want 403", path, rec.Code)
		}
	}
}

// TestDetailRoutesEvaluationAnyPerm 评估详情：evaluations.run/usage.read/audits.read 任一放行。
func TestDetailRoutesEvaluationAnyPerm(t *testing.T) {
	d := NewDeps(Deps{})
	for _, perm := range []string{"ai.evaluations.run", "ai.usage.read", "ai.audits.read"} {
		h := detailMux(d, noisePrincipal(perm))
		// 非法 ID 场景：放行后由 handler 返回 400（证明权限中间件已放行）
		if rec := doRequest(t, h, "GET", "/api/v1/ai/evaluations/not-a-uuid", ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("perm %s: status=%d want 400", perm, rec.Code)
		}
	}
}

// TestDetailRoutesInvalidID 非法 ID 在触达数据库前返回 400（Deps 无需装配）。
func TestDetailRoutesInvalidID(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, noisePrincipal(
		"ai.models.read", "ai.agents.read", "ai.tools.read", "ai.audits.read", "ai.evaluations.run"))
	for _, path := range detailPaths("not-a-uuid") {
		rec := doRequest(t, h, "GET", path, "")
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("GET %s status=%d want 400, body=%s", path, rec.Code, rec.Body.String())
		}
		if got := rec.Body.String(); !strings.Contains(got, "INVALID_ARGUMENT") {
			t.Fatalf("GET %s body=%s want code INVALID_ARGUMENT", path, got)
		}
	}
}

// TestDetailRoutesWildcardBoundary {id} 通配边界：GET /ai/audits/verify 无字面量注册，
// 落入 {id} 通配且 "verify" 非 UUID → 400（证明 verify 字面量 POST 路由不受影响）。
func TestDetailRoutesWildcardBoundary(t *testing.T) {
	d := NewDeps(Deps{})
	h := detailMux(d, noisePrincipal("ai.audits.read"))
	if rec := doRequest(t, h, "GET", "/api/v1/ai/audits/verify", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("GET /api/v1/ai/audits/verify status=%d want 400 (wildcard {id} rejected non-uuid)", rec.Code)
	}
}
