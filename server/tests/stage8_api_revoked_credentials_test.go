// stage8_api_revoked_credentials_test.go 已吊销凭据清单管理面 + 发布侧贯通测试
// （阶段8 §35「已吊销凭据使用」数据源，表与权限种子见迁移 000156）。
//
// 覆盖边界（如实声明）：本波 app.go 路由接线由主代理统一收口，故 CRUD 经
// 「真实 DB + 本地 mux 直接注册 handler（含权限中间件）」验证；发布链路与
// app.go 同一接线（SetRevokedCredentialLister(NewRevokedCredentialStore(db))）。
// 网关消费与检测挂接为下一波，本测试只校验 server 侧下发契约键名。
//
// 链路：迁移 000156（表约束/权限种子）→ CRUD（指纹校验/唯一冲突/窗口过滤）
// → guardconfig.Provider.BuildGuardConfig（当前生效行进入 api_revoked_credentials 段）
// → 生成器 Caddy JSON 契约键名 → 版本快照落库/回读 → 删除回落与版本戳确定性。
//
// 运行方式：
//
//	POSTGRES_PASSWORD=... VALKEY_PASSWORD=... go test ./tests -run TestStage8APIRevokedCredentials -count=1
package tests

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/accesscontrolversions"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/apirevokedcreds"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/guardconfig"
	"github.com/jiuzhang-waf/server/internal/protectedaddresses"
	"github.com/jiuzhang-waf/server/internal/ratelimitpolicies"
	"github.com/jiuzhang-waf/server/internal/trustedproxies"
)

// s8RevokedMux 本地注册已吊销凭据路由（app.go 未接线期的替代；权限中间件真实生效，
// principal 由注入器携带指定权限点）。
func s8RevokedMux(h *apirevokedcreds.Handler, perms ...string) *http.ServeMux {
	mux := http.NewServeMux()
	inject := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "s8cred", PermsSet: map[string]bool{}}
			for _, pm := range perms {
				p.PermsSet[pm] = true
			}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
	apirevokedcreds.RegisterRoutes(mux, inject, h)
	return mux
}

func s8RevokedReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// s8RevokedProvider 按 app.go 同一接线构造发布组装器（WDSP 形态 + 吊销清单读取）。
func s8RevokedProvider(env *testEnv) *guardconfig.Provider {
	p := guardconfig.NewProvider(
		trustedproxies.NewStore(env.db), protectedaddresses.NewStore(env.db),
		accessrules.NewStore(env.db), ratelimitpolicies.NewStore(env.db),
		accesscontrolversions.NewStore(env.db),
		guardconfig.Config{
			APIDynamicProtection: true, APIProtectionMode: "PROTECT",
			APIEventsLog: "/var/log/caddy/api-runtime-events.log",
			GatewayNode:  "gw-test",
		})
	p.SetRevokedCredentialLister(guardconfig.NewRevokedCredentialStore(env.db))
	return p
}

func TestStage8APIRevokedCredentials(t *testing.T) {
	env := setupStage8Env(t)
	ctx := context.Background()
	fp1 := "0123456789abcdef0123456789abcdef"
	fp2 := "fedcba9876543210fedcba9876543210"

	// ---------- 0. 迁移约束：指纹 CHECK 与窗口 CHECK 由库强制 ----------
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_revoked_credentials (credential_type, fingerprint, reason)
VALUES ('auth', 'not-hex', 'x')`); err == nil {
		t.Fatal("invalid fingerprint must be rejected by CHECK")
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_revoked_credentials (credential_type, fingerprint, reason, effective_from, effective_until)
VALUES ('auth', $1, 'x', '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z')`, fp1); err == nil {
		t.Fatal("inverted window must be rejected by CHECK")
	}
	// 权限种子：SECURITY_ADMIN 持有两个权限点
	var permCount int
	if err := env.db.QueryRow(ctx, `
SELECT count(*) FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id AND r.code = 'SECURITY_ADMIN'
JOIN permissions p ON p.id = rp.permission_id
WHERE p.code IN ('api_credential.read', 'api_credential.manage')`).Scan(&permCount); err != nil {
		t.Fatalf("query permission seed: %v", err)
	}
	if permCount != 2 {
		t.Fatalf("SECURITY_ADMIN credential permissions = %d, want 2", permCount)
	}

	// ---------- 1. 基线：无吊销记录 → 不下发 api_revoked_credentials 段 ----------
	cfg0, err := s8RevokedProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (baseline): %v", err)
	}
	if len(cfg0.APIRevokedCredentials) != 0 {
		t.Fatalf("baseline revoked credentials = %+v, want empty", cfg0.APIRevokedCredentials)
	}

	// ---------- 2. CRUD（本地 mux，权限中间件真实生效） ----------
	h := apirevokedcreds.NewHandler(apirevokedcreds.NewStore(env.db), nil)
	mux := s8RevokedMux(h, apirevokedcreds.PermCredentialRead, apirevokedcreds.PermCredentialManage)
	noPermMux := s8RevokedMux(h)
	if w := s8RevokedReq(t, noPermMux, "GET", "/api/v1/api-security/revoked-credentials", ""); w.Code != http.StatusForbidden {
		t.Fatalf("no-permission list status = %d, want 403", w.Code)
	}
	if w := s8RevokedReq(t, mux, "POST", "/api/v1/api-security/revoked-credentials",
		`{"credential_type":"auth","fingerprint":"bad","reason":"x"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad fingerprint status = %d, want 400", w.Code)
	}
	w := s8RevokedReq(t, mux, "POST", "/api/v1/api-security/revoked-credentials",
		fmt.Sprintf(`{"credential_type":"auth","fingerprint":%q,"reason":"凭据泄漏"}`, fp1))
	if w.Code != http.StatusCreated {
		t.Fatalf("create status = %d, body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"revoked_by":"s8cred"`) {
		t.Fatalf("revoked_by must come from principal: %s", w.Body.String())
	}
	var created apiResp
	readJSON(t, w.Result(), &created)
	id, _ := created.Data["id"].(string)
	if id == "" {
		t.Fatalf("created id missing: %+v", created.Data)
	}
	// 同类型同指纹重复：409
	if w := s8RevokedReq(t, mux, "POST", "/api/v1/api-security/revoked-credentials",
		fmt.Sprintf(`{"credential_type":"auth","fingerprint":%q,"reason":"重复"}`, fp1)); w.Code != http.StatusConflict {
		t.Fatalf("duplicate status = %d, want 409", w.Code)
	}
	// 同指纹不同来源类型：允许
	if w := s8RevokedReq(t, mux, "POST", "/api/v1/api-security/revoked-credentials",
		fmt.Sprintf(`{"credential_type":"key","fingerprint":%q,"reason":"同值不同来源"}`, fp1)); w.Code != http.StatusCreated {
		t.Fatalf("same fingerprint different type status = %d, want 201", w.Code)
	}
	// 未生效（未来生效）与已到期记录：不入发布载荷
	futureFrom := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	if w := s8RevokedReq(t, mux, "POST", "/api/v1/api-security/revoked-credentials",
		fmt.Sprintf(`{"credential_type":"sess","fingerprint":%q,"reason":"预约吊销","effective_from":%q}`, fp2, futureFrom)); w.Code != http.StatusCreated {
		t.Fatalf("future-dated create status = %d, body: %s", w.Code, w.Body.String())
	}
	if _, err := env.db.Exec(ctx, `
INSERT INTO api_revoked_credentials (credential_type, fingerprint, reason, effective_from, effective_until)
VALUES ('sess', '11111111111111111111111111111111', '已到期', now() - interval '2 days', now() - interval '1 day')`); err != nil {
		t.Fatalf("seed expired row: %v", err)
	}
	// active 过滤
	w = s8RevokedReq(t, mux, "GET", "/api/v1/api-security/revoked-credentials?active=true", "")
	if !strings.Contains(w.Body.String(), `"total":2`) {
		t.Fatalf("active list body = %s（want 2 active rows）", w.Body.String())
	}
	// 详情 + 调整窗口（永久 → 限时）
	w = s8RevokedReq(t, mux, "PUT", "/api/v1/api-security/revoked-credentials/"+id,
		`{"reason":"更新原因","effective_from":"2026-01-01T00:00:00Z","effective_until":"2027-01-01T00:00:00Z"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("update status = %d, body: %s", w.Code, w.Body.String())
	}

	// ---------- 3. 发布通道组装：当前生效行进入 GuardConfig（契约键名，无凭据明文） ----------
	cfg1, err := s8RevokedProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config: %v", err)
	}
	if len(cfg1.APIRevokedCredentials) != 2 {
		t.Fatalf("revoked credentials payload = %+v, want 2 active rows", cfg1.APIRevokedCredentials)
	}
	rc := cfg1.APIRevokedCredentials[0]
	if rc.CredentialType != "auth" || rc.Fingerprint != fp1 {
		t.Fatalf("first payload row = %+v (stable order: auth before key)", rc)
	}
	if cfg1.APIRevokedCredentials[1].CredentialType != "key" || cfg1.APIRevokedCredentials[1].Fingerprint != fp1 {
		t.Fatalf("second payload row = %+v", cfg1.APIRevokedCredentials[1])
	}
	if rc.ExpiresAt == "" {
		t.Fatal("updated row must carry expires_at")
	}
	if cfg1.APIPolicyVersion == cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must change when revoked credentials change")
	}

	// ---------- 4. 生成器：Caddy JSON 的 jiuzhang_guard 处理器含 api_revoked_credentials ----------
	j := s8GenerateGuardJSON(t, cfg1)
	for _, want := range []string{
		`"handler":"jiuzhang_guard"`,
		`"api_revoked_credentials":[{"credential_type":"auth","fingerprint":"` + fp1 + `"`,
		`"credential_type":"key"`, `"expires_at":"2027-01-01T00:00:00Z"`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("caddy json missing %q", want)
		}
	}

	// ---------- 5. 版本快照落库/回读：吊销清单随快照保留（回滚路径不丢配置） ----------
	versionID, err := s8RevokedProvider(env).SaveVersionSnapshot(ctx, cfg1, uuid.New(), uuid.New())
	if err != nil {
		t.Fatalf("save version snapshot: %v", err)
	}
	back, err := s8RevokedProvider(env).GetVersionConfig(ctx, versionID)
	if err != nil {
		t.Fatalf("get version config: %v", err)
	}
	if len(back.APIRevokedCredentials) != 2 || back.APIRevokedCredentials[0].Fingerprint != fp1 {
		t.Fatalf("snapshot round-trip lost revoked credentials: %+v", back.APIRevokedCredentials)
	}

	// ---------- 6. 删除 → 发布内容回落与版本戳确定性回归基线 ----------
	for _, row := range []string{id} {
		if w := s8RevokedReq(t, mux, "DELETE", "/api/v1/api-security/revoked-credentials/"+row, ""); w.Code != http.StatusOK {
			t.Fatalf("delete status = %d", w.Code)
		}
	}
	var keyRowID string
	if err := env.db.QueryRow(ctx,
		`SELECT id FROM api_revoked_credentials WHERE credential_type = 'key' AND fingerprint = $1`, fp1).Scan(&keyRowID); err != nil {
		t.Fatalf("find key row: %v", err)
	}
	if w := s8RevokedReq(t, mux, "DELETE", "/api/v1/api-security/revoked-credentials/"+keyRowID, ""); w.Code != http.StatusOK {
		t.Fatalf("delete key row status = %d", w.Code)
	}
	if _, err := env.db.Exec(ctx, `DELETE FROM api_revoked_credentials`); err != nil {
		t.Fatalf("cleanup rows: %v", err)
	}
	cfg2, err := s8RevokedProvider(env).BuildGuardConfig(ctx)
	if err != nil {
		t.Fatalf("build guard config (deleted): %v", err)
	}
	if len(cfg2.APIRevokedCredentials) != 0 {
		t.Fatalf("deleted rows must leave publish payload: %+v", cfg2.APIRevokedCredentials)
	}
	if cfg2.APIPolicyVersion != cfg0.APIPolicyVersion {
		t.Fatal("api_policy_version must return to baseline after delete（同内容恒同版）")
	}
	if j := s8GenerateGuardJSON(t, cfg2); strings.Contains(j, "api_revoked_credentials") {
		t.Fatal("deleted rows must not appear in caddy json")
	}
}
