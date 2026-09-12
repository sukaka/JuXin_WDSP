package detectors

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

func verifiedRoles(roles ...string) *jwtverify.VerificationResult {
	return &jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedRoles: roles}
}

// makeUnsignedJWT 拼装未验签 JWT（header.payload.sig；仅测试用，payload 为任意 claims）。
func makeUnsignedJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	return hdr + "." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"
}

func bearerReq(t *testing.T, claims map[string]any) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodPost, "http://h/v1/orders", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "Bearer "+makeUnsignedJWT(t, claims))
	return r
}

// TestExtractRequestRoles 角色提取：字符串 claim / 数组 claim / 两键合并去重 / 无 claim / 匿名与非法形态。
func TestExtractRequestRoles(t *testing.T) {
	// 字符串 role
	if got := ExtractRequestRoles(bearerReq(t, map[string]any{"role": "ops"})); len(got) != 1 || got[0] != "ops" {
		t.Fatalf("string role = %v", got)
	}
	// 数组 roles
	got := ExtractRequestRoles(bearerReq(t, map[string]any{"roles": []any{"ops", "admin"}}))
	if len(got) != 2 || got[0] != "ops" || got[1] != "admin" {
		t.Fatalf("array roles = %v", got)
	}
	// role + roles 合并去重；空串与非字符串元素忽略
	got = ExtractRequestRoles(bearerReq(t, map[string]any{"role": "ops", "roles": []any{"ops", "viewer", "", 7}}))
	if len(got) != 2 || got[0] != "ops" || got[1] != "viewer" {
		t.Fatalf("merged roles = %v", got)
	}
	// 无角色 claim → nil（有凭据但无角色声明，由 BFLA mismatch 分支处理）
	if got := ExtractRequestRoles(bearerReq(t, map[string]any{"sub": "u1"})); got != nil {
		t.Fatalf("no role claim must yield nil: %v", got)
	}
	// 匿名（无凭据）→ nil
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/orders", nil)
	if got := ExtractRequestRoles(r); got != nil {
		t.Fatalf("anonymous must yield nil: %v", got)
	}
	// 非 Bearer scheme → nil
	r, _ = http.NewRequest(http.MethodGet, "http://h/v1/orders", nil)
	r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	if got := ExtractRequestRoles(r); got != nil {
		t.Fatalf("basic auth must yield nil: %v", got)
	}
	// 非 JWT 形态（opaque bearer）→ nil
	r, _ = http.NewRequest(http.MethodGet, "http://h/v1/orders", nil)
	r.Header.Set("Authorization", "Bearer opaque-token-no-segments")
	if got := ExtractRequestRoles(r); got != nil {
		t.Fatalf("opaque token must yield nil: %v", got)
	}
	// 坏 base64 payload → nil
	r, _ = http.NewRequest(http.MethodGet, "http://h/v1/orders", nil)
	r.Header.Set("Authorization", "Bearer aaa.!!!.ccc")
	if got := ExtractRequestRoles(r); got != nil {
		t.Fatalf("bad payload must yield nil: %v", got)
	}
}

// TestCheckRoleBaselineNoBaselineZeroBehavior 无端点基线：零行为（基线缺失不判）。
func TestCheckRoleBaselineNoBaselineZeroBehavior(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	CheckRoleBaseline(ctx, r, "GET /v1/x", "GET", nil)
	CheckRoleBaseline(ctx, r, "GET /v1/x", "GET", []RoleBaseline{})
	if ctx.MatchCount() != 0 {
		t.Fatalf("no baseline must be zero behavior, got %+v", ctx.CopyMatches())
	}
}

// TestCheckRoleBaselineAnonymous 匿名访问有基线端点 → authz.bfla_anonymous（OBSERVE/HIGH）。
func TestCheckRoleBaselineAnonymous(t *testing.T) {
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	r, _ := http.NewRequest(http.MethodDelete, "http://h/v1/orders", nil)
	baselines := []RoleBaseline{{EndpointKey: "DELETE /v1/orders", Role: "ops", Method: "DELETE", Action: "DELETE", Allowed: true}}
	CheckRoleBaseline(ctx, r, "DELETE /v1/orders", "DELETE", baselines)
	m := findMatch(ctx, "authz.bfla_anonymous")
	if m == nil {
		t.Fatalf("expected authz.bfla_anonymous, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "HIGH" {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["endpoint_key"] != "DELETE /v1/orders" || m.Evidence["reason"] != "no_credential" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 匿名判定口径含 X-API-Key/Cookie：带任意凭据即非匿名（转入 mismatch 分支）
	ctx2 := dsctx.New("t2", dsctx.DefaultParseLimits())
	r2, _ := http.NewRequest(http.MethodDelete, "http://h/v1/orders", nil)
	r2.Header.Set("X-API-Key", "abcdefgh")
	CheckRoleBaseline(ctx2, r2, "DELETE /v1/orders", "DELETE", baselines)
	if findMatch(ctx2, "authz.bfla_anonymous") != nil {
		t.Fatal("credential-bearing request must not be anonymous")
	}
	if findMatch(ctx2, "authz.bfla_role_mismatch") == nil {
		t.Fatal("credential without role claim must mismatch")
	}
}

// TestCheckRoleBaselineMismatchAndAllowed 有基线：角色无匹配 allowed 基线 → mismatch；命中 allowed 基线 → 无明细。
func TestCheckRoleBaselineMismatchAndAllowed(t *testing.T) {
	baselines := []RoleBaseline{
		{EndpointKey: "POST /v1/orders", Role: "ops", Method: "POST", Action: "WRITE", Allowed: true},
		{EndpointKey: "POST /v1/orders", Role: "guest", Method: "POST", Action: "WRITE", Allowed: false}, // 显式拒绝
	}
	// viewer 无 allowed 基线 → mismatch（OBSERVE/MEDIUM；证据含角色名不落值）
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckRoleBaseline(ctx, bearerReq(t, map[string]any{"role": "viewer"}), "POST /v1/orders", "POST", baselines)
	m := findMatch(ctx, "authz.bfla_role_mismatch")
	if m == nil {
		t.Fatalf("expected mismatch, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("bad attrs: %+v", m)
	}
	if m.Evidence["roles"] != "viewer" || m.Evidence["method"] != "POST" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// guest 仅有 allowed=false 基线 → mismatch
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	CheckRoleBaseline(ctx, bearerReq(t, map[string]any{"role": "guest"}), "POST /v1/orders", "POST", baselines)
	if findMatch(ctx, "authz.bfla_role_mismatch") == nil {
		t.Fatal("denied-only role must mismatch")
	}
	// ops 命中 allowed 基线 → 无明细
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	CheckRoleBaseline(ctx, bearerReq(t, map[string]any{"role": "ops"}), "POST /v1/orders", "POST", baselines)
	if ctx.MatchCount() != 0 {
		t.Fatalf("allowed role must not match, got %+v", ctx.CopyMatches())
	}
	// 方法不匹配（基线是 POST，请求 GET）→ mismatch
	ctx = dsctx.New("t4", dsctx.DefaultParseLimits())
	CheckRoleBaseline(ctx, bearerReq(t, map[string]any{"role": "ops"}), "POST /v1/orders", "GET", baselines)
	if findMatch(ctx, "authz.bfla_role_mismatch") == nil {
		t.Fatal("method mismatch must mismatch")
	}
}

// TestCheckFieldPermissionsForbidden FORBIDDEN：默认行/角色行正反；BLOCK 类（PROTECT 升级的判定依据）。
func TestCheckFieldPermissionsForbidden(t *testing.T) {
	parsed := &parser.Parsed{JSONFields: map[string]string{"role": "string", "note": "string"}}
	// 默认行 FORBIDDEN：任意角色命中 → BLOCK/HIGH
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	perms := []FieldPermission{{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/orders", perms, parsed)
	m := findMatch(ctx, "authz.forbidden_field")
	if m == nil {
		t.Fatalf("expected forbidden_field, got %+v", ctx.CopyMatches())
	}
	if m.Category != "BLOCK" || m.Severity != "HIGH" {
		t.Fatalf("forbidden must be BLOCK/HIGH (PROTECT escalates via decision): %+v", m)
	}
	// 角色覆盖行：行内角色命中才判
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN", Role: "guest"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/orders", perms, parsed)
	if ctx.MatchCount() != 0 {
		t.Fatalf("role-scoped FORBIDDEN must not fire for other roles, got %+v", ctx.CopyMatches())
	}
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, verifiedRoles("guest"), "POST /v1/orders", perms, parsed)
	if findMatch(ctx, "authz.forbidden_field") == nil {
		t.Fatal("role-scoped FORBIDDEN must fire for the scoped role")
	}
	// 未授权字段（note 无权限行）不报：上例仅 json.role 一条
	if n := ctx.MatchCount(); n != 1 {
		t.Fatalf("exactly one field match expected, got %d", n)
	}
}

func TestCheckFieldPermissionsUsesOnlyVerifiedRoles(t *testing.T) {
	parsed := &parser.Parsed{JSONFields: map[string]string{"role": "string"}}
	perms := []FieldPermission{{EndpointKey: "POST /v1/orders", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN", Role: "ops"}}

	ctx := dsctx.New("unverified", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, &jwtverify.VerificationResult{
		Status: jwtverify.StatusInvalid, VerifiedRoles: []string{"ops"},
	}, "POST /v1/orders", perms, parsed)
	if ctx.MatchCount() != 0 {
		t.Fatalf("unverified roles must not cause BLOCK: %+v", ctx.CopyMatches())
	}

	ctx = dsctx.New("verified", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/orders", perms, parsed)
	if findMatch(ctx, "authz.forbidden_field") == nil {
		t.Fatalf("verified role must enforce FORBIDDEN: %+v", ctx.CopyMatches())
	}
}

func TestCheckFieldPermissionsEvaluatesForbiddenBeyondFindingCapacity(t *testing.T) {
	blockRuleCount := 3
	fields := make(map[string]string, maxAuthzFieldMatches+blockRuleCount)
	perms := make([]FieldPermission, 0, maxAuthzFieldMatches+blockRuleCount)
	for i := 0; i < maxAuthzFieldMatches; i++ {
		path := fmt.Sprintf("field%02d", i)
		fields[path] = "string"
		perms = append(perms, FieldPermission{
			EndpointKey: "POST /v1/orders", FieldPath: "json." + path,
			Direction: "REQUEST", Attribute: "READ_ONLY",
		})
	}
	for i := 0; i < blockRuleCount; i++ {
		path := fmt.Sprintf("z-block-%02d", i)
		fields[path] = "string"
		perms = append(perms, FieldPermission{
			EndpointKey: "POST /v1/orders", FieldPath: "json." + path,
			Direction: "REQUEST", Attribute: "FORBIDDEN",
		})
	}

	ctx := dsctx.New("field-cap", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/orders", perms, &parser.Parsed{JSONFields: fields})
	if ctx.MatchCount() != maxAuthzFieldMatches {
		t.Fatalf("field details must stay within hard capacity: got %d, want %d; matches=%+v", ctx.MatchCount(), maxAuthzFieldMatches, ctx.CopyMatches())
	}
	if got := len(matchesByRule(ctx, "authz.forbidden_field")); got != blockRuleCount {
		t.Fatalf("all FORBIDDEN findings beyond detail capacity must be retained: got %d, want %d; matches=%+v", got, blockRuleCount, ctx.CopyMatches())
	}
	if action := decision.Decide(ctx, decision.Input{Mode: decision.ModeProtect}); action != dsctx.ActionBlock {
		t.Fatalf("retained FORBIDDEN findings must still produce final block: %s", action)
	}
}

// TestCheckFieldPermissionsAttributes READ_ONLY / SERVER_GENERATED / ADMIN_WRITABLE / WRITABLE 正反。
func TestCheckFieldPermissionsAttributes(t *testing.T) {
	newParsed := func() *parser.Parsed {
		return &parser.Parsed{JSONFields: map[string]string{"note": "string", "id": "string", "level": "string"}}
	}
	// READ_ONLY 写入 → readonly_write（OBSERVE/MEDIUM）
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	perms := []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.note", Direction: "REQUEST", Attribute: "READ_ONLY"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, newParsed())
	m := findMatch(ctx, "authz.readonly_write")
	if m == nil || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("readonly_write = %+v", m)
	}
	// SERVER_GENERATED 客户端提供 → server_generated_write（OBSERVE/MEDIUM）
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.id", Direction: "REQUEST", Attribute: "SERVER_GENERATED"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, newParsed())
	m = findMatch(ctx, "authz.server_generated_write")
	if m == nil || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("server_generated_write = %+v", m)
	}
	// ADMIN_WRITABLE：指定角色本人写入 → 无明细；其他角色写入 → readonly_write（attribute=ADMIN_WRITABLE）
	perms = []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.level", Direction: "REQUEST", Attribute: "ADMIN_WRITABLE", Role: "admin"}}
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, verifiedRoles("admin"), "POST /v1/x", perms, newParsed())
	if ctx.MatchCount() != 0 {
		t.Fatalf("designated admin must not match, got %+v", ctx.CopyMatches())
	}
	ctx = dsctx.New("t4", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, newParsed())
	m = findMatch(ctx, "authz.readonly_write")
	if m == nil || m.Evidence["attribute"] != "ADMIN_WRITABLE" {
		t.Fatalf("admin writable mismatch = %+v", m)
	}
	// ADMIN_WRITABLE 默认行（role 空）：未指定可写角色，运行时不可判定 → 无明细
	ctx = dsctx.New("t5", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.level", Direction: "REQUEST", Attribute: "ADMIN_WRITABLE"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, newParsed())
	if ctx.MatchCount() != 0 {
		t.Fatalf("default ADMIN_WRITABLE row must be skipped, got %+v", ctx.CopyMatches())
	}
	// WRITABLE（允许语义）→ 无明细
	ctx = dsctx.New("t6", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.note", Direction: "REQUEST", Attribute: "WRITABLE"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, newParsed())
	if ctx.MatchCount() != 0 {
		t.Fatalf("WRITABLE must not match, got %+v", ctx.CopyMatches())
	}
}

// TestCheckFieldPermissionsScopeSkip 响应方向/租户覆盖行/无权限基线：请求侧零行为。
func TestCheckFieldPermissionsScopeSkip(t *testing.T) {
	parsed := &parser.Parsed{JSONFields: map[string]string{"role": "string"}}
	// 无权限行 / 空解析 → 零行为
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckFieldPermissions(ctx, nil, "POST /v1/x", nil, parsed)
	CheckFieldPermissions(ctx, nil, "POST /v1/x", []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"}}, &parser.Parsed{})
	if ctx.MatchCount() != 0 {
		t.Fatalf("no perms / no json fields must be zero behavior, got %+v", ctx.CopyMatches())
	}
	// RESPONSE 方向行由响应相位 CheckResponseFieldPermissions 消费，请求侧恒定跳过
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	perms := []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"}}
	CheckFieldPermissions(ctx, nil, "POST /v1/x", perms, parsed)
	if ctx.MatchCount() != 0 {
		t.Fatalf("RESPONSE direction must be skipped, got %+v", ctx.CopyMatches())
	}
	// 租户覆盖行运行时无租户上下文 → 本波不判定
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN", Tenant: "t1"}}
	CheckFieldPermissions(ctx, nil, "POST /v1/x", perms, parsed)
	if ctx.MatchCount() != 0 {
		t.Fatalf("tenant-scoped row must be skipped, got %+v", ctx.CopyMatches())
	}
}

// TestCheckFieldPermissionsEvidenceNoValues 证据只含字段名/角色名/属性，绝不落请求值。
func TestCheckFieldPermissionsEvidenceNoValues(t *testing.T) {
	const secret = "SuperSecretValue-12345"
	// 构造带真实值的请求（JWT 角色 + JSON 字段值），断言全部证据不含该值
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	parsed := &parser.Parsed{
		JSONFields: map[string]string{"role": "string"},
		JSONValues: map[string]string{"role": secret},
	}
	perms := []FieldPermission{{EndpointKey: "POST /v1/x", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"}}
	CheckFieldPermissions(ctx, verifiedRoles("ops"), "POST /v1/x", perms, parsed)
	m := findMatch(ctx, "authz.forbidden_field")
	if m == nil {
		t.Fatal("expected forbidden_field")
	}
	for k, v := range m.Evidence {
		if strings.Contains(v, secret) {
			t.Fatalf("evidence must never carry request values: %s=%s", k, v)
		}
	}
	if m.Evidence["field"] != "role" || m.Evidence["location"] != "json" ||
		m.Evidence["attribute"] != "FORBIDDEN" || m.Evidence["roles"] != "ops" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// BFLA 证据同样不落值（匿名分支连角色名都没有）
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	r, _ := http.NewRequest(http.MethodGet, "http://h/v1/x", nil)
	CheckRoleBaseline(ctx, r, "GET /v1/x", "GET", []RoleBaseline{{EndpointKey: "GET /v1/x", Role: "ops", Method: "GET", Action: "READ", Allowed: true}})
	m = findMatch(ctx, "authz.bfla_anonymous")
	if m == nil {
		t.Fatal("expected bfla_anonymous")
	}
	for k, v := range m.Evidence {
		if strings.Contains(v, secret) {
			t.Fatalf("evidence must never carry request values: %s=%s", k, v)
		}
	}
}

// TestGroupAndValidateAuthzRules 归组与装配期校验（配置错误显式返回，不静默吞错）。
func TestGroupAndValidateAuthzRules(t *testing.T) {
	baselines := []RoleBaseline{
		{EndpointKey: "GET /v1/a", Role: "ops", Method: "GET", Action: "READ", Allowed: true},
		{EndpointKey: "GET /v1/a", Role: "viewer", Method: "GET", Action: "READ", Allowed: true},
		{EndpointKey: "POST /v1/b", Role: "ops", Method: "POST", Action: "WRITE", Allowed: false},
	}
	g := GroupRoleBaselines(baselines)
	if len(g["GET /v1/a"]) != 2 || len(g["POST /v1/b"]) != 1 {
		t.Fatalf("grouped = %+v", g)
	}
	if GroupRoleBaselines(nil) != nil {
		t.Fatal("nil input must yield nil map")
	}
	perms := []FieldPermission{
		{EndpointKey: "POST /v1/a", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"},
		{EndpointKey: "POST /v1/b", FieldPath: "json.note", Direction: "REQUEST", Attribute: "READ_ONLY"},
	}
	gp := GroupFieldPermissions(perms)
	if len(gp["POST /v1/a"]) != 1 || len(gp["POST /v1/b"]) != 1 {
		t.Fatalf("grouped = %+v", gp)
	}
	if GroupFieldPermissions(nil) != nil {
		t.Fatal("nil input must yield nil map")
	}
	// 合法输入通过
	if err := ValidateAuthzRules(baselines, perms); err != nil {
		t.Fatal(err)
	}
	// 非法输入逐一拒绝
	badCases := []struct {
		name string
		bl   []RoleBaseline
		pm   []FieldPermission
	}{
		{"基线缺 endpoint_key", []RoleBaseline{{Role: "ops", Method: "GET"}}, nil},
		{"基线缺 role", []RoleBaseline{{EndpointKey: "GET /v1/a", Method: "GET"}}, nil},
		{"基线缺 method", []RoleBaseline{{EndpointKey: "GET /v1/a", Role: "ops"}}, nil},
		{"权限缺 field_path", nil, []FieldPermission{{EndpointKey: "POST /v1/a", Direction: "REQUEST", Attribute: "FORBIDDEN"}}},
		{"非法 direction", nil, []FieldPermission{{EndpointKey: "POST /v1/a", FieldPath: "json.a", Direction: "UPLOAD", Attribute: "FORBIDDEN"}}},
		{"非法 attribute", nil, []FieldPermission{{EndpointKey: "POST /v1/a", FieldPath: "json.a", Direction: "REQUEST", Attribute: "HIDDEN"}}},
	}
	for _, c := range badCases {
		if err := ValidateAuthzRules(c.bl, c.pm); err == nil {
			t.Errorf("%s must fail", c.name)
		}
	}
}

// TestCheckResponseFieldPermissionsForbidden RESPONSE 方向 FORBIDDEN（W11-RAUTHZ 越权读取）：
// 默认行/角色覆盖行正反；OBSERVE/MEDIUM（响应侧不定案阻断）；脱敏计划 REMOVE/MASK 去重、HASH 不去重。
func TestCheckResponseFieldPermissionsForbidden(t *testing.T) {
	fields := map[string]string{"note": "string", "role": "string"}
	perms := []FieldPermission{{EndpointKey: "GET /v1/orders", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"}}
	// 默认行：任意角色（含匿名 nil）命中 → OBSERVE/MEDIUM
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"ops"}, "GET /v1/orders", perms, fields, nil, nil)
	m := findMatch(ctx, "authz.response_forbidden_field")
	if m == nil {
		t.Fatalf("expected response_forbidden_field, got %+v", ctx.CopyMatches())
	}
	if m.Detector != "api_authz" || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
		t.Fatalf("response forbidden must be OBSERVE/MEDIUM: %+v", m)
	}
	if m.Evidence["endpoint_key"] != "GET /v1/orders" || m.Evidence["field"] != "role" ||
		m.Evidence["location"] != "response_json" || m.Evidence["attribute"] != "FORBIDDEN" ||
		m.Evidence["roles"] != "ops" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 未授权字段（note 无权限行）不报：上例仅 json.role 一条
	if n := ctx.MatchCount(); n != 1 {
		t.Fatalf("exactly one field match expected, got %d", n)
	}
	// 匿名（无角色集）默认行同样命中
	ctx = dsctx.New("t-anon", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/orders", perms, fields, nil, nil)
	if findMatch(ctx, "authz.response_forbidden_field") == nil {
		t.Fatal("default row must fire for anonymous")
	}
	// 角色覆盖行：行内角色命中才判
	rolePerms := []FieldPermission{{EndpointKey: "GET /v1/orders", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN", Role: "guest"}}
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"ops"}, "GET /v1/orders", rolePerms, fields, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("role-scoped FORBIDDEN must not fire for other roles, got %+v", ctx.CopyMatches())
	}
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"guest"}, "GET /v1/orders", rolePerms, fields, nil, nil)
	if findMatch(ctx, "authz.response_forbidden_field") == nil {
		t.Fatal("role-scoped FORBIDDEN must fire for the scoped role")
	}
	// 脱敏去重：字段被本相位 REMOVE/MASK 计划覆盖 → 不重复判定（脱敏治理优先）
	for _, algo := range []string{"REMOVE", "MASK"} {
		ctx = dsctx.New("t4-"+algo, dsctx.DefaultParseLimits())
		plan := []dsctx.FieldTransform{{FieldPath: "role", Algorithm: algo}}
		CheckResponseFieldPermissions(ctx, nil, "GET /v1/orders", perms, fields, plan, nil)
		if ctx.MatchCount() != 0 {
			t.Fatalf("%s-covered forbidden field must be deduped, got %+v", algo, ctx.CopyMatches())
		}
	}
	// HASH 仍外发摘要：不参与去重
	ctx = dsctx.New("t5", dsctx.DefaultParseLimits())
	plan := []dsctx.FieldTransform{{FieldPath: "role", Algorithm: "HASH"}}
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/orders", perms, fields, plan, nil)
	if findMatch(ctx, "authz.response_forbidden_field") == nil {
		t.Fatal("HASH-covered field still leaks digest, must fire")
	}
}

// TestCheckResponseFieldPermissionsSensitive RESPONSE 方向 SENSITIVE：正反 / 角色覆盖行 /
// 与敏感字段检测去重 / FORBIDDEN 优先级（每字段至多一条明细）。
func TestCheckResponseFieldPermissionsSensitive(t *testing.T) {
	fields := map[string]string{"internal_note": "string"}
	perms := []FieldPermission{{EndpointKey: "GET /v1/users", FieldPath: "json.internal_note", Direction: "RESPONSE", Attribute: "SENSITIVE"}}
	// 未被敏感检测命中 → response_sensitive_field（OBSERVE/LOW）
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"ops"}, "GET /v1/users", perms, fields, nil, nil)
	m := findMatch(ctx, "authz.response_sensitive_field")
	if m == nil {
		t.Fatalf("expected response_sensitive_field, got %+v", ctx.CopyMatches())
	}
	if m.Category != "OBSERVE" || m.Severity != "LOW" {
		t.Fatalf("response sensitive must be OBSERVE/LOW: %+v", m)
	}
	if m.Evidence["field"] != "internal_note" || m.Evidence["attribute"] != "SENSITIVE" ||
		m.Evidence["location"] != "response_json" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	// 已被敏感字段检测命中（sensitive.response_field 同路径）→ 不重复产出
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	hits := []dsctx.SensitiveFieldHit{{Path: "internal_note", DataType: "credential"}}
	CheckResponseFieldPermissions(ctx, []string{"ops"}, "GET /v1/users", perms, fields, nil, hits)
	if ctx.MatchCount() != 0 {
		t.Fatalf("sensitive-detector-covered field must be deduped, got %+v", ctx.CopyMatches())
	}
	// 角色覆盖行：行内角色命中才判
	rolePerms := []FieldPermission{{EndpointKey: "GET /v1/users", FieldPath: "json.internal_note", Direction: "RESPONSE", Attribute: "SENSITIVE", Role: "viewer"}}
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"admin"}, "GET /v1/users", rolePerms, fields, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("role-scoped SENSITIVE must not fire for other roles, got %+v", ctx.CopyMatches())
	}
	ctx = dsctx.New("t4", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"viewer"}, "GET /v1/users", rolePerms, fields, nil, nil)
	if findMatch(ctx, "authz.response_sensitive_field") == nil {
		t.Fatal("role-scoped SENSITIVE must fire for the scoped role")
	}
	// 同字段 FORBIDDEN + SENSITIVE 并存：FORBIDDEN 优先，每字段至多一条明细
	both := []FieldPermission{
		{EndpointKey: "GET /v1/users", FieldPath: "json.internal_note", Direction: "RESPONSE", Attribute: "SENSITIVE"},
		{EndpointKey: "GET /v1/users", FieldPath: "json.internal_note", Direction: "RESPONSE", Attribute: "FORBIDDEN"},
	}
	ctx = dsctx.New("t5", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/users", both, fields, nil, nil)
	if findMatch(ctx, "authz.response_forbidden_field") == nil {
		t.Fatal("FORBIDDEN must take priority over SENSITIVE")
	}
	if findMatch(ctx, "authz.response_sensitive_field") != nil {
		t.Fatal("one finding per field: SENSITIVE must not stack on FORBIDDEN")
	}
}

// TestCheckResponseFieldPermissionsScopeSkip 零行为边界：无权限行 / 空解析产物 / REQUEST 方向行 /
// 租户覆盖行 / 非 json. 前缀行 / nil 上下文。
func TestCheckResponseFieldPermissionsScopeSkip(t *testing.T) {
	fields := map[string]string{"role": "string"}
	// 无权限行 / 空解析产物 → 零行为
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/x", nil, fields, nil, nil)
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/x",
		[]FieldPermission{{EndpointKey: "GET /v1/x", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"}}, nil, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("no perms / no parsed fields must be zero behavior, got %+v", ctx.CopyMatches())
	}
	// REQUEST 方向行（响应侧不消费）
	ctx = dsctx.New("t2", dsctx.DefaultParseLimits())
	perms := []FieldPermission{{EndpointKey: "GET /v1/x", FieldPath: "json.role", Direction: "REQUEST", Attribute: "FORBIDDEN"}}
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/x", perms, fields, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("REQUEST direction must be skipped on response side, got %+v", ctx.CopyMatches())
	}
	// 租户覆盖行运行时无租户上下文 → 本波不判定
	ctx = dsctx.New("t3", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "GET /v1/x", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN", Tenant: "t1"}}
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/x", perms, fields, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("tenant-scoped row must be skipped, got %+v", ctx.CopyMatches())
	}
	// 非 json. 前缀行（query./header. 等位置响应侧不可判定）
	ctx = dsctx.New("t4", dsctx.DefaultParseLimits())
	perms = []FieldPermission{{EndpointKey: "GET /v1/x", FieldPath: "query.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"}}
	CheckResponseFieldPermissions(ctx, nil, "GET /v1/x", perms, fields, nil, nil)
	if ctx.MatchCount() != 0 {
		t.Fatalf("non-json field_path must be skipped, got %+v", ctx.CopyMatches())
	}
	// nil 上下文：不 panic、零行为
	CheckResponseFieldPermissions(nil, nil, "GET /v1/x",
		[]FieldPermission{{EndpointKey: "GET /v1/x", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"}}, fields, nil, nil)
}

// TestCheckResponseFieldPermissionsEvidenceNoValues 响应侧证据只含字段路径/属性/角色名，绝不落响应值。
func TestCheckResponseFieldPermissionsEvidenceNoValues(t *testing.T) {
	const secret = "SuperSecretValue-12345"
	// fields 为解析产物（路径→类型，本不含值）；secret 模拟响应明文值，断言全部证据不携带
	fields := map[string]string{"role": "string", "internal_note": "string"}
	perms := []FieldPermission{
		{EndpointKey: "GET /v1/x", FieldPath: "json.role", Direction: "RESPONSE", Attribute: "FORBIDDEN"},
		{EndpointKey: "GET /v1/x", FieldPath: "json.internal_note", Direction: "RESPONSE", Attribute: "SENSITIVE"},
	}
	ctx := dsctx.New("t", dsctx.DefaultParseLimits())
	CheckResponseFieldPermissions(ctx, []string{"ops"}, "GET /v1/x", perms, fields, nil, nil)
	if ctx.MatchCount() != 2 {
		t.Fatalf("expected forbidden + sensitive findings, got %+v", ctx.CopyMatches())
	}
	for _, m := range ctx.CopyMatches() {
		for k, v := range m.Evidence {
			if strings.Contains(v, secret) {
				t.Fatalf("evidence must never carry response values: %s=%s (%s)", k, v, m.RuleID)
			}
		}
	}
}
