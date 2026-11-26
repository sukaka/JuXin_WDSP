// apimcpguard_test.go MCP G1 装配与请求链测试：目录 hash 重算比对/绑定归一/
// writeMCPErrorResponse 字节形状/e2e 实断与放行/SSE 逐消息中途阻断/能力自报/C01。
package jiuzhang_guard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"go.uber.org/zap"
)

// testMCPCatalogSection 构造合法目录段（catalog_hash 按冻结算法现算——
// mcp-catalog-sha256:v1: + hex(sha256(排序拼接 tool_hash))）。
func testMCPCatalogSection(t *testing.T) string {
	t.Helper()
	hashes := []string{"mcp-tool-sha256:v1:echo", "mcp-tool-sha256:v1:risky"}
	sort.Strings(hashes)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "")))
	hash := "mcp-catalog-sha256:v1:" + hex.EncodeToString(sum[:])
	cat := mcpCatalogJSON{
		Name:            "test-catalog",
		ServiceIdentity: "mcp-test",
		ProtocolVersion: "2025-11-25",
		CatalogHash:     hash,
		Tools: []mcpToolJSON{
			{
				ToolName: "echo", ToolVersion: "1.0", ToolHash: "mcp-tool-sha256:v1:echo",
				RiskLevel: "LOW", DataClassification: "PUBLIC",
				InputSchema:  json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}`),
				OutputSchema: json.RawMessage(`{"type":"object","additionalProperties":true}`),
			},
			{
				ToolName: "risky", ToolVersion: "1.0", ToolHash: "mcp-tool-sha256:v1:risky",
				RiskLevel: "HIGH", DataClassification: "CONFIDENTIAL",
			},
		},
	}
	raw, err := json.Marshal([]mcpCatalogJSON{cat})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// newMCPGuard 构造带 MCP 装配置的 Guard（newAPITestGuard 同形态直注装配产物）。
func newMCPGuard(t *testing.T, mode string, catalogJSON string, bindings []mcpBindingJSON) (*Guard, string) {
	t.Helper()
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	var cats []mcpCatalogJSON
	if err := json.Unmarshal([]byte(catalogJSON), &cats); err != nil {
		t.Fatalf("catalog unmarshal: %v", err)
	}
	g.APIMCPToolCatalogs = cats
	g.APIMCPBindings = bindings
	g.AppID = "app-1"
	g.apiMCPGuard = g.buildMCPGuardConfig()
	if g.apiMCPGuard == nil {
		t.Fatal("装配置应非 nil")
	}
	return g, logPath
}

func mcpCallBody(toolName string, args map[string]any) string {
	raw, _ := json.Marshal(args)
	return `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"` + toolName + `","arguments":` + string(raw) + `}}`
}

// TestMCPGuardAssembly 装配：hash 比对通过/不符拒装/未知目录保留行/归一。
func TestMCPGuardAssembly(t *testing.T) {
	section := testMCPCatalogSection(t)
	t.Run("合法目录装配通过", func(t *testing.T) {
		g, _ := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
			{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "PROTECT"},
		})
		cfg := g.apiMCPGuard.ForEndpoint("app-1", "/mcp")
		if cfg == nil {
			t.Fatal("绑定应命中")
		}
		// 未知应用/路径不命中（精确匹配）
		if g.apiMCPGuard.ForEndpoint("app-2", "/mcp") != nil || g.apiMCPGuard.ForEndpoint("app-1", "/MCP") != nil {
			t.Fatal("精确匹配大小写敏感")
		}
	})
	t.Run("hash 不符整目录拒装（绑定无目录不误断）", func(t *testing.T) {
		sum := sha256.Sum256([]byte(strings.Join([]string{"mcp-tool-sha256:v1:echo", "mcp-tool-sha256:v1:risky"}, "")))
		bad := strings.Replace(section, hex.EncodeToString(sum[:]), strings.Repeat("0", 64), 1)
		g, _ := newMCPGuard(t, "PROTECT", bad, []mcpBindingJSON{
			{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "PROTECT"},
		})
		ep := g.apiMCPGuard.Apps["app-1"]["/mcp"]
		if ep.Catalog != nil {
			t.Fatal("摘要不符应拒装（Catalog=nil → 运行期 COV_NO_CATALOG）")
		}
	})
	t.Run("绑定引用未知目录保留行", func(t *testing.T) {
		g, _ := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
			{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "ghost", Mode: "PROTECT"},
		})
		ep := g.apiMCPGuard.Apps["app-1"]["/mcp"]
		if ep.Catalog != nil {
			t.Fatal("未知目录行保留但无目录")
		}
	})
	t.Run("mode 词表外归一 OBSERVE", func(t *testing.T) {
		g, _ := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
			{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "BLOCK"},
		})
		if g.apiMCPGuard.Apps["app-1"]["/mcp"].Mode != mcpguard.ModeObserve {
			t.Fatal("词表外应归一 OBSERVE")
		}
	})
	t.Run("无目录无绑定 nil 零行为（NG-T-C01）", func(t *testing.T) {
		g := &Guard{logger: zap.NewNop()}
		if g.buildMCPGuardConfig() != nil {
			t.Fatal("空配置应 nil")
		}
	})
}

// TestMCPProtectBlockE2E PROTECT 实断：403 + JSON-RPC 错误对象（-32011 固定短语，
// id 回显，data.source/request_id；源站不到达）；事件如实。
// 前置：PROTECT 绑定要求 JWT VERIFIED（§1.4-1——测试经请求上下文注入
// jwtverify.StatusVerified 信号（jwt_trust 产出口径同构）。
func TestMCPProtectBlockE2E(t *testing.T) {
	section := testMCPCatalogSection(t)
	g, logPath := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
		{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "PROTECT"},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("ghost_tool", map[string]any{})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-block-1")
	verified := jwtverify.VerificationResult{Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1", VerifiedTenantID: "t-1"}
	*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, verified))
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if called {
		t.Fatal("违规请求不得到达源站")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	wantBody := `{"jsonrpc":"2.0","id":42,"error":{"code":-32011,"message":"mcp tool call rejected by protection policy","data":{"source":"jiuzhang-wdsp","request_id":"req-mcp-block-1"}}}`
	if rec.Body.String() != wantBody {
		t.Fatalf("body = %q\n应精确等于 %q", rec.Body.String(), wantBody)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "mcp.tool_not_in_catalog" && m.Evidence["tool"] == "ghost_tool" {
			found = true
		}
	}
	if !found {
		t.Fatalf("事件缺 mcp.tool_not_in_catalog: %+v", recs[0].Details)
	}
}

// TestMCPObservePassthroughE2E OBSERVE 绑定：违规只记录放行（源站到达+响应透传）。
func TestMCPObservePassthroughE2E(t *testing.T) {
	section := testMCPCatalogSection(t)
	g, logPath := newMCPGuard(t, "OBSERVE", section, []mcpBindingJSON{
		{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "OBSERVE"},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":42,"result":{"ok":true}}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("ghost_tool", map[string]any{})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-obs-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("OBSERVE 应放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "mcp.tool_not_in_catalog" && m.Category == "OBSERVE" {
			found = true
		}
	}
	if !found {
		t.Fatalf("OBSERVE 拟动作未记录: %+v", recs[0].Details)
	}
}

// TestMCPAbsentZeroBehaviorE2E NG-T-C01：无目录无绑定 → 全链零行为。
func TestMCPAbsentZeroBehaviorE2E(t *testing.T) {
	g, logPath := newAPITestGuard(t, "PROTECT", nil)
	if g.apiMCPGuard != nil {
		t.Fatal("无目录无绑定装配应 nil")
	}
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`ok`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "a"})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-none-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("无绑定应原样放行: called=%v code=%d", called, rec.Code)
	}
	data := mustReadRawLine(t, logPath)
	if strings.Contains(data, "mcpguard") || strings.Contains(data, "mcp.coverage_v1") {
		t.Fatalf("无绑定事件不得含 mcpguard 痕迹: %s", data)
	}
}

// TestWriteMCPErrorResponseShape 错误对象字节形状（错误码表逐字；id 缺省 null；
// 未登记码防御归一）。
func TestWriteMCPErrorResponseShape(t *testing.T) {
	g := &Guard{logger: zap.NewNop()}
	rec := httptest.NewRecorder()
	g.writeMCPErrorResponse(rec, "req-1", -32010, 403, "null")
	if rec.Code != 403 {
		t.Fatalf("status = %d", rec.Code)
	}
	want := `{"jsonrpc":"2.0","id":null,"error":{"code":-32010,"message":"mcp tool call requires verified caller","data":{"source":"jiuzhang-wdsp","request_id":"req-1"}}}`
	if rec.Body.String() != want {
		t.Fatalf("body = %q", rec.Body.String())
	}
	// 413/429 分明 + 固定短语逐字
	for code, tc := range map[int]struct {
		status int
		msg    string
	}{
		-32011: {403, "mcp tool call rejected by protection policy"},
		-32012: {403, "mcp tool call arguments rejected"},
		-32013: {413, "mcp request exceeds resource budget"},
		-32014: {403, "mcp tool result blocked by protection policy"},
	} {
		rec := httptest.NewRecorder()
		g.writeMCPErrorResponse(rec, "r", code, tc.status, `"abc-9"`)
		if rec.Code != tc.status {
			t.Errorf("%d: status = %d，应 %d", code, rec.Code, tc.status)
		}
		if !strings.Contains(rec.Body.String(), `"code":`+strconv.Itoa(code)) || !strings.Contains(rec.Body.String(), tc.msg) ||
			!strings.Contains(rec.Body.String(), `"id":"abc-9"`) {
			t.Errorf("%d: body = %q", code, rec.Body.String())
		}
	}
	// 未登记码防御归一 -32011；非法 HTTP 归一 403
	rec = httptest.NewRecorder()
	g.writeMCPErrorResponse(rec, "r", -32999, 999, "null")
	if rec.Code != 403 || !strings.Contains(rec.Body.String(), `"code":-32011`) {
		t.Fatalf("防御归一: %d %q", rec.Code, rec.Body.String())
	}
}

// TestCapabilityReportMCP 能力自报恒报（protocols.mcp=pin_v2 + detectors
// mcp.toolcall=mcp/2 + mcp.observe=mcp/1 + mcp.pinning=mcppin/1 保留——不绑配置态）。
func TestCapabilityReportMCP(t *testing.T) {
	m := buildCapabilityManifest(capabilityInputs{NodeID: "n1"}, time.Now())
	if m.Protocols["mcp"] != "pin_v2" {
		t.Fatalf("protocols.mcp = %q，应 pin_v2（恒报）", m.Protocols["mcp"])
	}
	var toolcall, observe, pinning bool
	for _, d := range m.Detectors {
		if d.Name == "mcp.toolcall" && d.Version == "mcp/2" {
			toolcall = true
		}
		if d.Name == "mcp.observe" && d.Version == "mcp/1" {
			observe = true
		}
		if d.Name == "mcp.pinning" && d.Version == "mcppin/1" {
			pinning = true
		}
	}
	if !toolcall || !observe || !pinning {
		t.Fatalf("detectors = %+v", m.Detectors)
	}
}

// TestMCPProtectNoJwtDependencySkipE2E PROTECT 绑定但 jwt 未覆盖端点：
// 依赖缺席 SKIPPED(COV_NO_TRUSTED_SUBJECT) 放行+披露——恒不阻断（UNKNOWN 红线）。
func TestMCPProtectNoJwtDependencySkipE2E(t *testing.T) {
	section := testMCPCatalogSection(t)
	g, logPath := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
		{ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "test-catalog", Mode: "PROTECT"},
	})
	called := false
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":42,"result":{}}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("ghost_tool", map[string]any{})))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-mcp-nojwt-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("依赖缺席应放行: called=%v code=%d", called, rec.Code)
	}
	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("事件数 = %d", len(recs))
	}
	var found bool
	for _, m := range recs[0].Details {
		if m.RuleID == "mcpguard.dependency_unavailable" && m.Evidence["dependency_unavailable"] == "true" {
			found = true
		}
		if m.Category == "BLOCK" {
			t.Fatal("依赖缺席恒不阻断")
		}
	}
	if !found {
		t.Fatalf("缺依赖披露: %+v", recs[0].Details)
	}
}

// TestMCPGuardPhase9C1Assembly 验证 Phase 9C-1 扩展字段装配归一与 OAuth 2.1 URL 校验。
func TestMCPGuardPhase9C1Assembly(t *testing.T) {
	inSchema := json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}`)
	pinHash := mcpguard.ComputeToolDefinitionHash("echo", "Echo back text", inSchema)
	hashes := []string{"mcp-tool-sha256:v1:echo", "mcp-tool-sha256:v1:other"}
	sort.Strings(hashes)
	sum := sha256.Sum256([]byte(strings.Join(hashes, "")))
	catHash := "mcp-catalog-sha256:v1:" + hex.EncodeToString(sum[:])

	cat := mcpCatalogJSON{
		Name:            "pin-cat",
		ServiceIdentity: "mcp-pin",
		ProtocolVersion: "2025-11-25",
		CatalogHash:     catHash,
		Tools: []mcpToolJSON{
			{
				ToolName:             "echo",
				ToolVersion:          "1.0",
				ToolHash:             "mcp-tool-sha256:v1:echo",
				RiskLevel:            "LOW",
				DataClassification:   "PUBLIC",
				InputSchema:          inSchema,
				PinnedDefinitionHash: pinHash,
				PinEnforcement:       "PROTECT",
			},
			{
				ToolName:       "other",
				ToolVersion:    "1.0",
				ToolHash:       "mcp-tool-sha256:v1:other",
				RiskLevel:      "LOW",
				PinEnforcement: "INVALID_MODE",
			},
		},
	}
	rawCat, err := json.Marshal([]mcpCatalogJSON{cat})
	if err != nil {
		t.Fatal(err)
	}

	g, _ := newMCPGuard(t, "PROTECT", string(rawCat), []mcpBindingJSON{
		{
			ApplicationID:            "app-1",
			EndpointPath:             "/mcp",
			CatalogName:              "pin-cat",
			Mode:                     "PROTECT",
			ResponseGuardMode:        "SANITIZE",
			RequireSessionBinding:    true,
			OAuthResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource",
		},
		{
			ApplicationID:            "app-1",
			EndpointPath:             "/mcp-bad-url",
			CatalogName:              "pin-cat",
			Mode:                     "OBSERVE",
			ResponseGuardMode:        "BOGUS",
			OAuthResourceMetadataURL: "http://insecure.example.com/meta\r\nX-Inject: 1",
		},
	})

	ep := g.apiMCPGuard.Apps["app-1"]["/mcp"]
	if ep.ResponseGuardMode != mcpguard.ResponseGuardSanitize || !ep.RequireSessionBinding ||
		ep.OAuthResourceMetadataURL != "https://mcp.example.com/.well-known/oauth-protected-resource" {
		t.Fatalf("valid Phase 9C-1 binding fields not preserved: %+v", ep)
	}
	if ep.Catalog.Tools["echo"].PinnedDefinitionHash != pinHash || ep.Catalog.Tools["echo"].PinEnforcement != mcpguard.PinEnforcementProtect {
		t.Fatalf("pinned tool fields = %+v", ep.Catalog.Tools["echo"])
	}
	if ep.Catalog.Tools["other"].PinEnforcement != mcpguard.PinEnforcementObserve {
		t.Fatalf("unknown pin_enforcement must normalize to OBSERVE, got %q", ep.Catalog.Tools["other"].PinEnforcement)
	}

	epBad := g.apiMCPGuard.Apps["app-1"]["/mcp-bad-url"]
	if epBad.ResponseGuardMode != mcpguard.ResponseGuardObserve {
		t.Fatalf("unknown response_guard_mode must normalize to OBSERVE, got %q", epBad.ResponseGuardMode)
	}
	if epBad.OAuthResourceMetadataURL != "" {
		t.Fatalf("invalid oauth_resource_metadata_url must be ignored, got %q", epBad.OAuthResourceMetadataURL)
	}
}

// TestMCPSessionHijackE2E 验证 Streamable HTTP 会话跨主体复用在 PROTECT 下以 -32010 阻断。
func TestMCPSessionHijackE2E(t *testing.T) {
	section := testMCPCatalogSection(t)
	g, logPath := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{
		{
			ApplicationID:         "app-1",
			EndpointPath:          "/mcp",
			CatalogName:           "test-catalog",
			Mode:                  "PROTECT",
			RequireSessionBinding: true,
		},
	})
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":42,"result":{"ok":true}}`))
		return nil
	})

	const sessID = "streamable-session-abc123"
	// 1st request: user-1 establishes session binding
	req1 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("Mcp-Session-Id", sessID)
	req1.Header.Set("X-Request-Id", "req-sess-1")
	*req1 = *req1.WithContext(context.WithValue(req1.Context(), jwtResultKey{}, jwtverify.VerificationResult{
		Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-1", VerifiedTenantID: "t-1",
	}))
	rec1 := httptest.NewRecorder()
	if err := g.serveNext(rec1, req1, next); err != nil {
		t.Fatalf("req1 serveNext: %v", err)
	}
	if rec1.Code != http.StatusOK {
		t.Fatalf("req1 status = %d, want 200", rec1.Code)
	}

	// 2nd request: user-2 reuses user-1's Mcp-Session-Id -> blocked 403 / -32010
	called2 := false
	next2 := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		called2 = true
		return nil
	})
	req2 := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "steal"})))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Mcp-Session-Id", sessID)
	req2.Header.Set("X-Request-Id", "req-sess-2")
	*req2 = *req2.WithContext(context.WithValue(req2.Context(), jwtResultKey{}, jwtverify.VerificationResult{
		Status: jwtverify.StatusVerified, VerifiedPrincipalID: "user-2", VerifiedTenantID: "t-1",
	}))
	rec2 := httptest.NewRecorder()
	if err := g.serveNext(rec2, req2, next2); err != nil {
		t.Fatalf("req2 serveNext: %v", err)
	}
	if called2 {
		t.Fatal("hijacked session request must not reach upstream")
	}
	if rec2.Code != http.StatusForbidden || !strings.Contains(rec2.Body.String(), `"code":-32010`) {
		t.Fatalf("req2 response = %d %s", rec2.Code, rec2.Body.String())
	}
	recs := readAPIRecords(t, logPath)
	var hijackFound bool
	for _, rec := range recs {
		for _, m := range rec.Details {
			if m.RuleID == "mcp.session_hijack_suspected" && m.Category == "BLOCK" {
				hijackFound = true
				for _, v := range m.Evidence {
					if strings.Contains(v, sessID) {
						t.Fatal("event evidence must never log raw Mcp-Session-Id")
					}
				}
			}
		}
	}
	if !hijackFound {
		t.Fatalf("missing mcp.session_hijack_suspected in events: %+v", recs)
	}
}

// TestMCPToolsListRugPullBlockE2E 验证 tools/list 响应漂移在 PROTECT 下被干净抑制为 -32014。
func TestMCPToolsListRugPullBlockE2E(t *testing.T) {
	inSchema := json.RawMessage(`{"type":"object","properties":{"text":{"type":"string"}},"required":["text"],"additionalProperties":false}`)
	pinHash := mcpguard.ComputeToolDefinitionHash("echo", "Echo back text", inSchema)
	hashes := []string{"mcp-tool-sha256:v1:echo"}
	sum := sha256.Sum256([]byte(hashes[0]))
	cat := mcpCatalogJSON{
		Name:        "pin-cat",
		CatalogHash: "mcp-catalog-sha256:v1:" + hex.EncodeToString(sum[:]),
		Tools: []mcpToolJSON{{
			ToolName:             "echo",
			ToolVersion:          "1.0",
			ToolHash:             "mcp-tool-sha256:v1:echo",
			RiskLevel:            "LOW",
			DataClassification:   "PUBLIC",
			InputSchema:          inSchema,
			PinnedDefinitionHash: pinHash,
			PinEnforcement:       "PROTECT",
		}},
	}
	rawCat, _ := json.Marshal([]mcpCatalogJSON{cat})
	g, logPath := newMCPGuard(t, "PROTECT", string(rawCat), []mcpBindingJSON{{
		ApplicationID: "app-1", EndpointPath: "/mcp", CatalogName: "pin-cat", Mode: "PROTECT",
	}})

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":77,"result":{"tools":[{"name":"echo","description":"RUG_PULL_SECRET_PROMPT","inputSchema":{"type":"object"}}]}}`))
		return nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":77,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-Id", "req-rugpull-1")
	rec := httptest.NewRecorder()
	if err := g.serveNext(rec, req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":-32014`) || !strings.Contains(rec.Body.String(), `"id":77`) {
		t.Fatalf("expected clean -32014 block: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "RUG_PULL_SECRET_PROMPT") {
		t.Fatalf("blocked tools/list body leaked upstream payload: %s", rec.Body.String())
	}
	rawLog := mustReadRawLine(t, logPath)
	if strings.Contains(rawLog, "RUG_PULL_SECRET_PROMPT") {
		t.Fatalf("event log leaked raw description text: %s", rawLog)
	}
}

// TestMCPSanitizeAndOAuth21ChallengeE2E 验证非流式 SANITIZE 清洗回写响应体与 OAuth 2.1 挑战头。
func TestMCPSanitizeAndOAuth21ChallengeE2E(t *testing.T) {
	section := testMCPCatalogSection(t)
	g, _ := newMCPGuard(t, "PROTECT", section, []mcpBindingJSON{{
		ApplicationID:            "app-1",
		EndpointPath:             "/mcp",
		CatalogName:              "test-catalog",
		Mode:                     "PROTECT",
		ResponseGuardMode:        "SANITIZE",
		OAuthResourceMetadataURL: "https://mcp.example.com/.well-known/oauth-protected-resource",
	}})

	t.Run("SANITIZE rewrites non-streaming JSON-RPC response body", func(t *testing.T) {
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":88,"result":{"contents":[{"text":"Safe\u200B\uDB40\uDC41\u202E text"}]}}`))
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":88,"method":"resources/read","params":{"uri":"file:///x"}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "req-san-e2e-1")
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), `"text":"Safe text"`) {
			t.Fatalf("expected sanitized body, got %s", rec.Body.String())
		}
		if strings.ContainsRune(rec.Body.String(), '\u200B') || strings.ContainsRune(rec.Body.String(), '\u202E') {
			t.Fatalf("invisible runes survived: %s", rec.Body.String())
		}
	})

	t.Run("OAuth 2.1 WWW-Authenticate header attached on -32010 unauthenticated MCP call", func(t *testing.T) {
		next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			t.Fatal("untrusted caller must not reach upstream")
			return nil
		})
		req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(mcpCallBody("echo", map[string]any{"text": "hi"})))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Request-Id", "req-oauth21-1")
		*req = *req.WithContext(context.WithValue(req.Context(), jwtResultKey{}, jwtverify.VerificationResult{
			Status: jwtverify.StatusUnverified,
		}))
		rec := httptest.NewRecorder()
		if err := g.serveNext(rec, req, next); err != nil {
			t.Fatalf("serveNext: %v", err)
		}
		if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), `"code":-32010`) {
			t.Fatalf("status/body = %d %s", rec.Code, rec.Body.String())
		}
		wantHdr := `Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource"`
		if got := rec.Header().Get("WWW-Authenticate"); got != wantHdr {
			t.Fatalf("WWW-Authenticate = %q, want %q", got, wantHdr)
		}
	})
}
