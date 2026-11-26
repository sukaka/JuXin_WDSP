package clientside

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestValidatePolicyAndBounds(t *testing.T) {
	appID := uuid.New()
	p := DefaultPolicy(appID)
	p.Mode = "protect"
	p.CSPMode = "enforce"
	p.SensitivePaths = []string{" /login ", "/checkout", "/checkout", "/pay/card"}
	p.ProbeEnabled = true
	p.StripUnauthorizedScripts = true
	p.AllowedScriptOrigins = []string{"'self'", "https://cdn.example.com", "https://*.static.example.com:8443", "https:"}
	p.AllowedConnectOrigins = []string{"'self'", "wss://api.example.com", "api.example.com"}
	p.AllowedFormOrigins = []string{"'self'", "https://pay.example.com/submit"}
	p.CustomCSPDirectives = "object-src 'none'; base-uri 'self'"

	NormalizePolicy(p)
	if p.Mode != ModeProtect || p.CSPMode != CSPModeEnforce {
		t.Fatalf("normalize failed: mode=%q csp=%q", p.Mode, p.CSPMode)
	}
	if len(p.SensitivePaths) != 3 {
		t.Fatalf("expected deduplicated 3 sensitive_paths, got %v", p.SensitivePaths)
	}
	if errs := ValidatePolicy(p); len(errs) > 0 {
		t.Fatalf("valid policy rejected: %+v", errs)
	}

	fieldSet := func(errs []FieldError) map[string]bool {
		m := map[string]bool{}
		for _, e := range errs {
			m[e.Field] = true
		}
		return m
	}

	tooManyPaths := make([]string, MaxSensitivePaths+1)
	for i := range tooManyPaths {
		tooManyPaths[i] = "/p" + strings.Repeat("a", i%5+1) + string(rune('a'+i%26))
	}
	tooManyOrigins := make([]string, MaxOrigins+1)
	for i := range tooManyOrigins {
		tooManyOrigins[i] = "https://cdn" + string(rune('a'+i%26)) + ".example.com"
	}

	cases := []struct {
		name   string
		mutate func(*Policy)
		field  string
	}{
		{"非法mode", func(x *Policy) { x.Mode = "BLOCK" }, "mode"},
		{"非法csp_mode", func(x *Policy) { x.CSPMode = "STRICT" }, "csp_mode"},
		{"敏感路径不以斜杠开头", func(x *Policy) { x.SensitivePaths = []string{"checkout"} }, "sensitive_paths[0]"},
		{"敏感路径含查询串", func(x *Policy) { x.SensitivePaths = []string{"/checkout?a=1"} }, "sensitive_paths[0]"},
		{"敏感路径含锚点", func(x *Policy) { x.SensitivePaths = []string{"/checkout#top"} }, "sensitive_paths[0]"},
		{"敏感路径超长", func(x *Policy) { x.SensitivePaths = []string{"/" + strings.Repeat("a", MaxPathLen)} }, "sensitive_paths[0]"},
		{"敏感路径超64条", func(x *Policy) { x.SensitivePaths = tooManyPaths }, "sensitive_paths"},
		{"CSP源含分号注入", func(x *Policy) { x.AllowedScriptOrigins = []string{"'self'; script-src *"} }, "allowed_script_origins[0]"},
		{"CSP源含CRLF注入", func(x *Policy) { x.AllowedConnectOrigins = []string{"https://a.com\r\nX-Evil: 1"} }, "allowed_connect_origins[0]"},
		{"CSP源含未知单引号关键字", func(x *Policy) { x.AllowedFormOrigins = []string{"'evil-keyword'"} }, "allowed_form_origins[0]"},
		{"CSP源超64条", func(x *Policy) { x.AllowedScriptOrigins = tooManyOrigins }, "allowed_script_origins"},
		{"自定义CSP指令含CRLF", func(x *Policy) { x.CustomCSPDirectives = "object-src 'none'\r\nSet-Cookie: a=1" }, "custom_csp_directives"},
		{"自定义CSP指令超2048", func(x *Policy) { x.CustomCSPDirectives = strings.Repeat("a", MaxCustomDirectivesLen+1) }, "custom_csp_directives"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := *p
			cp.SensitivePaths = append([]string(nil), p.SensitivePaths...)
			cp.AllowedScriptOrigins = append([]string(nil), p.AllowedScriptOrigins...)
			cp.AllowedConnectOrigins = append([]string(nil), p.AllowedConnectOrigins...)
			cp.AllowedFormOrigins = append([]string(nil), p.AllowedFormOrigins...)
			tc.mutate(&cp)
			errs := ValidatePolicy(&cp)
			if !fieldSet(errs)[tc.field] {
				t.Fatalf("expected error on %q, got %+v", tc.field, errs)
			}
		})
	}
}

func TestValidateScriptAndPCIDSS643(t *testing.T) {
	validSRI := "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
	sc := Script{
		ApplicationID: uuid.New(),
		ScriptURL:     "https://cdn.example.com/checkout.js",
		ScriptType:    "external",
		SRIHash:       validSRI,
		Status:        "authorized",
		Justification: "结账页支付 SDK，由支付网关团队维护",
	}
	NormalizeScript(&sc)
	if sc.ScriptOrigin != "https://cdn.example.com" {
		t.Fatalf("origin = %q, want https://cdn.example.com", sc.ScriptOrigin)
	}
	if errs := ValidateCreateScript(&sc); len(errs) > 0 {
		t.Fatalf("valid script rejected: %+v", errs)
	}

	// PCI DSS 4.0 6.4.3：AUTHORIZED 必须提供非空 justification
	noJust := sc
	noJust.Justification = "   "
	if errs := ValidateCreateScript(&noJust); len(errs) == 0 || errs[0].Field != "justification" {
		t.Fatalf("AUTHORIZED without justification must fail on justification, got %+v", errs)
	}
	if errs := ValidateUpdateScript(validSRI, ScriptStatusAuthorized, ""); len(errs) == 0 || errs[0].Field != "justification" {
		t.Fatalf("Update AUTHORIZED without justification must fail, got %+v", errs)
	}
	// BLOCKED / DISCOVERED 允许空 justification
	if errs := ValidateUpdateScript("", ScriptStatusBlocked, ""); len(errs) > 0 {
		t.Fatalf("BLOCKED with empty justification should pass, got %+v", errs)
	}

	// SRI 哈希校验
	for _, okSRI := range []string{"", "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", validSRI, "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="} {
		if err := ValidateSRIHash(okSRI); err != nil {
			t.Errorf("valid SRI %q rejected: %v", okSRI, err)
		}
	}
	for _, badSRI := range []string{"md5-dGVzdA==", "sha256-not valid!", "sha384-", "plainstring"} {
		if err := ValidateSRIHash(badSRI); err == nil {
			t.Errorf("invalid SRI %q should be rejected", badSRI)
		}
	}

	// INLINE_HASH 派生来源与站内脚本派生来源
	if got := ExtractScriptOrigin("/static/app.js", ScriptTypeExternal); got != "'self'" {
		t.Errorf("relative external origin = %q, want 'self'", got)
	}
	if got := ExtractScriptOrigin("sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=", ScriptTypeInlineHash); got != "inline" {
		t.Errorf("inline origin = %q, want inline", got)
	}
}

func TestToGuardPolicyFrozenContract(t *testing.T) {
	appID := uuid.MustParse("8b1a2c3d-0000-4000-8000-000000000011")
	p := DefaultPolicy(appID)
	p.Mode = ModeProtect
	p.Version = 3
	p.CSPMode = CSPModeEnforce
	p.SensitivePaths = []string{"/login", "/checkout"}
	p.ProbeEnabled = true
	p.StripUnauthorizedScripts = true
	p.AllowedScriptOrigins = []string{"'self'", "https://cdn.example.com"}
	p.AllowedConnectOrigins = []string{"'self'"}
	p.AllowedFormOrigins = []string{"'self'"}
	p.CustomCSPDirectives = "object-src 'none'"

	scripts := []Script{
		{ScriptURL: "https://cdn.example.com/pay.js", ScriptType: ScriptTypeExternal, SRIHash: "sha384-dGVzdA==", Status: ScriptStatusAuthorized},
		{ScriptURL: "https://evil.example/skim.js", ScriptType: ScriptTypeExternal, Status: ScriptStatusBlocked},
		{ScriptURL: "https://pending.example/new.js", ScriptType: ScriptTypeExternal, Status: ScriptStatusDiscovered},
	}

	gp := toGuardPolicy(p, scripts)
	if len(gp.AuthorizedScripts) != 2 {
		t.Fatalf("expected only AUTHORIZED and BLOCKED (2 items), got %d: %+v", len(gp.AuthorizedScripts), gp.AuthorizedScripts)
	}
	raw, err := json.Marshal(gp)
	if err != nil {
		t.Fatalf("marshal guard policy: %v", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal guard policy: %v", err)
	}
	wantKeys := []string{
		"schema_version", "application_id", "mode", "version", "csp_mode",
		"sensitive_paths", "probe_enabled", "strip_unauthorized_scripts",
		"allowed_script_origins", "allowed_connect_origins", "allowed_form_origins",
		"custom_csp_directives", "authorized_scripts",
	}
	if len(obj) != len(wantKeys) {
		t.Fatalf("frozen contract expects exactly %d keys, got %d: %s", len(wantKeys), len(obj), raw)
	}
	for _, k := range wantKeys {
		if _, ok := obj[k]; !ok {
			t.Errorf("frozen guard JSON missing key %q: %s", k, raw)
		}
	}
}

type execCall struct {
	sql  string
	args []any
}

type fakeExecer struct {
	calls []execCall
}

func (f *fakeExecer) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, execCall{sql: sql, args: args})
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func TestIngestEventSQLAndNeverOverwritesAuthorized(t *testing.T) {
	// 静态断言：upsertObservedScriptSQL 的 ON CONFLICT DO UPDATE 子句绝不覆盖 status / sri_hash / justification / approved_by / approved_at
	conflictPart := upsertObservedScriptSQL[strings.Index(upsertObservedScriptSQL, "DO UPDATE SET"):]
	for _, forbidden := range []string{"status", "sri_hash", "justification", "approved_by", "approved_at"} {
		// 注意 observed_sri 包含 sri 字样，精准检查赋值列名
		if strings.Contains(conflictPart, "\t"+forbidden+" ") || strings.Contains(conflictPart, " "+forbidden+"=") || strings.Contains(conflictPart, " "+forbidden+" =") {
			t.Fatalf("upsertObservedScriptSQL must NEVER overwrite %q on conflict:\n%s", forbidden, conflictPart)
		}
	}

	appID := uuid.New()
	ts := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)

	// 1. CLIENT_SIDE_SCRIPT_OBSERVED -> 单次 UPSERT client_script_inventory
	fe := &fakeExecer{}
	store := &Store{exec: fe}
	err := store.IngestEvent(context.Background(), &accesscontrolevents.Event{
		OccurredAt:    ts,
		ApplicationID: &appID,
		RequestPath:   "/checkout",
		EventType:     accesscontrolevents.EventTypeClientSideScriptObserved,
		Details: map[string]interface{}{
			"client_side": map[string]interface{}{
				"script_url":   "https://cdn.example.com/pay.js",
				"script_type":  "EXTERNAL",
				"observed_sri": "sha384-dGVzdA==",
				"page_path":    "/checkout",
			},
		},
	})
	if err != nil {
		t.Fatalf("IngestEvent observed: %v", err)
	}
	if len(fe.calls) != 1 || !strings.Contains(fe.calls[0].sql, "INSERT INTO client_script_inventory") {
		t.Fatalf("expected 1 script inventory upsert, got %d calls", len(fe.calls))
	}

	// 2. CLIENT_SIDE_UNAUTHORIZED_SCRIPT -> INSERT client_side_violations + UPSERT DISCOVERED 到 client_script_inventory
	fe2 := &fakeExecer{}
	store2 := &Store{exec: fe2}
	err = store2.IngestEvent(context.Background(), &accesscontrolevents.Event{
		RequestID:     "req-unauth-1",
		OccurredAt:    ts,
		ApplicationID: &appID,
		ClientIP:      "203.0.113.10",
		EventType:     accesscontrolevents.EventTypeClientSideUnauthorizedScript,
		Action:        "STRIPPED",
		Details: map[string]interface{}{
			"client_side": map[string]interface{}{
				"violation_type": "UNAUTHORIZED_SCRIPT",
				"script_url":     "https://evil.example/skim.js",
				"script_type":    "EXTERNAL",
				"page_path":      "/checkout",
				"action_taken":   "STRIPPED",
				"reason":         "unauthorized_external_script",
			},
		},
	})
	if err != nil {
		t.Fatalf("IngestEvent unauthorized: %v", err)
	}
	if len(fe2.calls) != 2 {
		t.Fatalf("expected 2 SQL calls (violation insert + script upsert), got %d", len(fe2.calls))
	}
	if !strings.Contains(fe2.calls[0].sql, "INSERT INTO client_side_violations") {
		t.Fatalf("first call must insert violation, got: %s", fe2.calls[0].sql)
	}
	if fe2.calls[0].args[3] != ViolationUnauthorizedScript {
		t.Fatalf("violation_type = %v, want %s", fe2.calls[0].args[3], ViolationUnauthorizedScript)
	}
	if !strings.Contains(fe2.calls[1].sql, "INSERT INTO client_script_inventory") {
		t.Fatalf("second call must upsert script inventory, got: %s", fe2.calls[1].sql)
	}

	// 3. CSP_VIOLATION / SCRIPT_TAMPERED / PROBE_ALERT -> 仅 INSERT client_side_violations
	for _, tc := range []struct {
		evType string
		vType  string
	}{
		{accesscontrolevents.EventTypeClientSideScriptTampered, ViolationScriptTampered},
		{accesscontrolevents.EventTypeClientSideCSPViolation, ViolationCSPViolation},
		{accesscontrolevents.EventTypeClientSideProbeAlert, ViolationProbeAlert},
	} {
		feN := &fakeExecer{}
		sN := &Store{exec: feN}
		if err := sN.IngestEvent(context.Background(), &accesscontrolevents.Event{
			RequestID:     "req-1",
			OccurredAt:    ts,
			ApplicationID: &appID,
			EventType:     tc.evType,
			Details: map[string]interface{}{
				"client_side": map[string]interface{}{
					"blocked_uri":        "https://evil.example/exfil",
					"violated_directive": "connect-src",
					"action_taken":       "REPORTED",
				},
			},
		}); err != nil {
			t.Fatalf("%s: %v", tc.evType, err)
		}
		if len(feN.calls) != 1 || feN.calls[0].args[3] != tc.vType {
			t.Fatalf("%s: expected 1 violation insert with type %s, got calls=%d args=%v", tc.evType, tc.vType, len(feN.calls), feN.calls[0].args)
		}
	}

	// 4. 缺失 ApplicationID 安全跳过
	feNil := &fakeExecer{}
	if err := (&Store{exec: feNil}).IngestEvent(context.Background(), &accesscontrolevents.Event{
		EventType: accesscontrolevents.EventTypeClientSideScriptObserved,
	}); err != nil || len(feNil.calls) != 0 {
		t.Fatalf("nil application_id should skip safely: calls=%d err=%v", len(feNil.calls), err)
	}
}

func TestRenderComplianceCSVAndFormulaEscaping(t *testing.T) {
	ts := time.Date(2026, 11, 26, 9, 0, 0, 0, time.UTC)
	scripts := []Script{
		{
			ApplicationCode: "shop",
			ApplicationName: "在线商城",
			ScriptURL:       "https://cdn.example.com/pay.js",
			ScriptOrigin:    "https://cdn.example.com",
			ScriptType:      ScriptTypeExternal,
			Status:          ScriptStatusAuthorized,
			SRIHash:         "sha384-dGVzdA==",
			ObservedSRI:     "sha384-dGVzdA==",
			Justification:   "=CMD|' /C calc'!A0",
			ApprovedBy:      "secadmin",
			ApprovedAt:      &ts,
			SamplePagePath:  "/checkout",
			FirstSeenAt:     ts,
			LastSeenAt:      ts,
			ObservedCount:   42,
		},
		{
			ApplicationCode: "shop",
			ApplicationName: "在线商城",
			ScriptURL:       "https://cdn.example.com/tampered.js",
			ScriptType:      ScriptTypeExternal,
			Status:          ScriptStatusAuthorized,
			SRIHash:         "sha384-AAAA",
			ObservedSRI:     "sha384-BBBB",
			Justification:   "+2+3,含逗号",
			FirstSeenAt:     ts,
			LastSeenAt:      ts,
		},
	}
	violations := []Violation{
		{
			OccurredAt:        ts,
			ApplicationCode:   "shop",
			ApplicationName:   "在线商城",
			RequestID:         "req-v1",
			ViolationType:     ViolationScriptTampered,
			PagePath:          "/checkout",
			ScriptURL:         "https://cdn.example.com/tampered.js",
			ExpectedSRI:       "sha384-AAAA",
			ObservedSRI:       "sha384-BBBB",
			ActionTaken:       "STRIPPED",
			Reason:            "@SUM(A1:A2)",
			ClientIP:          "198.51.100.7",
			Status:            ViolationStatusOpen,
			Note:              "\t-inject",
		},
	}
	summary := ViolationSummary{Total: 1, Open: 1, ScriptTampered: 1}

	out := RenderComplianceCSV(scripts, violations, summary)
	if !strings.HasPrefix(out, csvUTF8BOM) {
		t.Fatal("CSV export missing UTF-8 BOM")
	}
	for _, want := range []string{
		"PCI DSS 4.0 6.4.3 脚本授权台账",
		"PCI DSS 4.0 11.6.1 违规摘要",
		"业务必要性说明(6.4.3)",
		",一致,",
		",不匹配,",
		"'=CMD|' /C calc'!A0",
		`"'+2+3,含逗号"`,
		"'@SUM(A1:A2)",
		"'\t-inject",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("CSV missing %q:\n%s", want, out)
		}
	}
}

// ---------- HTTP Handler 全端点单测 ----------

type fakeAppGetter struct {
	apps map[uuid.UUID]*applications.Application
}

func (f fakeAppGetter) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	if a, ok := f.apps[id]; ok {
		return a, nil
	}
	return nil, applications.ErrNotFound
}

type memRepo struct {
	policies   map[uuid.UUID]*Policy
	published  map[string]int
	scripts    map[uuid.UUID]*Script
	violations map[uuid.UUID]*Violation
}

func newMemRepo() *memRepo {
	return &memRepo{
		policies:   map[uuid.UUID]*Policy{},
		published:  map[string]int{},
		scripts:    map[uuid.UUID]*Script{},
		violations: map[uuid.UUID]*Violation{},
	}
}

func (m *memRepo) GetPolicyByApp(_ context.Context, appID uuid.UUID) (*Policy, error) {
	p, ok := m.policies[appID]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *memRepo) SavePolicyDraft(_ context.Context, p *Policy, expectedVersion int, _, updatedBy string) error {
	cur := m.policies[p.ApplicationID]
	if cur == nil && expectedVersion != 0 {
		return ErrConflict
	}
	if cur != nil && cur.Version != expectedVersion {
		return ErrConflict
	}
	cp := *p
	if cp.ID == uuid.Nil {
		cp.ID = uuid.New()
	}
	cp.Version = expectedVersion + 1
	cp.UpdatedBy = updatedBy
	m.policies[p.ApplicationID] = &cp
	p.ID = cp.ID
	p.Version = cp.Version
	return nil
}

func (m *memRepo) PublishedVersion(_ context.Context, appCode string) (int, error) {
	return m.published[appCode], nil
}

func (m *memRepo) ListScripts(_ context.Context, f ScriptFilter) ([]Script, int64, error) {
	out := []Script{}
	for _, s := range m.scripts {
		if f.ApplicationID != nil && s.ApplicationID != *f.ApplicationID {
			continue
		}
		if f.Status != "" && s.Status != f.Status {
			continue
		}
		if f.Keyword != "" && !strings.Contains(s.ScriptURL, f.Keyword) {
			continue
		}
		out = append(out, *s)
	}
	return out, int64(len(out)), nil
}

func (m *memRepo) GetScript(_ context.Context, id uuid.UUID) (*Script, error) {
	s, ok := m.scripts[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *memRepo) CreateScript(_ context.Context, s *Script) error {
	for _, existing := range m.scripts {
		if existing.ApplicationID == s.ApplicationID && existing.ScriptURL == s.ScriptURL && existing.ScriptType == s.ScriptType {
			return ErrConflict
		}
	}
	s.ID = uuid.New()
	now := time.Now().UTC()
	s.FirstSeenAt = now
	s.LastSeenAt = now
	s.CreatedAt = now
	s.UpdatedAt = now
	cp := *s
	m.scripts[s.ID] = &cp
	return nil
}

func (m *memRepo) UpdateScript(_ context.Context, id uuid.UUID, sriHash, status, justification, approvedBy string, approvedAt *time.Time) (*Script, error) {
	s, ok := m.scripts[id]
	if !ok {
		return nil, ErrNotFound
	}
	s.SRIHash = sriHash
	s.Status = status
	s.Justification = justification
	s.ApprovedBy = approvedBy
	s.ApprovedAt = approvedAt
	cp := *s
	return &cp, nil
}

func (m *memRepo) DeleteScript(_ context.Context, id uuid.UUID) error {
	if _, ok := m.scripts[id]; !ok {
		return ErrNotFound
	}
	delete(m.scripts, id)
	return nil
}

func (m *memRepo) ListViolations(_ context.Context, f ViolationFilter) ([]Violation, int64, error) {
	out := []Violation{}
	for _, v := range m.violations {
		if f.ApplicationID != nil && v.ApplicationID != *f.ApplicationID {
			continue
		}
		if f.ViolationType != "" && v.ViolationType != f.ViolationType {
			continue
		}
		if f.Status != "" && v.Status != f.Status {
			continue
		}
		out = append(out, *v)
	}
	return out, int64(len(out)), nil
}

func (m *memRepo) GetViolation(_ context.Context, id uuid.UUID) (*Violation, error) {
	v, ok := m.violations[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *v
	return &cp, nil
}

func (m *memRepo) UpdateViolationStatus(_ context.Context, id uuid.UUID, status, note, handledBy string, handledAt time.Time) (*Violation, error) {
	v, ok := m.violations[id]
	if !ok {
		return nil, ErrNotFound
	}
	v.Status = status
	v.Note = note
	v.HandledBy = handledBy
	v.HandledAt = &handledAt
	cp := *v
	return &cp, nil
}

func (m *memRepo) ExportComplianceData(_ context.Context, appID *uuid.UUID) ([]Script, []Violation, ViolationSummary, error) {
	scripts, _, _ := m.ListScripts(context.Background(), ScriptFilter{ApplicationID: appID})
	violations, _, _ := m.ListViolations(context.Background(), ViolationFilter{ApplicationID: appID})
	return scripts, violations, ViolationSummary{Total: int64(len(violations))}, nil
}

func withSecPrincipal(req *http.Request) *http.Request {
	ctx := authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "secadmin",
	})
	return req.WithContext(ctx)
}

func TestHandlerAllEndpoints(t *testing.T) {
	appID := uuid.New()
	repo := newMemRepo()
	apps := fakeAppGetter{apps: map[uuid.UUID]*applications.Application{
		appID: {ID: appID, Code: "shop", Name: "Shop"},
	}}
	h := NewHandler(repo, apps, nil)

	// 1. GET default OFF policy
	req := httptest.NewRequest(http.MethodGet, "/api/v1/applications/"+appID.String()+"/client-side-policy", nil)
	req.SetPathValue("id", appID.String())
	w := httptest.NewRecorder()
	h.GetPolicy(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET policy = %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"state":"NOT_CONFIGURED"`) || !strings.Contains(w.Body.String(), `"mode":"OFF"`) {
		t.Fatalf("unexpected default policy response: %s", w.Body.String())
	}

	// 2. PUT policy draft (v0 -> v1) & 409 conflict on stale expected_version=0
	putBody := `{"mode":"PROTECT","expected_version":0,"csp_mode":"ENFORCE","sensitive_paths":["/checkout"],"probe_enabled":true,"strip_unauthorized_scripts":true,"allowed_script_origins":["'self'","https://cdn.example.com"],"allowed_connect_origins":["'self'"],"allowed_form_origins":["'self'"],"custom_csp_directives":"object-src 'none'","reason":"启用支付页防篡改"}`
	req = withSecPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/applications/"+appID.String()+"/client-side-policy", bytes.NewBufferString(putBody)))
	req.SetPathValue("id", appID.String())
	w = httptest.NewRecorder()
	h.PutPolicy(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"version":1`) {
		t.Fatalf("PUT policy = %d: %s", w.Code, w.Body.String())
	}

	// 乐观锁冲突 -> 409
	req = withSecPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/applications/"+appID.String()+"/client-side-policy", bytes.NewBufferString(putBody)))
	req.SetPathValue("id", appID.String())
	w = httptest.NewRecorder()
	h.PutPolicy(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("stale expected_version must return 409, got %d: %s", w.Code, w.Body.String())
	}

	// 3. POST script: AUTHORIZED without justification -> 400 (PCI DSS 4.0 6.4.3)
	badScript := `{"application_id":"` + appID.String() + `","script_url":"https://cdn.example.com/pay.js","script_type":"EXTERNAL","status":"AUTHORIZED","justification":""}`
	req = withSecPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/client-side/scripts", bytes.NewBufferString(badScript)))
	w = httptest.NewRecorder()
	h.CreateScript(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "6.4.3") {
		t.Fatalf("AUTHORIZED without justification must return 400, got %d: %s", w.Code, w.Body.String())
	}

	// POST script valid -> 201
	goodScript := `{"application_id":"` + appID.String() + `","script_url":"https://cdn.example.com/pay.js","script_type":"EXTERNAL","sri_hash":"sha384-dGVzdA==","status":"AUTHORIZED","justification":"支付网关必需脚本"}`
	req = withSecPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/client-side/scripts", bytes.NewBufferString(goodScript)))
	w = httptest.NewRecorder()
	h.CreateScript(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST script = %d: %s", w.Code, w.Body.String())
	}
	var createResp struct {
		Data struct {
			Script Script `json:"script"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &createResp); err != nil {
		t.Fatal(err)
	}
	scriptID := createResp.Data.Script.ID
	if createResp.Data.Script.ApprovedBy != "secadmin" || createResp.Data.Script.ApprovedAt == nil {
		t.Fatalf("expected approved_by/approved_at recorded, got %+v", createResp.Data.Script)
	}

	// 4. PUT script -> 400 if AUTHORIZED with empty justification, 200 if BLOCKED
	req = withSecPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/client-side/scripts/"+scriptID.String(), bytes.NewBufferString(`{"status":"AUTHORIZED","justification":""}`)))
	req.SetPathValue("id", scriptID.String())
	w = httptest.NewRecorder()
	h.UpdateScript(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("PUT script AUTHORIZED without justification must return 400, got %d", w.Code)
	}

	req = withSecPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/client-side/scripts/"+scriptID.String(), bytes.NewBufferString(`{"sri_hash":"sha384-dGVzdA==","status":"BLOCKED","justification":"发现供应链风险"}`)))
	req.SetPathValue("id", scriptID.String())
	w = httptest.NewRecorder()
	h.UpdateScript(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"BLOCKED"`) {
		t.Fatalf("PUT script BLOCKED = %d: %s", w.Code, w.Body.String())
	}

	// 5. GET scripts
	req = httptest.NewRequest(http.MethodGet, "/api/v1/client-side/scripts?application_id="+appID.String()+"&status=BLOCKED", nil)
	w = httptest.NewRecorder()
	h.ListScripts(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("GET scripts = %d: %s", w.Code, w.Body.String())
	}

	// 6. Violation list & status update
	vID := uuid.New()
	repo.violations[vID] = &Violation{
		ID:            vID,
		ApplicationID: appID,
		OccurredAt:    time.Now().UTC(),
		ViolationType: ViolationCSPViolation,
		BlockedURI:    "https://evil.example/a.js",
		Status:        ViolationStatusOpen,
	}
	req = httptest.NewRequest(http.MethodGet, "/api/v1/client-side/violations?violation_type=CSP_VIOLATION", nil)
	w = httptest.NewRecorder()
	h.ListViolations(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("GET violations = %d: %s", w.Code, w.Body.String())
	}

	req = withSecPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/client-side/violations/"+vID.String()+"/status", bytes.NewBufferString(`{"status":"RESOLVED","note":"已下架第三方插件"}`)))
	req.SetPathValue("id", vID.String())
	w = httptest.NewRecorder()
	h.UpdateViolationStatus(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"status":"RESOLVED"`) || !strings.Contains(w.Body.String(), `"handled_by":"secadmin"`) {
		t.Fatalf("PUT violation status = %d: %s", w.Code, w.Body.String())
	}

	// 7. GET compliance-export CSV
	req = withSecPrincipal(httptest.NewRequest(http.MethodGet, "/api/v1/client-side/compliance-export?application_id="+appID.String(), nil))
	w = httptest.NewRecorder()
	h.ExportCompliance(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET compliance-export = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "text/csv; charset=utf-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if !strings.HasPrefix(w.Body.String(), csvUTF8BOM) {
		t.Fatal("exported CSV missing UTF-8 BOM")
	}

	// 8. DELETE script
	req = withSecPrincipal(httptest.NewRequest(http.MethodDelete, "/api/v1/client-side/scripts/"+scriptID.String(), nil))
	req.SetPathValue("id", scriptID.String())
	w = httptest.NewRecorder()
	h.DeleteScript(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"deleted":true`) {
		t.Fatalf("DELETE script = %d: %s", w.Code, w.Body.String())
	}
}
