package blockpages

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
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/authz"
)

func TestSanitizeHTMLSecurityAndStyling(t *testing.T) {
	in := `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="0;url=https://evil.example">
  <title>拦截页</title>
  <style>
    @import url("https://evil.example/a.css");
    body { background: #1b2431; color: #fff; }
    .evil { width: exp/*x*/ression(alert(1)); background-image: url(https://evil.example/t.png); }
    .grad { fill: url(#shieldGrad); }
  </style>
  <script>alert('xss')</script>
</head>
<body onload="evil()">
  <div class="card" style="padding:24px; behavior:url(x.htc);">
    <svg viewBox="0 0 24 24" width="32" height="32" xmlns="http://www.w3.org/2000/svg">
      <defs><linearGradient id="shieldGrad"><stop offset="0%" stop-color="#f00"/></linearGradient></defs>
      <path d="M12 2L4 5v6c0 5 3.4 9.7 8 11 4.6-1.3 8-6 8-11V5l-8-3z" fill="url(#shieldGrad)"/>
      <animate attributeName="x" from="0" to="10"/>
    </svg>
    <h1 onclick="alert(1)">请求已被拦截</h1>
    <p>请求编号：{{request_id}}</p>
    <a href="javascript:alert(1)">危险链接</a>
    <a href="https://help.example.com" target="_blank">帮助中心</a>
    <img src="data:image/svg+xml;base64,PHN2Zz4=" alt="bad"/>
    <img src="https://cdn.example.com/logo.png" alt="Logo" width="120"/>
    <iframe src="https://evil.example"></iframe>
    <form action="https://evil.example"><input name="pw"/></form>
  </div>
</body>
</html>`

	res := SanitizeHTML(in)
	for _, banned := range []string{
		"<script", "alert('xss')", "alert(1)", "onload=", "onclick=",
		"http-equiv", "evil.example/a.css", "evil.example/t.png",
		"expression(", "behavior:", "javascript:", "<iframe", "<form", "<input",
		"data:image/svg+xml", "<animate",
	} {
		if strings.Contains(strings.ToLower(res.HTML), strings.ToLower(banned)) {
			t.Fatalf("sanitized HTML still contains dangerous fragment %q:\n%s", banned, res.HTML)
		}
	}
	for _, want := range []string{
		"<!DOCTYPE html>",
		`<meta charset="UTF-8">`,
		`<meta name="viewport" content="width=device-width, initial-scale=1.0">`,
		`<style>`,
		`background: #1b2431`,
		`url(#shieldGrad)`,
		`class="card"`,
		`viewBox="0 0 24 24"`,
		`<linearGradient id="shieldGrad">`,
		`{{request_id}}`,
		`href="https://help.example.com"`,
		`rel="noopener noreferrer"`,
		`src="https://cdn.example.com/logo.png"`,
	} {
		if !strings.Contains(res.HTML, want) {
			t.Fatalf("sanitized HTML missing expected safe fragment %q:\n%s", want, res.HTML)
		}
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected sanitizer warnings for stripped elements/attributes")
	}
}

func TestSanitizeHTMLAdversarialMXSSCSSEscapesAndVoidTags(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		banned []string
		want   []string
	}{
		{
			name:   "nested_closing_style_reassembly_escape",
			in:     `<style></sty</stylele><script>alert(1)</script></style><p>SAFE</p>`,
			banned: []string{"</style><script", "<script", "alert(1)"},
			want:   []string{"<p>SAFE</p>"},
		},
		{
			name:   "comment_assisted_closing_style_escape",
			in:     `<style></sty<//**/stylele><script>alert(1)</script></style><p>SAFE2</p>`,
			banned: []string{"</style><script", "<script", "alert(1)"},
			want:   []string{"<p>SAFE2</p>"},
		},
		{
			name:   "svg_style_mxss_anchor_attr",
			in:     `<svg viewBox="0 0 10 10"><style><a id="</style><img src=x onerror=alert(1)>"></a></style><rect width="10" height="10"/></svg><p>AFTER_SVG</p>`,
			banned: []string{"<style", "<img", "onerror", "alert(1)"},
			want:   []string{"<svg", "<rect", "<p>AFTER_SVG</p>"},
		},
		{
			name:   "svg_style_mxss_foreign_breakout_img",
			in:     `<svg viewBox="0 0 10 10"><style><img src=x onerror=alert(1)></style><rect width="10" height="10"/></svg><p>AFTER_SVG</p>`,
			banned: []string{"<style", "src=", "onerror", "alert(1)"},
			want:   []string{"<svg", "<p>AFTER_SVG</p>"},
		},
		{
			name:   "svg_desc_html_integration_point",
			in:     `<svg viewBox="0 0 10 10"><desc><img src=x onerror=alert(1)><script>alert(2)</script></desc><rect width="10" height="10"/></svg>`,
			banned: []string{"<img", "<script", "onerror", "alert("},
			want:   []string{"<svg", "<rect"},
		},
		{
			name:   "svg_style_mxss_script",
			in:     `<svg><style><script>alert(1)</script></style></svg><p>OK</p>`,
			banned: []string{"<style", "<script", "alert(1)"},
			want:   []string{"<p>OK</p>"},
		},
		{
			name:   "css_hex_escapes_and_image_set",
			in:     `<style>@\69mport "https://evil.example/a.css"; body{background:u\72l(https://evil.example/x.png);background-image:image-set("https://evil.example/y.png" 1x);color:#222;}</style><p>CSS</p>`,
			banned: []string{"@import", "evil.example", "image-set"},
			want:   []string{"color:#222", "<p>CSS</p>"},
		},
		{
			name:   "void_dropped_tags_do_not_swallow_following_content",
			in:     `<div class="a"><link rel="stylesheet" href="x"><input name="y"><base href="https://evil.example"><embed src="z"><p>KEEP_ME</p></div>`,
			banned: []string{"<link", "<input", "<base", "<embed"},
			want:   []string{`<div class="a">`, `<p>KEEP_ME</p>`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := SanitizeHTML(tc.in)
			low := strings.ToLower(res.HTML)
			for _, b := range tc.banned {
				if strings.Contains(low, strings.ToLower(b)) {
					t.Fatalf("case %s: banned %q survived:\n%s", tc.name, b, res.HTML)
				}
			}
			for _, w := range tc.want {
				if !strings.Contains(res.HTML, w) {
					t.Fatalf("case %s: expected %q missing:\n%s", tc.name, w, res.HTML)
				}
			}
		})
	}
}

func TestRenderVisualHTMLAllThemesAndEscaping(t *testing.T) {
	vc := DefaultVisualConfig()
	vc.Title = `阻止 <script>alert(1)</script>`
	vc.BrandName = `聚信得仁 & 安全`
	vc.PrimaryColor = "#2563eb"
	vc.ShowRetryAfter = true
	vc.LogoURL = "https://cdn.example.com/brand.png"

	for _, theme := range BuiltinThemes() {
		html := RenderVisualHTML(theme.Key, vc)
		if strings.Contains(html, "<script>") {
			t.Fatalf("theme %s did not escape script tag in title", theme.Key)
		}
		if !strings.Contains(html, "&lt;script&gt;alert(1)&lt;/script&gt;") {
			t.Fatalf("theme %s missing escaped title", theme.Key)
		}
		if !strings.Contains(html, "{{request_id}}") || !strings.Contains(html, "{{retry_after}}") {
			t.Fatalf("theme %s missing expected placeholders", theme.Key)
		}
		if !strings.Contains(html, "#2563eb") {
			t.Fatalf("theme %s missing primary color override", theme.Key)
		}
	}
}

func TestSubstitutePlaceholdersEscapesRuntimeValues(t *testing.T) {
	tmpl := `<p>{{request_id}} | {{domain}} | {{path}} | {{client_ip}} | {{status_code}} | {{scene_label}}</p>`
	out := SubstitutePlaceholders(tmpl, PlaceholderValues{
		RequestID:  "req-1",
		Domain:     `evil"><script>alert(1)</script>`,
		Path:       "/" + strings.Repeat("a", 300),
		ClientIP:   "198.51.100.1",
		StatusCode: "403",
		SceneLabel: "WAF 安全拦截",
	})
	if strings.Contains(out, "<script>") {
		t.Fatalf("runtime placeholder value not escaped: %s", out)
	}
	if !strings.Contains(out, "&lt;script&gt;") || !strings.Contains(out, "...") {
		t.Fatalf("expected escaped domain and truncated path: %s", out)
	}
}

func TestCompileAndValidateErrors(t *testing.T) {
	_, errs := CompileAndValidate(CompileInput{
		CheckName:  true,
		Name:       "",
		EditorMode: "UNKNOWN",
		StatusCode: 200,
		JSONCode:   "bad code!",
	})
	if len(errs) < 4 {
		t.Fatalf("expected >=4 validation errors, got %+v", errs)
	}

	_, errs = CompileAndValidate(CompileInput{
		CheckName:   true,
		Name:        "oversize",
		EditorMode:  EditorModeHTML,
		HTMLContent: strings.Repeat("a", MaxHTMLBytes+1),
	})
	if len(errs) == 0 {
		t.Fatalf("expected error for oversized HTML")
	}
}

// ---------- HTTP Handler 内存桩单测 ----------

type memRepo struct {
	pages    map[uuid.UUID]*BlockPage
	versions map[uuid.UUID][]BlockPageVersion
	bindings map[uuid.UUID]*BlockPageBinding
}

func newMemRepo() *memRepo {
	return &memRepo{
		pages:    map[uuid.UUID]*BlockPage{},
		versions: map[uuid.UUID][]BlockPageVersion{},
		bindings: map[uuid.UUID]*BlockPageBinding{},
	}
}

func (m *memRepo) List(_ context.Context, _ ListFilter) ([]BlockPage, int, error) {
	out := make([]BlockPage, 0, len(m.pages))
	for _, p := range m.pages {
		cp := *p
		out = append(out, cp)
	}
	return out, len(out), nil
}

func (m *memRepo) GetByID(_ context.Context, id uuid.UUID) (*BlockPage, error) {
	p, ok := m.pages[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *p
	return &cp, nil
}

func (m *memRepo) ListVersions(_ context.Context, pageID uuid.UUID) ([]BlockPageVersion, error) {
	vs := m.versions[pageID]
	out := make([]BlockPageVersion, len(vs))
	for i := range vs {
		out[i] = vs[len(vs)-1-i]
	}
	return out, nil
}

func (m *memRepo) GetVersion(_ context.Context, pageID uuid.UUID, version int) (*BlockPageVersion, error) {
	for _, v := range m.versions[pageID] {
		if v.Version == version {
			cp := v
			return &cp, nil
		}
	}
	return nil, ErrVersionNotFound
}

func (m *memRepo) Create(_ context.Context, in CreateInput) (*BlockPage, *BlockPageVersion, error) {
	for _, p := range m.pages {
		if p.Name == in.Name {
			return nil, nil, ErrDuplicateName
		}
	}
	now := time.Now().UTC()
	p := &BlockPage{
		ID: uuid.New(), Name: in.Name, Description: in.Description,
		EditorMode: in.EditorMode, Theme: in.Theme, VisualConfig: in.VisualConfig,
		HTMLContent: in.HTMLContent, RenderedHTML: in.RenderedHTML,
		StatusCode: in.StatusCode, JSONCode: in.JSONCode, JSONMessage: in.JSONMessage,
		Version: 1, CreatedBy: in.CreatedBy, UpdatedBy: in.CreatedBy,
		CreatedAt: now, UpdatedAt: now,
	}
	v := BlockPageVersion{
		ID: uuid.New(), BlockPageID: p.ID, Version: 1,
		EditorMode: p.EditorMode, Theme: p.Theme, VisualConfig: p.VisualConfig,
		HTMLContent: p.HTMLContent, RenderedHTML: p.RenderedHTML,
		StatusCode: p.StatusCode, JSONCode: p.JSONCode, JSONMessage: p.JSONMessage,
		ChangeNote: in.ChangeNote, CreatedBy: in.CreatedBy, CreatedAt: now,
	}
	m.pages[p.ID] = p
	m.versions[p.ID] = []BlockPageVersion{v}
	cp := *p
	return &cp, &v, nil
}

func (m *memRepo) Update(_ context.Context, in UpdateInput) (*BlockPage, *BlockPageVersion, error) {
	p, ok := m.pages[in.ID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if p.Version != in.ExpectedVersion {
		return nil, nil, ErrConflict
	}
	p.Name = in.Name
	p.Description = in.Description
	p.EditorMode = in.EditorMode
	p.Theme = in.Theme
	p.VisualConfig = in.VisualConfig
	p.HTMLContent = in.HTMLContent
	p.RenderedHTML = in.RenderedHTML
	p.StatusCode = in.StatusCode
	p.JSONCode = in.JSONCode
	p.JSONMessage = in.JSONMessage
	p.Version++
	p.UpdatedBy = in.UpdatedBy
	p.UpdatedAt = time.Now().UTC()
	v := BlockPageVersion{
		ID: uuid.New(), BlockPageID: p.ID, Version: p.Version,
		EditorMode: p.EditorMode, Theme: p.Theme, VisualConfig: p.VisualConfig,
		HTMLContent: p.HTMLContent, RenderedHTML: p.RenderedHTML,
		StatusCode: p.StatusCode, JSONCode: p.JSONCode, JSONMessage: p.JSONMessage,
		ChangeNote: in.ChangeNote, CreatedBy: in.UpdatedBy, CreatedAt: p.UpdatedAt,
	}
	m.versions[p.ID] = append(m.versions[p.ID], v)
	cp := *p
	return &cp, &v, nil
}

func (m *memRepo) Rollback(_ context.Context, in RollbackInput) (*BlockPage, *BlockPageVersion, error) {
	p, ok := m.pages[in.ID]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if p.Version != in.ExpectedVersion {
		return nil, nil, ErrConflict
	}
	target, err := m.GetVersion(context.Background(), in.ID, in.TargetVersion)
	if err != nil {
		return nil, nil, err
	}
	p.EditorMode = target.EditorMode
	p.Theme = target.Theme
	p.VisualConfig = target.VisualConfig
	p.HTMLContent = target.HTMLContent
	p.RenderedHTML = target.RenderedHTML
	p.StatusCode = target.StatusCode
	p.JSONCode = target.JSONCode
	p.JSONMessage = target.JSONMessage
	p.Version++
	p.UpdatedBy = in.UpdatedBy
	p.UpdatedAt = time.Now().UTC()
	v := BlockPageVersion{
		ID: uuid.New(), BlockPageID: p.ID, Version: p.Version,
		EditorMode: p.EditorMode, Theme: p.Theme, VisualConfig: p.VisualConfig,
		HTMLContent: p.HTMLContent, RenderedHTML: p.RenderedHTML,
		StatusCode: p.StatusCode, JSONCode: p.JSONCode, JSONMessage: p.JSONMessage,
		ChangeNote: in.ChangeNote, CreatedBy: in.UpdatedBy, CreatedAt: p.UpdatedAt,
	}
	m.versions[p.ID] = append(m.versions[p.ID], v)
	cp := *p
	return &cp, &v, nil
}

func (m *memRepo) Delete(_ context.Context, id uuid.UUID) error {
	p, ok := m.pages[id]
	if !ok {
		return ErrNotFound
	}
	if p.IsBuiltin {
		return ErrBuiltinProtected
	}
	for _, b := range m.bindings {
		if b.BlockPageID == id {
			return ErrInUse
		}
	}
	delete(m.pages, id)
	delete(m.versions, id)
	return nil
}

func (m *memRepo) ListBindings(_ context.Context, _ BindingFilter) ([]BlockPageBinding, error) {
	out := make([]BlockPageBinding, 0, len(m.bindings))
	for _, b := range m.bindings {
		out = append(out, *b)
	}
	return out, nil
}

func (m *memRepo) ListBindingsByPage(_ context.Context, pageID uuid.UUID) ([]BlockPageBinding, error) {
	var out []BlockPageBinding
	for _, b := range m.bindings {
		if b.BlockPageID == pageID {
			out = append(out, *b)
		}
	}
	return out, nil
}

func (m *memRepo) GetBindingByID(_ context.Context, id uuid.UUID) (*BlockPageBinding, error) {
	b, ok := m.bindings[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *b
	return &cp, nil
}

func (m *memRepo) UpsertBinding(_ context.Context, in UpsertBindingInput) (*BlockPageBinding, error) {
	p, ok := m.pages[in.BlockPageID]
	if !ok {
		return nil, ErrNotFound
	}
	effVer := p.Version
	if in.PinnedVersion != nil {
		if _, err := m.GetVersion(context.Background(), in.BlockPageID, *in.PinnedVersion); err != nil {
			return nil, err
		}
		effVer = *in.PinnedVersion
	}
	for _, b := range m.bindings {
		sameApp := (b.ApplicationID == nil && in.ApplicationID == nil) ||
			(b.ApplicationID != nil && in.ApplicationID != nil && *b.ApplicationID == *in.ApplicationID)
		if sameApp && b.Scene == in.Scene {
			b.BlockPageID = in.BlockPageID
			b.BlockPageName = p.Name
			b.BlockPageLatestVersion = p.Version
			b.PinnedVersion = in.PinnedVersion
			b.EffectiveVersion = effVer
			b.Enabled = in.Enabled
			cp := *b
			return &cp, nil
		}
	}
	b := &BlockPageBinding{
		ID: uuid.New(), ApplicationID: in.ApplicationID, Scene: in.Scene,
		BlockPageID: in.BlockPageID, BlockPageName: p.Name,
		BlockPageLatestVersion: p.Version, PinnedVersion: in.PinnedVersion,
		EffectiveVersion: effVer, Enabled: in.Enabled, UpdatedBy: in.UpdatedBy,
	}
	m.bindings[b.ID] = b
	cp := *b
	return &cp, nil
}

func (m *memRepo) DeleteBinding(_ context.Context, id uuid.UUID) error {
	if _, ok := m.bindings[id]; !ok {
		return ErrNotFound
	}
	delete(m.bindings, id)
	return nil
}

type stubApps struct {
	existing uuid.UUID
}

func (s stubApps) GetByID(_ context.Context, id uuid.UUID) (*applications.Application, error) {
	if id == s.existing {
		return &applications.Application{ID: id, Code: "shop", Name: "电商站点"}, nil
	}
	return nil, applications.ErrNotFound
}

func withPrincipal(req *http.Request) *http.Request {
	return req.WithContext(authz.WithPrincipal(req.Context(), &authz.Principal{
		UserID:   uuid.New(),
		Username: "secadmin",
	}))
}

func TestHandlerLifecycleVersioningAndBindings(t *testing.T) {
	repo := newMemRepo()
	appID := uuid.New()
	h := NewHandler(repo, stubApps{existing: appID}, nil)

	// 1. Create HTML page v1 (with script to verify sanitization + warning)
	createBody := `{"name":"政企自定义页","editor_mode":"HTML","html_content":"<html><body><h1>拦截</h1><script>alert(1)</script><p>{{request_id}}</p></body></html>","status_code":403,"change_note":"初版"}`
	req := withPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/block-pages", strings.NewReader(createBody)))
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var createResp struct {
		Data struct {
			BlockPage BlockPage `json:"block_page"`
			Warnings  []string  `json:"warnings"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &createResp); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	pageID := createResp.Data.BlockPage.ID
	if createResp.Data.BlockPage.Version != 1 || strings.Contains(createResp.Data.BlockPage.RenderedHTML, "<script") {
		t.Fatalf("unexpected v1 page: %+v", createResp.Data.BlockPage)
	}
	if len(createResp.Data.Warnings) == 0 {
		t.Fatalf("expected warning for stripped script")
	}

	// 2. Update to v2 (VISUAL mode)
	updBody := `{"expected_version":1,"name":"政企自定义页","editor_mode":"VISUAL","theme":"enterprise_blue","visual_config":{"badge":"安全拦截","title":"第二版标题","description":"测试说明","show_request_id":true},"change_note":"切换可视化风格"}`
	req = withPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/block-pages/"+pageID.String(), strings.NewReader(updBody)))
	req.SetPathValue("id", pageID.String())
	rec = httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 2b. Stale expected_version -> 409 Conflict
	req = withPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/block-pages/"+pageID.String(), strings.NewReader(updBody)))
	req.SetPathValue("id", pageID.String())
	rec = httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 conflict on stale expected_version, got %d", rec.Code)
	}

	// 3. Rollback to v1 -> produces v3 (immutable trail)
	rbBody := `{"expected_version":2,"target_version":1,"change_note":"回退到初版"}`
	req = withPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/block-pages/"+pageID.String()+"/rollback", strings.NewReader(rbBody)))
	req.SetPathValue("id", pageID.String())
	rec = httptest.NewRecorder()
	h.Rollback(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := repo.pages[pageID].Version; got != 3 || repo.pages[pageID].EditorMode != EditorModeHTML {
		t.Fatalf("expected v3 HTML after rollback, got v%d mode=%s", got, repo.pages[pageID].EditorMode)
	}

	// 4. Bind to app + WAF scene pinned at v2
	bindPayload, _ := json.Marshal(map[string]interface{}{
		"application_id": appID.String(),
		"scene":          SceneWAF,
		"block_page_id":  pageID.String(),
		"pinned_version": 2,
		"enabled":        true,
	})
	req = withPrincipal(httptest.NewRequest(http.MethodPut, "/api/v1/block-pages/bindings", bytes.NewReader(bindPayload)))
	rec = httptest.NewRecorder()
	h.UpsertBinding(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("bind status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 5. Delete bound template -> 409 Conflict
	req = withPrincipal(httptest.NewRequest(http.MethodDelete, "/api/v1/block-pages/"+pageID.String(), nil))
	req.SetPathValue("id", pageID.String())
	rec = httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("expected 409 when deleting bound page, got %d", rec.Code)
	}

	// 6. Preview saved historical version v2
	prevPayload, _ := json.Marshal(map[string]interface{}{
		"block_page_id": pageID.String(),
		"version":       2,
		"scene":         SceneWAF,
	})
	req = withPrincipal(httptest.NewRequest(http.MethodPost, "/api/v1/block-pages/preview", bytes.NewReader(prevPayload)))
	rec = httptest.NewRecorder()
	h.Preview(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "第二版标题") {
		t.Fatalf("preview v2 failed: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
