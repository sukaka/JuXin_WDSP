// apimcp_test.go MCP 工具目录管理面单测（NG-MCP G1 批次 B1）：
// Validate* 词表矩阵、tool_hash/catalog_hash 确定性与变更重算、语义相等判定、
// CRUD+审核 HTTP 映射（200/400/404/409）、权限（api_spec.read/manage 零新增；
// jiuzhang_admin 形态越权全 403）、写操作 HIGH 审计、绑定变更触发发布（设计 §1.14）。
// fake 仓储承载 HTTP 映射；事务/唯一键/FK/审核态机语义由 PG 契约测试覆盖。
package apimcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
)

// ---------- Validate* 词表矩阵 ----------

func TestValidateCatalogInput(t *testing.T) {
	schema := map[string]any{"type": "object"}
	cases := []struct {
		name string
		in   CatalogInput
		want string
	}{
		{"合法全字段", CatalogInput{Name: "pay-mcp", ServiceIdentity: "mcp://pay.example.com", ProtocolVersion: "2025-11-25",
			Tools: []ToolInput{{ToolName: "refund", Description: "退款", InputSchema: &schema}}}, ""},
		{"空 tools 合法（空目录）", CatalogInput{Name: "pay-mcp", ServiceIdentity: "mcp://pay.example.com"}, ""},
		{"name 空", CatalogInput{ServiceIdentity: "mcp://pay.example.com"}, "name"},
		{"service_identity 空", CatalogInput{Name: "pay-mcp"}, "service_identity"},
		{"protocol_version 超长", CatalogInput{Name: "a", ServiceIdentity: "b", ProtocolVersion: strings.Repeat("1", 33)}, "protocol_version"},
		{"tool_name 空", CatalogInput{Name: "a", ServiceIdentity: "b", Tools: []ToolInput{{ToolName: " "}}}, "tool_name"},
		{"risk_level 词表外", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", RiskLevel: "CRITICAL"}}}, "risk_level"},
		{"risk_level 小写归一合法", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", RiskLevel: "low"}}}, ""},
		{"data_classification 词表外", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", DataClassification: "SECRET"}}}, "data_classification"},
		{"max_calls_per_minute 负", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", MaxCallsPerMinute: -1}}}, "max_calls_per_minute"},
		{"arg kind 词表外", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", ArgConstraints: []ArgConstraint{{Field: "path", Kind: "regex", Allow: []string{"/a"}}}}}}, "kind"},
		{"arg allow 空集", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", ArgConstraints: []ArgConstraint{{Field: "path", Kind: ArgKindPathPrefix}}}}}, "allow"},
		{"arg 两形态合法", CatalogInput{Name: "a", ServiceIdentity: "b",
			Tools: []ToolInput{{ToolName: "t", ArgConstraints: []ArgConstraint{
				{Field: "path", Kind: ArgKindPathPrefix, Allow: []string{"/refunds"}},
				{Field: "url", Kind: ArgKindDomainSuffix, Allow: []string{".example.com"}},
			}}}}, ""},
	}
	for _, c := range cases {
		got := ValidateCatalogInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

func TestValidateBindingInput(t *testing.T) {
	app, cat := uuid.NewString(), uuid.NewString()
	cases := []struct {
		name string
		in   BindingInput
		want string
	}{
		{"合法全字段", BindingInput{ApplicationID: app, EndpointPath: "/mcp/pay", CatalogID: cat, Mode: "PROTECT"}, ""},
		{"mode 缺省合法", BindingInput{ApplicationID: app, EndpointPath: "/mcp/pay", CatalogID: cat}, ""},
		{"mode 小写归一", BindingInput{ApplicationID: app, EndpointPath: "/mcp/pay", CatalogID: cat, Mode: "observe"}, ""},
		{"application_id 非法", BindingInput{ApplicationID: "xx", EndpointPath: "/mcp", CatalogID: cat}, "application_id"},
		{"endpoint_path 非斜杠开头", BindingInput{ApplicationID: app, EndpointPath: "mcp", CatalogID: cat}, "endpoint_path"},
		{"endpoint_path 空", BindingInput{ApplicationID: app, EndpointPath: " ", CatalogID: cat}, "endpoint_path"},
		{"catalog_id 非法", BindingInput{ApplicationID: app, EndpointPath: "/mcp", CatalogID: "zz"}, "catalog_id"},
		{"mode 词表外", BindingInput{ApplicationID: app, EndpointPath: "/mcp", CatalogID: cat, Mode: "BLOCK"}, "mode"},
	}
	for _, c := range cases {
		got := ValidateBindingInput(c.in)
		if c.want == "" && got != "" {
			t.Fatalf("%s 应合法: %s", c.name, got)
		}
		if c.want != "" && !strings.Contains(got, c.want) {
			t.Fatalf("%s 应含 %q: %s", c.name, c.want, got)
		}
	}
}

// ---------- 摘要算法 ----------

// tool_hash 确定性（同输入恒同输出，map 键序无关）+五元组任一变更即重算。
func TestComputeToolHashDeterministic(t *testing.T) {
	inA := map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{"type": "string"}, "b": map[string]any{"type": "integer"}}}
	inB := map[string]any{"properties": map[string]any{"b": map[string]any{"type": "integer"}, "a": map[string]any{"type": "string"}}, "type": "object"}
	h1, err := ComputeToolHash("refund", "1.0.0", "退款工具", &inA, nil)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := ComputeToolHash("refund", "1.0.0", "退款工具", &inB, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h1 != h2 {
		t.Fatalf("键序无关确定性: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, ToolHashPrefix) || len(h1) != len(ToolHashPrefix)+64 {
		t.Fatalf("前缀/长度形态: %s", h1)
	}
	// nil 与空 map 同义（store 层经 nilSchemaP 归一后入算——归一后与 nil 入算哈希一致）
	empty := map[string]any{}
	hNil, _ := ComputeToolHash("refund", "1.0.0", "退款工具", nil, nil)
	h3, _ := ComputeToolHash("refund", "1.0.0", "退款工具", nilSchemaP(&empty), nil)
	if h3 != hNil {
		t.Fatalf("空 schema 归一: %s vs %s", h3, hNil)
	}
	// 五元组任一变更 → 重算（描述/版本/schema/name 各一例）
	out := map[string]any{"type": "object"}
	for name, mutate := range map[string]func() (string, string, string, *map[string]any, *map[string]any){
		"描述变更": func() (string, string, string, *map[string]any, *map[string]any) {
			return "refund", "1.0.0", "退款工具v2", &inA, nil
		},
		"版本变更": func() (string, string, string, *map[string]any, *map[string]any) {
			return "refund", "1.0.1", "退款工具", &inA, nil
		},
		"schema 变更": func() (string, string, string, *map[string]any, *map[string]any) {
			return "refund", "1.0.0", "退款工具", &inA, &out
		},
		"名称变更": func() (string, string, string, *map[string]any, *map[string]any) {
			return "refund_v2", "1.0.0", "退款工具", &inA, nil
		},
	} {
		n, v, d, is, os := mutate()
		hx, err := ComputeToolHash(n, v, d, is, os)
		if err != nil {
			t.Fatal(err)
		}
		if hx == h1 {
			t.Fatalf("%s 应重算 tool_hash", name)
		}
	}
}

// catalog_hash 排序无关（输入序不同同集合同摘要）+空集确定性。
func TestComputeCatalogHash(t *testing.T) {
	a, b := ToolHashPrefix+"aaaa", ToolHashPrefix+"bbbb"
	h1 := ComputeCatalogHash([]string{a, b})
	h2 := ComputeCatalogHash([]string{b, a})
	if h1 != h2 {
		t.Fatalf("排序无关: %s vs %s", h1, h2)
	}
	if !strings.HasPrefix(h1, CatalogHashPrefix) || len(h1) != len(CatalogHashPrefix)+64 {
		t.Fatalf("前缀/长度形态: %s", h1)
	}
	if ComputeCatalogHash(nil) != ComputeCatalogHash([]string{}) {
		t.Fatal("空集确定性")
	}
	if ComputeCatalogHash([]string{a}) == h1 {
		t.Fatal("集合变更应重算")
	}
}

// 语义相等判定：digest+version+双 schema 规范化比较（空 map 与 nil 同义不判变更）。
func TestToolSemanticallyEqual(t *testing.T) {
	in := map[string]any{"type": "object"}
	base := Tool{ToolVersion: "1.0.0", DescriptionDigest: "d1", InputSchema: in}
	if !toolSemanticallyEqual(base, "1.0.0", "d1", &in, nil) {
		t.Fatal("全等应相等")
	}
	if toolSemanticallyEqual(base, "1.0.1", "d1", &in, nil) {
		t.Fatal("版本不等")
	}
	if toolSemanticallyEqual(base, "1.0.0", "d2", &in, nil) {
		t.Fatal("描述 digest 不等")
	}
	other := map[string]any{"type": "array"}
	if toolSemanticallyEqual(base, "1.0.0", "d1", &other, nil) {
		t.Fatal("schema 不等")
	}
	// DB 侧空 map 与导入侧 nil 同义（归一后相等）
	emptyDB := Tool{ToolVersion: "1.0.0", DescriptionDigest: "d1", InputSchema: map[string]any{}}
	if !toolSemanticallyEqual(emptyDB, "1.0.0", "d1", nil, nil) {
		t.Fatal("空 map/nil 归一相等")
	}
}

// ---------- fake 仓储 ----------

type fakeRepo struct {
	catalogs   map[uuid.UUID]*Catalog
	tools      map[uuid.UUID][]*Tool // catalog_id → 工具行
	bindings   map[uuid.UUID]*Binding
	nameIdx    map[string]uuid.UUID
	appExists  bool
	catExists  bool
	reviewedBy string
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		catalogs: map[uuid.UUID]*Catalog{}, tools: map[uuid.UUID][]*Tool{},
		bindings: map[uuid.UUID]*Binding{}, nameIdx: map[string]uuid.UUID{},
		appExists: true, catExists: true,
	}
}

func toolFromInput(catalogID uuid.UUID, in ToolInput) *Tool {
	digest := "sha256:" + in.Description // fake 形态（真算法 PG 契约覆盖）
	hash, _ := ComputeToolHash(in.ToolName, in.ToolVersion, in.Description, nilSchemaP(in.InputSchema), nilSchemaP(in.OutputSchema))
	risk := strings.ToUpper(strings.TrimSpace(in.RiskLevel))
	if risk == "" {
		risk = RiskHigh
	}
	class := strings.ToUpper(strings.TrimSpace(in.DataClassification))
	if class == "" {
		class = ClassUnknown
	}
	t := &Tool{ID: uuid.New(), CatalogID: catalogID, ToolName: strings.TrimSpace(in.ToolName),
		ToolVersion: in.ToolVersion, DescriptionDigest: digest, DescriptionPreview: in.Description,
		ToolHash: hash, RiskLevel: risk, DataClassification: class,
		CapabilityTags: in.CapabilityTags, AllowedPrincipals: in.AllowedPrincipals,
		AllowedRoles: in.AllowedRoles, AllowedTenants: in.AllowedTenants,
		ApprovalRequired: in.ApprovalRequired, MaxCallsPerMinute: in.MaxCallsPerMinute,
		ArgConstraints: in.ArgConstraints, ReviewStatus: ReviewPending,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if in.InputSchema != nil {
		t.InputSchema = *in.InputSchema
	}
	if in.OutputSchema != nil {
		t.OutputSchema = *in.OutputSchema
	}
	return t
}

func (f *fakeRepo) CreateCatalog(_ context.Context, in CatalogInput, by string) (*Catalog, []Tool, error) {
	name := strings.TrimSpace(in.Name)
	if _, dup := f.nameIdx[name]; dup {
		return nil, nil, ErrDuplicateName
	}
	c := &Catalog{ID: uuid.New(), Name: name, ServiceIdentity: strings.TrimSpace(in.ServiceIdentity),
		ProtocolVersion: ProtocolVersionDefault, Source: "MANUAL_IMPORT", Status: StatusEnabled,
		Version: 1, CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	tools := []Tool{}
	for _, ti := range in.Tools {
		t := toolFromInput(c.ID, ti)
		f.tools[c.ID] = append(f.tools[c.ID], t)
		tools = append(tools, *t)
	}
	c.CatalogHash = ComputeCatalogHash(nil)
	f.catalogs[c.ID] = c
	f.nameIdx[name] = c.ID
	return c, tools, nil
}

func (f *fakeRepo) ListCatalogs(_ context.Context) ([]CatalogSummary, error) {
	out := []CatalogSummary{}
	for _, c := range f.catalogs {
		s := CatalogSummary{Catalog: *c}
		for _, t := range f.tools[c.ID] {
			s.ToolCount++
			switch t.ReviewStatus {
			case ReviewApproved:
				s.ApprovedCount++
			case ReviewPending:
				s.PendingCount++
			case ReviewRejected:
				s.RejectedCount++
			}
		}
		out = append(out, s)
	}
	return out, nil
}

func (f *fakeRepo) GetCatalog(_ context.Context, id uuid.UUID) (*Catalog, []Tool, error) {
	c, ok := f.catalogs[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	tools := []Tool{}
	for _, t := range f.tools[id] {
		tools = append(tools, *t)
	}
	return c, tools, nil
}

func (f *fakeRepo) UpdateCatalog(_ context.Context, id uuid.UUID, in CatalogInput) (*Catalog, []Tool, error) {
	c, ok := f.catalogs[id]
	if !ok {
		return nil, nil, ErrNotFound
	}
	if c.Version != in.Version {
		return nil, nil, ErrVersionConflict
	}
	if other, dup := f.nameIdx[strings.TrimSpace(in.Name)]; dup && other != id {
		return nil, nil, ErrDuplicateName
	}
	delete(f.nameIdx, c.Name)
	c.Name = strings.TrimSpace(in.Name)
	c.ServiceIdentity = strings.TrimSpace(in.ServiceIdentity)
	c.Version++
	f.nameIdx[c.Name] = id
	f.tools[id] = nil
	tools := []Tool{}
	for _, ti := range in.Tools {
		t := toolFromInput(id, ti)
		f.tools[id] = append(f.tools[id], t)
		tools = append(tools, *t)
	}
	return c, tools, nil
}

func (f *fakeRepo) DeleteCatalog(_ context.Context, id uuid.UUID) error {
	c, ok := f.catalogs[id]
	if !ok {
		return ErrNotFound
	}
	for _, b := range f.bindings {
		if b.CatalogID == id {
			return ErrCatalogInUse
		}
	}
	delete(f.nameIdx, c.Name)
	delete(f.catalogs, id)
	delete(f.tools, id)
	return nil
}

func (f *fakeRepo) ReviewTool(_ context.Context, catalogID, toolID uuid.UUID, in ReviewInput, reviewedBy string) (*Tool, error) {
	for _, t := range f.tools[catalogID] {
		if t.ID == toolID {
			t.ReviewStatus = strings.ToUpper(strings.TrimSpace(in.Action))
			t.ReviewedBy = reviewedBy
			now := time.Now().UTC()
			t.ReviewedAt = &now
			if v := strings.ToUpper(strings.TrimSpace(in.RiskLevel)); v != "" {
				t.RiskLevel = v
			}
			if v := strings.ToUpper(strings.TrimSpace(in.DataClassification)); v != "" {
				t.DataClassification = v
			}
			if in.ApprovalRequired != nil {
				t.ApprovalRequired = *in.ApprovalRequired
			}
			if in.MaxCallsPerMinute != nil {
				t.MaxCallsPerMinute = *in.MaxCallsPerMinute
			}
			return t, nil
		}
	}
	return nil, ErrNotFound
}

func (f *fakeRepo) CreateBinding(_ context.Context, in BindingInput, by string) (*Binding, error) {
	if !f.appExists {
		return nil, ErrAppNotFound
	}
	if !f.catExists {
		return nil, ErrCatalogNotFound
	}
	appID, _ := uuid.Parse(in.ApplicationID)
	catID, _ := uuid.Parse(in.CatalogID)
	for _, b := range f.bindings {
		if b.ApplicationID == appID && b.EndpointPath == strings.TrimSpace(in.EndpointPath) {
			return nil, ErrBindingDuplicate
		}
	}
	mode := strings.ToUpper(strings.TrimSpace(in.Mode))
	if mode == "" {
		mode = ModeObserve
	}
	b := &Binding{ID: uuid.New(), ApplicationID: appID, EndpointPath: strings.TrimSpace(in.EndpointPath),
		CatalogID: catID, CatalogName: "pay-mcp", Mode: mode, Version: 1,
		CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	f.bindings[b.ID] = b
	return b, nil
}

func (f *fakeRepo) ListBindings(_ context.Context, applicationID uuid.UUID) ([]Binding, error) {
	out := []Binding{}
	for _, b := range f.bindings {
		if applicationID == uuid.Nil || b.ApplicationID == applicationID {
			out = append(out, *b)
		}
	}
	return out, nil
}

func (f *fakeRepo) UpdateBinding(_ context.Context, id uuid.UUID, in BindingInput) (*Binding, error) {
	b, ok := f.bindings[id]
	if !ok {
		return nil, ErrBindingNotFound
	}
	if b.Version != in.Version {
		return nil, ErrVersionConflict
	}
	if !f.catExists {
		return nil, ErrCatalogNotFound
	}
	catID, _ := uuid.Parse(in.CatalogID)
	b.CatalogID = catID
	if m := strings.ToUpper(strings.TrimSpace(in.Mode)); m != "" {
		b.Mode = m
	}
	b.Version++
	return b, nil
}

func (f *fakeRepo) DeleteBinding(_ context.Context, id uuid.UUID) error {
	if _, ok := f.bindings[id]; !ok {
		return ErrBindingNotFound
	}
	delete(f.bindings, id)
	return nil
}

// ---------- HTTP 映射 ----------

type spyAudits struct{ entries []audits.RecordInput }

func (s *spyAudits) Record(_ context.Context, in audits.RecordInput) error {
	s.entries = append(s.entries, in)
	return nil
}

func injectPerms(perms ...string) func(http.Handler) http.Handler {
	set := map[string]bool{}
	for _, p := range perms {
		set[p] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := &authz.Principal{UserID: uuid.New(), Username: "tester", PermsSet: set}
			next.ServeHTTP(w, r.WithContext(authz.WithPrincipal(r.Context(), p)))
		})
	}
}

func doReq(t *testing.T, mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	return rr
}

func decodeData(t *testing.T, rr *httptest.ResponseRecorder, v any) {
	t.Helper()
	var env map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(env["data"], v); err != nil {
		t.Fatalf("data 解码: %v body=%s", err, rr.Body.String())
	}
}

const catalogPath = "/api/v1/api-security/mcp/tool-catalogs"
const bindingPath = "/api/v1/api-security/mcp/bindings"

func validCatalogBody() string {
	return `{"name":"pay-mcp","service_identity":"mcp://pay.example.com","tools":[` +
		`{"tool_name":"refund","tool_version":"1.0.0","description":"发起退款","input_schema":{"type":"object"}},` +
		`{"tool_name":"query_order","description":"查询订单"}]}`
}

// 目录 CRUD 全链：create 200（导入落 PENDING_REVIEW）→ 同名 409 → list 统计 →
// get 200/404 → update 乐观锁两态 → delete 200/404。
func TestCatalogCRUDHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.read", "api_spec.manage"), NewHandler(repo, nil))

	rr := doReq(t, mux, http.MethodPost, catalogPath, validCatalogBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var created struct {
		Catalog Catalog `json:"catalog"`
		Tools   []Tool  `json:"tools"`
	}
	decodeData(t, rr, &created)
	if created.Catalog.Version != 1 || created.Catalog.Status != StatusEnabled {
		t.Fatalf("目录归一: %+v", created.Catalog)
	}
	if len(created.Tools) != 2 {
		t.Fatalf("工具行数: %d", len(created.Tools))
	}
	for _, tool := range created.Tools {
		if tool.ReviewStatus != ReviewPending {
			t.Fatalf("导入恒落 PENDING_REVIEW: %s", tool.ReviewStatus)
		}
		if !strings.HasPrefix(tool.ToolHash, ToolHashPrefix) {
			t.Fatalf("tool_hash 前缀: %s", tool.ToolHash)
		}
		if tool.RiskLevel != RiskHigh || tool.DataClassification != ClassUnknown {
			t.Fatalf("导入缺省定级 HIGH/UNKNOWN: %s/%s", tool.RiskLevel, tool.DataClassification)
		}
	}
	catID := created.Catalog.ID.String()

	// 同名 → 409
	if rr := doReq(t, mux, http.MethodPost, catalogPath, validCatalogBody()); rr.Code != http.StatusConflict {
		t.Fatalf("同名应 409: %d %s", rr.Code, rr.Body.String())
	}
	// 校验 400（service_identity 空）
	if rr := doReq(t, mux, http.MethodPost, catalogPath, `{"name":"x"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("校验应 400: %d", rr.Code)
	}
	// list 含审核统计
	rr = doReq(t, mux, http.MethodGet, catalogPath, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d", rr.Code)
	}
	var list struct {
		Items []CatalogSummary `json:"items"`
		Total int              `json:"total"`
	}
	decodeData(t, rr, &list)
	if list.Total != 1 || list.Items[0].ToolCount != 2 || list.Items[0].PendingCount != 2 {
		t.Fatalf("list 统计: %+v", list)
	}
	// get 200 / 404
	if rr := doReq(t, mux, http.MethodGet, catalogPath+"/"+catID, ""); rr.Code != http.StatusOK {
		t.Fatalf("get: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodGet, catalogPath+"/"+uuid.NewString(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodGet, catalogPath+"/not-a-uuid", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 id 应 400: %d", rr.Code)
	}
	// update：version 缺失 400 / 冲突 409 / 合法 200（再导入变更行重置 PENDING_REVIEW）
	if rr := doReq(t, mux, http.MethodPut, catalogPath+"/"+catID,
		`{"name":"pay-mcp","service_identity":"mcp://pay.example.com","tools":[]}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("version 缺失应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, catalogPath+"/"+catID,
		`{"name":"pay-mcp","service_identity":"mcp://pay.example.com","tools":[],"version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("乐观锁冲突应 409: %d", rr.Code)
	}
	rr = doReq(t, mux, http.MethodPut, catalogPath+"/"+catID,
		`{"name":"pay-mcp","service_identity":"mcp://pay.example.com","tools":[{"tool_name":"refund","description":"发起退款v2"}],"version":1}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: %d %s", rr.Code, rr.Body.String())
	}
	// delete 200；重复 404
	if rr := doReq(t, mux, http.MethodDelete, catalogPath+"/"+catID, ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, catalogPath+"/"+catID, ""); rr.Code != http.StatusNotFound {
		t.Fatalf("重复 delete 应 404: %d", rr.Code)
	}
}

// 审核端点：action 词表 400 / APPROVED 200（定级更新+reviewed_by）/ 不存在 404。
func TestReviewToolHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.read", "api_spec.manage"), NewHandler(repo, nil))

	rr := doReq(t, mux, http.MethodPost, catalogPath, validCatalogBody())
	var created struct {
		Catalog Catalog `json:"catalog"`
		Tools   []Tool  `json:"tools"`
	}
	decodeData(t, rr, &created)
	catID := created.Catalog.ID.String()
	toolID := created.Tools[0].ID.String()
	reviewPath := catalogPath + "/" + catID + "/tools/" + toolID + "/review"

	// action 词表外 → 400
	if rr := doReq(t, mux, http.MethodPost, reviewPath, `{"action":"PASS"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("action 词表应 400: %d", rr.Code)
	}
	// risk_level 词表外 → 400
	if rr := doReq(t, mux, http.MethodPost, reviewPath, `{"action":"APPROVED","risk_level":"CRITICAL"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("risk_level 词表应 400: %d", rr.Code)
	}
	// APPROVED + 定级更新 → 200
	rr = doReq(t, mux, http.MethodPost, reviewPath,
		`{"action":"APPROVED","risk_level":"MEDIUM","data_classification":"INTERNAL","approval_required":true,"max_calls_per_minute":60}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("review: %d %s", rr.Code, rr.Body.String())
	}
	var tool Tool
	decodeData(t, rr, &tool)
	if tool.ReviewStatus != ReviewApproved || tool.ReviewedBy != "tester" || tool.ReviewedAt == nil {
		t.Fatalf("审核落账: %+v", tool)
	}
	if tool.RiskLevel != RiskMedium || tool.DataClassification != ClassInternal ||
		!tool.ApprovalRequired || tool.MaxCallsPerMinute != 60 {
		t.Fatalf("定级更新: %+v", tool)
	}
	// toolId 非法 400 / 不存在 404
	if rr := doReq(t, mux, http.MethodPost, catalogPath+"/"+catID+"/tools/xx/review", `{"action":"APPROVED"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 toolId 应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPost, catalogPath+"/"+catID+"/tools/"+uuid.NewString()+"/review",
		`{"action":"REJECTED"}`); rr.Code != http.StatusNotFound {
		t.Fatalf("不存在工具应 404: %d", rr.Code)
	}
}

// 绑定 CRUD 全链：create 200 → 同（应用,endpoint_path）409 → 引用缺失 400 →
// list 过滤 → update 乐观锁两态 → delete 200/404 → 引用目录删除 409。
func TestBindingCRUDHTTP(t *testing.T) {
	repo := newFakeRepo()
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.read", "api_spec.manage"), NewHandler(repo, nil))
	appID, catID := uuid.NewString(), uuid.NewString()
	body := `{"application_id":"` + appID + `","endpoint_path":"/mcp/pay","catalog_id":"` + catID + `","mode":"PROTECT"}`

	rr := doReq(t, mux, http.MethodPost, bindingPath, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var b Binding
	decodeData(t, rr, &b)
	if b.Mode != ModeProtect || b.Version != 1 {
		t.Fatalf("绑定归一: %+v", b)
	}
	// 同（应用,endpoint_path）→ 409
	if rr := doReq(t, mux, http.MethodPost, bindingPath, body); rr.Code != http.StatusConflict {
		t.Fatalf("重复绑定应 409: %d", rr.Code)
	}
	// 应用/目录引用缺失 → 400（两态）
	repo.appExists = false
	if rr := doReq(t, mux, http.MethodPost, bindingPath,
		`{"application_id":"`+uuid.NewString()+`","endpoint_path":"/mcp/x","catalog_id":"`+catID+`"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("应用缺失应 400: %d", rr.Code)
	}
	repo.appExists = true
	repo.catExists = false
	if rr := doReq(t, mux, http.MethodPost, bindingPath,
		`{"application_id":"`+uuid.NewString()+`","endpoint_path":"/mcp/y","catalog_id":"`+uuid.NewString()+`"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("目录缺失应 400: %d", rr.Code)
	}
	repo.catExists = true
	// list（application_id 过滤）
	rr = doReq(t, mux, http.MethodGet, bindingPath+"?application_id="+appID, "")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "/mcp/pay") {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	if rr := doReq(t, mux, http.MethodGet, bindingPath+"?application_id=xx", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("过滤参数非法应 400: %d", rr.Code)
	}
	// update：version 缺失 400 / 冲突 409 / 合法 200
	if rr := doReq(t, mux, http.MethodPut, bindingPath+"/"+b.ID.String(),
		`{"catalog_id":"`+catID+`","mode":"OBSERVE"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("version 缺失应 400: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, bindingPath+"/"+b.ID.String(),
		`{"catalog_id":"`+catID+`","mode":"OBSERVE","version":9}`); rr.Code != http.StatusConflict {
		t.Fatalf("乐观锁冲突应 409: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodPut, bindingPath+"/"+b.ID.String(),
		`{"catalog_id":"`+catID+`","mode":"OBSERVE","version":1}`); rr.Code != http.StatusOK {
		t.Fatalf("update: %d", rr.Code)
	}
	// 引用目录删除 → 409（ErrCatalogInUse 先决校验）
	repo.catalogs[b.CatalogID] = &Catalog{ID: b.CatalogID, Name: "pay-mcp"}
	if rr := doReq(t, mux, http.MethodDelete, catalogPath+"/"+b.CatalogID.String(), ""); rr.Code != http.StatusConflict {
		t.Fatalf("引用中目录删除应 409: %d", rr.Code)
	}
	// delete 200；重复 404
	if rr := doReq(t, mux, http.MethodDelete, bindingPath+"/"+b.ID.String(), ""); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d", rr.Code)
	}
	if rr := doReq(t, mux, http.MethodDelete, bindingPath+"/"+b.ID.String(), ""); rr.Code != http.StatusNotFound {
		t.Fatalf("重复 delete 应 404: %d", rr.Code)
	}
}

// 越权对照（jiuzhang_admin 形态全 403；read/manage 权限点零新增实证）。
func TestEndpointsForbiddenForSysAdmin(t *testing.T) {
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("system.read", "applications.edit"), NewHandler(newFakeRepo(), nil))
	catID, toolID := uuid.NewString(), uuid.NewString()
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, catalogPath, ""},
		{http.MethodPost, catalogPath, validCatalogBody()},
		{http.MethodGet, catalogPath + "/" + catID, ""},
		{http.MethodPut, catalogPath + "/" + catID, `{"name":"a","service_identity":"b","tools":[],"version":1}`},
		{http.MethodDelete, catalogPath + "/" + catID, ""},
		{http.MethodPost, catalogPath + "/" + catID + "/tools/" + toolID + "/review", `{"action":"APPROVED"}`},
		{http.MethodGet, bindingPath, ""},
		{http.MethodPost, bindingPath, `{"application_id":"` + uuid.NewString() + `","endpoint_path":"/mcp","catalog_id":"` + catID + `"}`},
		{http.MethodPut, bindingPath + "/" + toolID, `{"catalog_id":"` + catID + `","mode":"OBSERVE","version":1}`},
		{http.MethodDelete, bindingPath + "/" + toolID, ""},
	} {
		rr := doReq(t, mux, tc.method, tc.path, tc.body)
		if rr.Code != http.StatusForbidden {
			t.Fatalf("%s %s: 应 403, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

// 写操作 HIGH 审计（object_type + after 摘要 JSON 全值非遮蔽形态）。
func TestAuditHigh(t *testing.T) {
	repo := newFakeRepo()
	spy := &spyAudits{}
	h := NewHandler(repo, nil)
	h.audits = spy
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.manage"), h)

	rr := doReq(t, mux, http.MethodPost, catalogPath, validCatalogBody())
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d", rr.Code)
	}
	if len(spy.entries) != 1 {
		t.Fatalf("审计条数: %d", len(spy.entries))
	}
	e := spy.entries[0]
	if e.ObjectType != "mcp_tool_catalog" || e.RiskLevel != "HIGH" || e.Action != "create" ||
		!strings.Contains(e.AfterSummary, `"name":"pay-mcp"`) || !strings.Contains(e.AfterSummary, `"tools":2`) {
		t.Fatalf("目录审计内容: %+v", e)
	}

	rr = doReq(t, mux, http.MethodPost, bindingPath,
		`{"application_id":"`+uuid.NewString()+`","endpoint_path":"/mcp/pay","catalog_id":"`+uuid.NewString()+`","mode":"PROTECT"}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("binding create: %d", rr.Code)
	}
	e = spy.entries[1]
	if e.ObjectType != "mcp_catalog_binding" || e.RiskLevel != "HIGH" ||
		!strings.Contains(e.AfterSummary, `"endpoint_path":"/mcp/pay"`) || !strings.Contains(e.AfterSummary, `"mode":"PROTECT"`) {
		t.Fatalf("绑定审计内容: %+v", e)
	}
}

// 绑定变更触发发布（设计 §1.14）；目录/审核操作不触发（S5 描述符先例——下次发布带上）。
func TestBindingChangeTriggersPublish(t *testing.T) {
	repo := newFakeRepo()
	h := NewHandler(repo, nil)
	var calls int
	h.SetPublishFunc(func(_ context.Context, _ uuid.UUID, _ string) { calls++ })
	mux := http.NewServeMux()
	RegisterRoutes(mux, injectPerms("api_spec.manage"), h)
	catID := uuid.NewString()

	// 目录创建不触发
	doReq(t, mux, http.MethodPost, catalogPath, validCatalogBody())
	if calls != 0 {
		t.Fatalf("目录创建不应触发发布: %d", calls)
	}
	// 绑定 create/update/delete 各触发一次
	body := `{"application_id":"` + uuid.NewString() + `","endpoint_path":"/mcp/pay","catalog_id":"` + catID + `"}`
	rr := doReq(t, mux, http.MethodPost, bindingPath, body)
	if rr.Code != http.StatusOK {
		t.Fatalf("create: %d", rr.Code)
	}
	var b Binding
	decodeData(t, rr, &b)
	doReq(t, mux, http.MethodPut, bindingPath+"/"+b.ID.String(), `{"catalog_id":"`+catID+`","mode":"PROTECT","version":1}`)
	doReq(t, mux, http.MethodDelete, bindingPath+"/"+b.ID.String(), "")
	if calls != 3 {
		t.Fatalf("绑定三次变更应触发三次: %d", calls)
	}
	// 发布通道不可用时主流程不受影响（warn 降级）
	h2 := NewHandler(newFakeRepo(), nil)
	mux2 := http.NewServeMux()
	RegisterRoutes(mux2, injectPerms("api_spec.manage"), h2)
	if rr := doReq(t, mux2, http.MethodPost, bindingPath, body); rr.Code != http.StatusOK {
		t.Fatalf("无发布通道 create 仍 200: %d", rr.Code)
	}
}
