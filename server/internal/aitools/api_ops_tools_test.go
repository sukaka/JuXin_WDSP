// api_ops_tools_test.go P1-02 第一批 API 运营 Tool 组测试：
// 注册元数据（READ_ONLY + 权限点）、权限拒绝、输入校验、只读语义（fake 仅暴露读方法即结构性保证），
// 以及弱点证据脱敏 / 策略双模式 / 规范差异截断 / 态势透传的 happy path。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
)

// fakePolicyReader 内存 APIRuntimePolicyReader（只读，无写方法可实现——只读语义的结构性保证）。
type fakePolicyReader struct {
	byID map[uuid.UUID]*apimodels.RuntimePolicy
}

func (f *fakePolicyReader) GetRuntimePolicyByID(_ context.Context, id uuid.UUID) (*apimodels.RuntimePolicy, error) {
	p, ok := f.byID[id]
	if !ok {
		return nil, apimodels.ErrRuntimePolicyNotFound
	}
	return p, nil
}

func (f *fakePolicyReader) ListRuntimePolicies(_ context.Context, filter apimodels.RuntimePolicyFilter) ([]apimodels.RuntimePolicy, int64, error) {
	out := []apimodels.RuntimePolicy{}
	for _, p := range f.byID {
		if filter.EndpointID != nil && p.EndpointID != *filter.EndpointID {
			continue
		}
		if filter.Status != "" && p.Status != filter.Status {
			continue
		}
		out = append(out, *p)
	}
	return out, int64(len(out)), nil
}

// fakeSpecReader 内存 APISpecReader。
type fakeSpecReader struct {
	specs map[uuid.UUID]*apisecurity.ImportSpec
	diffs map[uuid.UUID][]apisecurity.SpecDiff
}

func (f *fakeSpecReader) ListSpecs(_ context.Context, name, status string, _, _ int) ([]apisecurity.ImportSpec, int64, error) {
	out := []apisecurity.ImportSpec{}
	for _, s := range f.specs {
		if name != "" && s.Name != name {
			continue
		}
		if status != "" && s.Status != status {
			continue
		}
		out = append(out, *s)
	}
	return out, int64(len(out)), nil
}

func (f *fakeSpecReader) GetSpec(_ context.Context, id uuid.UUID) (*apisecurity.ImportSpec, error) {
	s, ok := f.specs[id]
	if !ok {
		return nil, apisecurity.ErrNotFound
	}
	return s, nil
}

func (f *fakeSpecReader) ListSpecDiffs(_ context.Context, specID uuid.UUID) ([]apisecurity.SpecDiff, error) {
	out := f.diffs[specID]
	if out == nil {
		out = []apisecurity.SpecDiff{}
	}
	return out, nil
}

// fakePostureReader 内存 APIPostureReader。
type fakePostureReader struct{ posture *apisecurity.Posture }

func (f *fakePostureReader) GetPosture(context.Context) (*apisecurity.Posture, error) {
	return f.posture, nil
}

// newAPIOpsRegistry 注册 P1-02 第一批 Tool 的测试注册中心。
func newAPIOpsRegistry(weakness APIWeaknessReader, sensitive APISensitiveReader, policies APIRuntimePolicyReader, specs APISpecReader, posture APIPostureReader) *Registry {
	r := NewRegistry()
	NewAPIOpsTools(r, weakness, sensitive, policies, specs, posture)
	return r
}

// emptyOpsFakes 五路只读依赖的空 fake（不触库测试用）。
func emptyOpsFakes() (APIWeaknessReader, APISensitiveReader, APIRuntimePolicyReader, APISpecReader, APIPostureReader) {
	return apiweakness.NewMemStore(), apidata.NewMemStore(),
		&fakePolicyReader{byID: map[uuid.UUID]*apimodels.RuntimePolicy{}},
		&fakeSpecReader{specs: map[uuid.UUID]*apisecurity.ImportSpec{}, diffs: map[uuid.UUID][]apisecurity.SpecDiff{}},
		&fakePostureReader{posture: &apisecurity.Posture{}}
}

// TestNewAPIOpsToolsMetadata 五个 Tool 全部注册，READ_ONLY 且权限点正确。
func TestNewAPIOpsToolsMetadata(t *testing.T) {
	r := newAPIOpsRegistry(emptyOpsFakes())
	want := map[string]string{
		"api_weakness.search":    "api_weakness.read",
		"api_sensitive.search":   "api_data.read",
		"api_runtime_policy.get": "api_model.read",
		"api_spec.get":           "api_spec.read",
		"api_posture.get":        "api_runtime.read",
	}
	if got := len(r.List()); got != len(want) {
		t.Fatalf("注册 Tool 数 = %d, want %d", got, len(want))
	}
	for code, perm := range want {
		tl, ok := r.Get(code)
		if !ok {
			t.Errorf("缺少 Tool %s", code)
			continue
		}
		if tl.RiskLevel() != RiskReadOnly {
			t.Errorf("Tool %s risk = %s, want READ_ONLY（P1-02 纪律：API 域新增 Tool 只允许 READ_ONLY）", code, tl.RiskLevel())
		}
		if tl.RequiredPermission() != perm {
			t.Errorf("Tool %s permission = %s, want %s", code, tl.RequiredPermission(), perm)
		}
		if tl.TimeoutSeconds() <= 0 || tl.MaxResults() <= 0 {
			t.Errorf("Tool %s timeout/maxResults 未设置", code)
		}
	}
}

// TestAPIOpsToolPermissionDenied 无对应权限点拒绝执行并审计 DENIED；nil Principal 同样拒绝。
func TestAPIOpsToolPermissionDenied(t *testing.T) {
	r := newAPIOpsRegistry(emptyOpsFakes())
	aud := &fakeAuditor{}
	_, _, err := r.Execute(context.Background(), adminPrincipal("api_runtime.read"), uuid.New(), nil,
		"api_weakness.search", json.RawMessage(`{}`), aud)
	if !errors.Is(err, ErrPermission) {
		t.Fatalf("err = %v, want ErrPermission", err)
	}
	if len(aud.records) != 1 || aud.records[0].Status != "DENIED" {
		t.Fatalf("DENIED 审计记录缺失: %+v", aud.records)
	}
	// nil Principal 拒绝
	if _, _, err := r.Execute(context.Background(), nil, uuid.New(), nil,
		"api_posture.get", nil, nil); !errors.Is(err, ErrPermission) {
		t.Errorf("nil Principal err = %v, want ErrPermission", err)
	}
	// 具备权限点 → 放行（空仓储正常返回空列表）
	if _, _, err := r.Execute(context.Background(), adminPrincipal("api_weakness.read"), uuid.New(), nil,
		"api_weakness.search", json.RawMessage(`{}`), nil); err != nil {
		t.Errorf("具备权限点应放行: %v", err)
	}
}

// TestAPIOpsToolInputValidation 入参校验：非法枚举 / 非法 UUID / 互斥参数。
func TestAPIOpsToolInputValidation(t *testing.T) {
	r := newAPIOpsRegistry(emptyOpsFakes())
	ctx := context.Background()
	cases := []struct {
		code  string
		perm  string
		input string
	}{
		{"api_weakness.search", "api_weakness.read", `{"status":"HACKED"}`},
		{"api_weakness.search", "api_weakness.read", `{"severity":"EXTREME"}`},
		{"api_weakness.search", "api_weakness.read", `{"category":"FOO"}`},
		{"api_weakness.search", "api_weakness.read", `{"endpoint_id":"bad"}`},
		{"api_sensitive.search", "api_data.read", `{"status":"ON"}`},
		{"api_sensitive.search", "api_data.read", `{"level":"TOP"}`},
		{"api_runtime_policy.get", "api_model.read", `{}`},
		{"api_runtime_policy.get", "api_model.read", `{"policy_id":"` + uuid.NewString() + `","endpoint_id":"` + uuid.NewString() + `"}`},
		{"api_runtime_policy.get", "api_model.read", `{"policy_id":"bad"}`},
		{"api_runtime_policy.get", "api_model.read", `{"endpoint_id":"bad"}`},
		{"api_runtime_policy.get", "api_model.read", `{"endpoint_id":"` + uuid.NewString() + `","status":"WEIRD"}`},
		{"api_spec.get", "api_spec.read", `{"spec_id":"bad"}`},
		{"api_spec.get", "api_spec.read", `{"status":"WEIRD"}`},
	}
	for _, c := range cases {
		_, _, err := r.Execute(ctx, adminPrincipal(c.perm), uuid.New(), nil, c.code, json.RawMessage(c.input), nil)
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s input %s: err = %v, want ErrInvalidInput", c.code, c.input, err)
		}
	}
}

// seedWeaknesses 内存仓储造两个弱点：w1 SENSITIVE_IN_QUERY（HIGH/SENSITIVE），w2 DEPRECATED_STILL_CALLED（MEDIUM/LIFECYCLE）。
// w1 证据故意携带 password 键，验证输出脱敏纪律。
func seedWeaknesses(t *testing.T) (*apiweakness.MemStore, uuid.UUID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	mem := apiweakness.NewMemStore()
	ep1, ep2 := uuid.New(), uuid.New()
	mem.SetEndpointKey(ep1, "GET /api/users")
	mem.SetEndpointKey(ep2, "GET /api/old")
	now := time.Now().UTC()
	if _, err := mem.UpsertDerived(ctx, apiweakness.DerivedInput{
		EndpointID: ep1, WeaknessCode: apiweakness.CodeSensitiveInQuery,
		WeaknessName: "敏感数据出现在 URL 查询串", Category: apiweakness.CategorySensitive, Severity: apiweakness.SeverityHigh,
		Evidence: json.RawMessage(`{"password":"secret123","field":"query.token"}`), Now: now,
	}); err != nil {
		t.Fatalf("UpsertDerived w1: %v", err)
	}
	if _, err := mem.UpsertDerived(ctx, apiweakness.DerivedInput{
		EndpointID: ep2, WeaknessCode: apiweakness.CodeDeprecatedStillCalled,
		WeaknessName: "已下线接口仍被调用", Category: apiweakness.CategoryLifecycle, Severity: apiweakness.SeverityMedium,
		Evidence: json.RawMessage(`{"hits":3}`), Now: now,
	}); err != nil {
		t.Fatalf("UpsertDerived w2: %v", err)
	}
	return mem, ep1, ep2
}

// TestAPIWeaknessSearchHappyPath api_weakness.search 过滤与证据脱敏。
func TestAPIWeaknessSearchHappyPath(t *testing.T) {
	mem, ep1, _ := seedWeaknesses(t)
	_, sens, pol, spec, post := emptyOpsFakes()
	r := newAPIOpsRegistry(mem, sens, pol, spec, post)
	ctx := context.Background()
	p := adminPrincipal("api_weakness.read")

	// 全量两条，证据 password 已脱敏
	res, _, err := r.Execute(ctx, p, uuid.New(), nil, "api_weakness.search", json.RawMessage(`{"limit":50}`), nil)
	if err != nil {
		t.Fatalf("api_weakness.search: %v", err)
	}
	got := res.(map[string]interface{})
	if got["total"].(int64) != 2 {
		t.Fatalf("total = %v, want 2", got["total"])
	}
	for _, it := range got["items"].([]map[string]interface{}) {
		ev := it["evidence"].(string)
		if strings.Contains(ev, "secret123") {
			t.Errorf("证据未脱敏: %s", ev)
		}
		if it["weakness_code"] == apiweakness.CodeSensitiveInQuery && !strings.Contains(ev, "********") {
			t.Errorf("password 键应被掩码: %s", ev)
		}
	}

	// 分类过滤（小写输入归一为大写）
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_weakness.search", json.RawMessage(`{"category":"sensitive"}`), nil)
	if err != nil {
		t.Fatalf("category 过滤: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 1 {
		t.Errorf("SENSITIVE total = %v, want 1", got)
	}

	// 状态 + 接口过滤（派生弱点初始状态 NEW）
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_weakness.search",
		json.RawMessage(`{"status":"new","endpoint_id":"`+ep1.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("status+endpoint 过滤: %v", err)
	}
	items := res.(map[string]interface{})["items"].([]map[string]interface{})
	if len(items) != 1 || items[0]["endpoint_key"] != "GET /api/users" {
		t.Errorf("过滤命中错误: %+v", items)
	}

	// severity 过滤
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_weakness.search", json.RawMessage(`{"severity":"medium"}`), nil)
	if err != nil {
		t.Fatalf("severity 过滤: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 1 {
		t.Errorf("MEDIUM total = %v, want 1", got)
	}
}

// TestAPISensitiveSearchHappyPath api_sensitive.search 等级/状态/关键字过滤。
func TestAPISensitiveSearchHappyPath(t *testing.T) {
	ctx := context.Background()
	mem := apidata.NewMemStore()
	if err := mem.CreateType(ctx, &apidata.SensitiveDataType{
		Name: "身份证号", Category: "PII", Level: apidata.LevelCore, DataType: "id_card",
		Status: apidata.TypeStatusEnabled,
	}); err != nil {
		t.Fatalf("CreateType 1: %v", err)
	}
	if err := mem.CreateType(ctx, &apidata.SensitiveDataType{
		Name: "内部备注", Category: "INTERNAL", Level: apidata.LevelGeneral, DataType: "note",
		Status: apidata.TypeStatusDisabled,
	}); err != nil {
		t.Fatalf("CreateType 2: %v", err)
	}
	wk, _, pol, spec, post := emptyOpsFakes()
	r := newAPIOpsRegistry(wk, mem, pol, spec, post)
	p := adminPrincipal("api_data.read")

	res, _, err := r.Execute(ctx, p, uuid.New(), nil, "api_sensitive.search", json.RawMessage(`{"level":"core"}`), nil)
	if err != nil {
		t.Fatalf("api_sensitive.search: %v", err)
	}
	got := res.(map[string]interface{})
	if got["total"].(int64) != 1 {
		t.Fatalf("CORE total = %v, want 1", got["total"])
	}
	items := got["items"].([]apidata.SensitiveDataType)
	if items[0].Name != "身份证号" || items[0].Level != apidata.LevelCore {
		t.Errorf("命中类型错误: %+v", items[0])
	}

	// 状态过滤 + 关键字
	res, _, err = r.Execute(ctx, p, uuid.New(), nil, "api_sensitive.search", json.RawMessage(`{"status":"disabled","keyword":"备注"}`), nil)
	if err != nil {
		t.Fatalf("status+keyword 过滤: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 1 {
		t.Errorf("DISABLED+备注 total = %v, want 1", got)
	}
}

// TestAPIRuntimePolicyGetHappyPath api_runtime_policy.get 双模式：详情含编译内容，列表不含。
func TestAPIRuntimePolicyGetHappyPath(t *testing.T) {
	endpointID := uuid.New()
	p1 := &apimodels.RuntimePolicy{
		ID: uuid.New(), EndpointID: endpointID, EndpointKey: "GET /api/users",
		SourceModelVersionID: uuid.New(), RuntimeVersion: "v2", CompilerVersion: "1.0",
		Content:     json.RawMessage(`{"endpoint_key":"GET /api/users","rules":[]}`),
		ContentHash: "h2", Status: apimodels.PolicyStatusActive,
	}
	p2 := &apimodels.RuntimePolicy{
		ID: uuid.New(), EndpointID: endpointID, EndpointKey: "GET /api/users",
		SourceModelVersionID: uuid.New(), RuntimeVersion: "v1", CompilerVersion: "1.0",
		Content:     json.RawMessage(`{"endpoint_key":"GET /api/users"}`),
		ContentHash: "h1", Status: apimodels.PolicyStatusRolledBack,
	}
	fp := &fakePolicyReader{byID: map[uuid.UUID]*apimodels.RuntimePolicy{p1.ID: p1, p2.ID: p2}}
	wk, sens, _, spec, post := emptyOpsFakes()
	r := newAPIOpsRegistry(wk, sens, fp, spec, post)
	ctx := context.Background()
	perm := adminPrincipal("api_model.read")

	// 详情模式：含完整编译内容
	res, _, err := r.Execute(ctx, perm, uuid.New(), nil, "api_runtime_policy.get",
		json.RawMessage(`{"policy_id":"`+p1.ID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("policy_id 详情: %v", err)
	}
	detail := res.(map[string]interface{})
	if detail["status"] != apimodels.PolicyStatusActive || detail["runtime_version"] != "v2" {
		t.Errorf("详情字段错误: %v", detail)
	}
	if _, ok := detail["content"].(json.RawMessage); !ok {
		t.Errorf("详情应含编译内容 content, got %T", detail["content"])
	}

	// 不存在的策略
	_, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_runtime_policy.get",
		json.RawMessage(`{"policy_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失策略 err = %v, want not found", err)
	}

	// 列表模式：不含编译内容，带说明
	res, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_runtime_policy.get",
		json.RawMessage(`{"endpoint_id":"`+endpointID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("endpoint_id 列表: %v", err)
	}
	got := res.(map[string]interface{})
	if got["total"].(int64) != 2 {
		t.Fatalf("列表 total = %v, want 2", got["total"])
	}
	for _, it := range got["items"].([]map[string]interface{}) {
		if _, has := it["content"]; has {
			t.Errorf("列表模式不应含编译内容: %v", it)
		}
	}
	if got["note"] == "" {
		t.Errorf("列表模式应带说明 note")
	}

	// 列表模式状态过滤
	res, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_runtime_policy.get",
		json.RawMessage(`{"endpoint_id":"`+endpointID.String()+`","status":"active"}`), nil)
	if err != nil {
		t.Fatalf("status 过滤: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 1 {
		t.Errorf("ACTIVE total = %v, want 1", got)
	}
}

// TestAPISpecGetHappyPath api_spec.get 双模式：详情含差异（截断标记），列表按名称/状态过滤。
func TestAPISpecGetHappyPath(t *testing.T) {
	specID := uuid.New()
	spec := &apisecurity.ImportSpec{
		ID: specID, Name: "payment-api", VersionNo: 2, Status: apisecurity.SpecStatusActive,
		Format: apisecurity.SpecFormatOpenAPI3, FileName: "payment.json", ContentHash: "abc",
		EndpointCount: 12,
	}
	oldID := uuid.New()
	old := &apisecurity.ImportSpec{
		ID: oldID, Name: "payment-api", VersionNo: 1, Status: apisecurity.SpecStatusHistorical,
		Format: apisecurity.SpecFormatOpenAPI3, EndpointCount: 10,
	}
	// 201 条差异验证截断
	diffs := make([]apisecurity.SpecDiff, 0, 201)
	for i := 0; i < 201; i++ {
		diffs = append(diffs, apisecurity.SpecDiff{
			ID: uuid.New(), SpecID: specID, DiffType: apisecurity.DiffMissingInRuntime,
			EndpointKey: "GET /p" + strings.Repeat("x", i%3) + string(rune('0'+i%10)),
		})
	}
	fs := &fakeSpecReader{
		specs: map[uuid.UUID]*apisecurity.ImportSpec{specID: spec, oldID: old},
		diffs: map[uuid.UUID][]apisecurity.SpecDiff{specID: diffs},
	}
	wk, sens, pol, _, post := emptyOpsFakes()
	r := newAPIOpsRegistry(wk, sens, pol, fs, post)
	ctx := context.Background()
	perm := adminPrincipal("api_spec.read")

	// 详情模式：差异截断到 200 并标记
	res, _, err := r.Execute(ctx, perm, uuid.New(), nil, "api_spec.get",
		json.RawMessage(`{"spec_id":"`+specID.String()+`"}`), nil)
	if err != nil {
		t.Fatalf("spec_id 详情: %v", err)
	}
	got := res.(map[string]interface{})
	gotSpec := got["spec"].(*apisecurity.ImportSpec)
	if gotSpec.Name != "payment-api" || gotSpec.VersionNo != 2 {
		t.Errorf("规范详情错误: %+v", gotSpec)
	}
	if got["diff_count"].(int) != apiSpecDiffsMax || !got["diffs_truncated"].(bool) {
		t.Errorf("差异截断错误: count=%v truncated=%v", got["diff_count"], got["diffs_truncated"])
	}
	if got["note"] == "" {
		t.Errorf("缺少差异说明 note")
	}

	// 不存在的规范
	_, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_spec.get",
		json.RawMessage(`{"spec_id":"`+uuid.NewString()+`"}`), nil)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("缺失规范 err = %v, want not found", err)
	}

	// 列表模式：按名称过滤两个版本；状态过滤只剩 ACTIVE
	res, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_spec.get", json.RawMessage(`{"name":"payment-api"}`), nil)
	if err != nil {
		t.Fatalf("name 列表: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 2 {
		t.Errorf("name 过滤 total = %v, want 2", got)
	}
	res, _, err = r.Execute(ctx, perm, uuid.New(), nil, "api_spec.get", json.RawMessage(`{"status":"active"}`), nil)
	if err != nil {
		t.Fatalf("status 列表: %v", err)
	}
	if got := res.(map[string]interface{})["total"].(int64); got != 1 {
		t.Errorf("ACTIVE total = %v, want 1", got)
	}
}

// TestAPIPostureGetHappyPath api_posture.get 透传聚合结果。
func TestAPIPostureGetHappyPath(t *testing.T) {
	fp := &fakePostureReader{posture: &apisecurity.Posture{
		Endpoints: apisecurity.EndpointPosture{
			Total:            9,
			ByAssetStatus:    map[string]int{"CONFIRMED": 7, "DISCOVERED": 2},
			ByLearningStatus: map[string]int{"LEARNED": 6},
		},
		Findings:           apisecurity.FindingPosture{OpenTotal: 3, OpenBySeverity: map[string]int{"HIGH": 1}},
		LearningCoverage:   0.6667,
		LearningCovered:    6,
		ModelFreezeRate:    0.5,
		ModelVersionTotal:  8,
		ModelVersionFrozen: 4,
	}}
	wk, sens, pol, spec, _ := emptyOpsFakes()
	r := newAPIOpsRegistry(wk, sens, pol, spec, fp)
	res, _, err := r.Execute(context.Background(), adminPrincipal("api_runtime.read"), uuid.New(), nil,
		"api_posture.get", nil, nil)
	if err != nil {
		t.Fatalf("api_posture.get: %v", err)
	}
	got, ok := res.(*apisecurity.Posture)
	if !ok || got.Endpoints.Total != 9 || got.Findings.OpenTotal != 3 || got.ModelVersionFrozen != 4 {
		t.Errorf("posture = %+v", res)
	}
}
