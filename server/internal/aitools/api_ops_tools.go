// api_ops_tools.go API 安全补全第六波（W6-C，P1-02 第一批）：API 域 READ_ONLY Tool 增补
// （设计稿 docs/API_AI_OPERATIONS.md §4.1，后端能力均已就绪，本文件为纯 Tool 层）。
// 五个 Tool：api_weakness.search / api_sensitive.search / api_runtime_policy.get /
// api_spec.get / api_posture.get，全部 READ_ONLY——只调用各域既有只读仓储方法，
// 不触任何写路径（弱点流转、类型编辑、策略发布/回滚、规范导入/激活均不在此暴露）。
// 输出纪律与 api_tools.go 一致：证据类字段经 audits.MaskSensitiveJSON 脱敏。
// 装配 gating：与 NewAPITools 相同，仅 cfg.Product.APIDynamicProtectionEnabled() 时挂接；
// 注册后经既有 aihandlers.SyncRegistry 自动 upsert 进 ai_tools 表（code 唯一，保留启停状态）。
package aitools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/apimodels"
	"github.com/jiuzhang-waf/server/internal/apisecurity"
	"github.com/jiuzhang-waf/server/internal/apiweakness"
	"github.com/jiuzhang-waf/server/internal/audits"
)

// APIWeaknessReader api_weakness.search 的只读依赖（*apiweakness.Store 与 *apiweakness.MemStore 均满足）。
type APIWeaknessReader interface {
	List(ctx context.Context, f apiweakness.ListFilter) ([]apiweakness.Weakness, int64, error)
}

// APISensitiveReader api_sensitive.search 的只读依赖（*apidata.Store 与 *apidata.MemStore 均满足）。
type APISensitiveReader interface {
	ListTypes(ctx context.Context, f apidata.TypeFilter) ([]apidata.SensitiveDataType, int64, error)
}

// APIRuntimePolicyReader api_runtime_policy.get 的只读依赖（*apimodels.Store 满足）。
type APIRuntimePolicyReader interface {
	GetRuntimePolicyByID(ctx context.Context, id uuid.UUID) (*apimodels.RuntimePolicy, error)
	ListRuntimePolicies(ctx context.Context, f apimodels.RuntimePolicyFilter) ([]apimodels.RuntimePolicy, int64, error)
}

// APISpecReader api_spec.get 的只读依赖（*apisecurity.Store 满足）。
type APISpecReader interface {
	ListSpecs(ctx context.Context, name, status string, page, pageSize int) ([]apisecurity.ImportSpec, int64, error)
	GetSpec(ctx context.Context, id uuid.UUID) (*apisecurity.ImportSpec, error)
	ListSpecDiffs(ctx context.Context, specID uuid.UUID) ([]apisecurity.SpecDiff, error)
}

// APIPostureReader api_posture.get 的只读依赖（*apisecurity.Store 满足）。
type APIPostureReader interface {
	GetPosture(ctx context.Context) (*apisecurity.Posture, error)
}

// 编译期保证：生产 SQL Store 与内存实现均满足只读依赖接口（app.go 装配契约）。
var (
	_ APIWeaknessReader      = (*apiweakness.Store)(nil)
	_ APIWeaknessReader      = (*apiweakness.MemStore)(nil)
	_ APISensitiveReader     = (*apidata.Store)(nil)
	_ APISensitiveReader     = (*apidata.MemStore)(nil)
	_ APIRuntimePolicyReader = (*apimodels.Store)(nil)
	_ APISpecReader          = (*apisecurity.Store)(nil)
	_ APIPostureReader       = (*apisecurity.Store)(nil)
)

// 输入枚举白名单（与各域迁移 CHECK 约束口径一致，非法值直接拒绝；
// 弱点 status/severity 复用 apiweakness.IsValidStatus/IsValidSeverity，
// 策略 status 复用 apimodels.ValidPolicyStatus，不再重复建表）。
var (
	apiWeaknessCategoryWhitelist = map[string]bool{
		apiweakness.CategoryAuthn: true, apiweakness.CategoryLifecycle: true,
		apiweakness.CategorySensitive: true, apiweakness.CategorySchema: true,
	}
	apiSensitiveStatusWhitelist = map[string]bool{
		apidata.TypeStatusEnabled: true, apidata.TypeStatusDisabled: true,
	}
	apiSensitiveLevelWhitelist = map[string]bool{
		apidata.LevelNonSensitive: true, apidata.LevelGeneral: true, apidata.LevelSensitive: true,
		apidata.LevelImportant: true, apidata.LevelCore: true,
	}
	apiSpecStatusWhitelist = map[string]bool{
		apisecurity.SpecStatusDraft: true, apisecurity.SpecStatusActive: true,
		apisecurity.SpecStatusHistorical: true, apisecurity.SpecStatusInvalid: true,
		apisecurity.SpecStatusArchived: true,
	}
)

// apiOpsTools P1-02 第一批 Tool 组共享依赖。
type apiOpsTools struct {
	weakness  APIWeaknessReader
	sensitive APISensitiveReader
	policies  APIRuntimePolicyReader
	specs     APISpecReader
	posture   APIPostureReader
}

// NewAPIOpsTools 注册 P1-02 第一批 API 运营 Tool（5 个，全部 READ_ONLY）。
// 仅在 cfg.Product.APIDynamicProtectionEnabled() 为真时由装配侧调用（与 NewAPITools 同一块内）。
func NewAPIOpsTools(r *Registry, weakness APIWeaknessReader, sensitive APISensitiveReader, policies APIRuntimePolicyReader, specs APISpecReader, posture APIPostureReader) {
	g := &apiOpsTools{weakness: weakness, sensitive: sensitive, policies: policies, specs: specs, posture: posture}
	r.Register(&apiWeaknessSearch{baseTool: baseTool{meta: toolMeta{
		code: "api_weakness.search", name: "API弱点搜索", version: "1.0",
		description: "按状态/严重级别/分类搜索API弱点（证据已脱敏），供整改提醒与态势研判",
		risk:        RiskReadOnly, permission: "api_weakness.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"status":      sch("string", "状态 NEW/CONFIRMED/TO_FIX/FIXED/REPRODUCED/IGNORED/ARCHIVED（可选）"),
			"severity":    sch("string", "严重级别 INFO/LOW/MEDIUM/HIGH/CRITICAL（可选）"),
			"category":    sch("string", "分类 AUTHN/LIFECYCLE/SENSITIVE/SCHEMA（可选）"),
			"endpoint_id": sch("string", "接口ID（可选，按接口过滤）"),
			"page":        sch("integer", "页码"),
			"limit":       sch("integer", "每页数量（默认20，上限50）"),
		})}}, g: g})
	r.Register(&apiSensitiveSearch{baseTool: baseTool{meta: toolMeta{
		code: "api_sensitive.search", name: "敏感数据类型搜索", version: "1.0",
		description: "按状态/敏感等级/分类/关键字搜索敏感数据类型定义（识别规则，不含任何样本值）",
		risk:        RiskReadOnly, permission: "api_data.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"status":   sch("string", "状态 ENABLED/DISABLED（可选）"),
			"level":    sch("string", "敏感等级 NON_SENSITIVE/GENERAL/SENSITIVE/IMPORTANT/CORE（可选）"),
			"category": sch("string", "分类（可选，自由文本）"),
			"keyword":  sch("string", "名称关键字（可选，子串匹配）"),
			"page":     sch("integer", "页码"),
			"limit":    sch("integer", "每页数量（默认20，上限50）"),
		})}}, g: g})
	r.Register(&apiRuntimePolicyGet{baseTool: baseTool{meta: toolMeta{
		code: "api_runtime_policy.get", name: "API运行时策略查询", version: "1.0",
		description: "按策略ID获取完整编译策略，或按接口ID列出策略版本摘要（列表不含编译内容）",
		risk:        RiskReadOnly, permission: "api_model.read", timeout: 10, maxResults: 20,
		schema: obj(map[string]interface{}{
			"policy_id":   sch("string", "策略ID（与 endpoint_id 二选一，返回完整编译内容）"),
			"endpoint_id": sch("string", "接口ID（与 policy_id 二选一，列出该接口策略版本摘要）"),
			"status":      sch("string", "策略状态 DRAFT/VALIDATED/PUBLISHED/ACTIVE/ROLLED_BACK/FAILED（可选，仅列表模式生效）"),
			"page":        sch("integer", "页码（仅列表模式）"),
			"limit":       sch("integer", "每页数量（默认20，上限20，仅列表模式）"),
		})}}, g: g})
	r.Register(&apiSpecGet{baseTool: baseTool{meta: toolMeta{
		code: "api_spec.get", name: "API规范查询", version: "1.0",
		description: "按规范ID获取版本详情与运行时对比差异，或按名称/状态列出规范版本（均不含规范原文）",
		risk:        RiskReadOnly, permission: "api_spec.read", timeout: 15, maxResults: 50,
		schema: obj(map[string]interface{}{
			"spec_id": sch("string", "规范版本ID（可选；提供时返回该版本详情与对比差异）"),
			"name":    sch("string", "规范名称（可选，列表模式精确匹配）"),
			"status":  sch("string", "版本状态 DRAFT/ACTIVE/HISTORICAL/INVALID/ARCHIVED（可选，仅列表模式生效）"),
			"page":    sch("integer", "页码（仅列表模式）"),
			"limit":   sch("integer", "每页数量（默认20，上限50，仅列表模式）"),
		})}}, g: g})
	r.Register(&apiPostureGet{baseTool: baseTool{meta: toolMeta{
		code: "api_posture.get", name: "API安全态势", version: "1.0",
		description: "API安全态势聚合：端点资产/学习状态分布、活动风险发现、学习覆盖率与模型冻结率",
		risk:        RiskReadOnly, permission: "api_runtime.read", timeout: 15, maxResults: 1,
		schema: obj(map[string]interface{}{})}}, g: g})
}

// ---------- 1. api_weakness.search ----------

type apiWeaknessSearch struct {
	baseTool
	g *apiOpsTools
}

func (t *apiWeaknessSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	page, limit := pageLimit(m, 20, 50)
	f := apiweakness.ListFilter{Page: page, PageSize: limit}
	if v := strings.ToUpper(StrField(m, "status", 20)); v != "" {
		if !apiweakness.IsValidStatus(v) {
			return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
		}
		f.Status = v
	}
	if v := strings.ToUpper(StrField(m, "severity", 20)); v != "" {
		if !apiweakness.IsValidSeverity(v) {
			return nil, fmt.Errorf("%w: invalid severity", ErrInvalidInput)
		}
		f.Severity = v
	}
	if v := strings.ToUpper(StrField(m, "category", 20)); v != "" {
		if !apiWeaknessCategoryWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid category", ErrInvalidInput)
		}
		f.Category = v
	}
	if v := StrField(m, "endpoint_id", 64); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid endpoint_id", ErrInvalidInput)
		}
		f.EndpointID = &id
	}
	items, total, err := t.g.weakness.List(ctx, f)
	if err != nil {
		return nil, err
	}
	out := []map[string]interface{}{}
	for _, w := range items {
		out = append(out, map[string]interface{}{
			"weakness_id":   w.ID,
			"endpoint_id":   w.EndpointID,
			"endpoint_key":  w.EndpointKey,
			"weakness_code": w.WeaknessCode,
			"weakness_name": w.WeaknessName,
			"category":      w.Category,
			"severity":      w.Severity,
			"status":        w.Status,
			// 证据只含派生摘要（规则/计数/窗口），输出仍按既定纪律再过一道脱敏
			"evidence":      audits.MaskSensitiveJSON(string(w.Evidence)),
			"first_seen_at": w.FirstSeen,
			"last_seen_at":  w.LastSeen,
			"trigger_count": w.TriggerCount,
			"owner":         w.Owner,
			"due_date":      w.DueDate,
		})
	}
	return map[string]interface{}{"total": total, "page": page, "limit": limit, "items": out}, nil
}

// ---------- 2. api_sensitive.search ----------

type apiSensitiveSearch struct {
	baseTool
	g *apiOpsTools
}

func (t *apiSensitiveSearch) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	page, limit := pageLimit(m, 20, 50)
	f := apidata.TypeFilter{Page: page, PageSize: limit}
	if v := strings.ToUpper(StrField(m, "status", 20)); v != "" {
		if !apiSensitiveStatusWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
		}
		f.Status = v
	}
	if v := strings.ToUpper(StrField(m, "level", 20)); v != "" {
		if !apiSensitiveLevelWhitelist[v] {
			return nil, fmt.Errorf("%w: invalid level", ErrInvalidInput)
		}
		f.Level = v
	}
	f.Category = StrField(m, "category", 64)
	f.Keyword = StrField(m, "keyword", 128)
	items, total, err := t.g.sensitive.ListTypes(ctx, f)
	if err != nil {
		return nil, err
	}
	// 类型定义为识别规则（词根/正则/等级），不含任何运行时样本值，无需脱敏
	return map[string]interface{}{"total": total, "page": page, "limit": limit, "items": items}, nil
}

// ---------- 3. api_runtime_policy.get ----------

type apiRuntimePolicyGet struct {
	baseTool
	g *apiOpsTools
}

// policySummary 策略版本摘要（列表模式不带编译内容，控制输出体积）。
func policySummary(p apimodels.RuntimePolicy) map[string]interface{} {
	return map[string]interface{}{
		"policy_id":               p.ID,
		"endpoint_id":             p.EndpointID,
		"endpoint_key":            p.EndpointKey,
		"source_model_version_id": p.SourceModelVersionID,
		"runtime_version":         p.RuntimeVersion,
		"compiler_version":        p.CompilerVersion,
		"content_hash":            p.ContentHash,
		"status":                  p.Status,
		"error":                   p.Error,
		"created_at":              p.CreatedAt,
		"published_at":            p.PublishedAt,
		"activated_at":            p.ActivatedAt,
	}
}

func (t *apiRuntimePolicyGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	policyIDRaw := StrField(m, "policy_id", 64)
	endpointIDRaw := StrField(m, "endpoint_id", 64)
	if policyIDRaw != "" && endpointIDRaw != "" {
		return nil, fmt.Errorf("%w: provide exactly one of policy_id or endpoint_id", ErrInvalidInput)
	}
	status := strings.ToUpper(StrField(m, "status", 20))
	if status != "" && !apimodels.ValidPolicyStatus(status) {
		return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}
	// 详情模式：按策略ID返回完整编译内容（READ_ONLY，内容即 CompiledEndpointPolicy 序列化）
	if policyIDRaw != "" {
		id, err := uuid.Parse(policyIDRaw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid policy_id", ErrInvalidInput)
		}
		p, err := t.g.policies.GetRuntimePolicyByID(ctx, id)
		if errors.Is(err, apimodels.ErrRuntimePolicyNotFound) {
			return nil, fmt.Errorf("runtime policy not found")
		}
		if err != nil {
			return nil, err
		}
		out := policySummary(*p)
		out["content"] = p.Content
		return out, nil
	}
	// 列表模式：按接口ID列出版本摘要（不含编译内容，详情请按 policy_id 再查）
	if endpointIDRaw == "" {
		return nil, fmt.Errorf("%w: provide exactly one of policy_id or endpoint_id", ErrInvalidInput)
	}
	endpointID, err := uuid.Parse(endpointIDRaw)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid endpoint_id", ErrInvalidInput)
	}
	page, limit := pageLimit(m, 20, 20)
	items, total, err := t.g.policies.ListRuntimePolicies(ctx, apimodels.RuntimePolicyFilter{
		EndpointID: &endpointID, Status: status, Page: page, PageSize: limit,
	})
	if err != nil {
		return nil, err
	}
	out := []map[string]interface{}{}
	for _, p := range items {
		out = append(out, policySummary(p))
	}
	return map[string]interface{}{
		"total": total, "page": page, "limit": limit, "items": out,
		"note": "列表不含编译内容（content），按 policy_id 调取完整策略",
	}, nil
}

// ---------- 4. api_spec.get ----------

type apiSpecGet struct {
	baseTool
	g *apiOpsTools
}

// apiSpecDiffsMax 单次返回的规范对比差异上限（超出截断并标记）。
const apiSpecDiffsMax = 200

func (t *apiSpecGet) Run(ctx context.Context, input json.RawMessage) (interface{}, error) {
	var m map[string]interface{}
	if err := Decode(input, &m); err != nil {
		return nil, err
	}
	// 详情模式：按规范版本ID返回版本详情 + 该次导入的运行时对比差异（不含 spec_json 原文）
	if raw := StrField(m, "spec_id", 64); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid spec_id", ErrInvalidInput)
		}
		spec, err := t.g.specs.GetSpec(ctx, id)
		if errors.Is(err, apisecurity.ErrNotFound) {
			return nil, fmt.Errorf("spec not found")
		}
		if err != nil {
			return nil, err
		}
		diffs, err := t.g.specs.ListSpecDiffs(ctx, id)
		if err != nil {
			return nil, err
		}
		truncated := false
		if len(diffs) > apiSpecDiffsMax {
			diffs = diffs[:apiSpecDiffsMax]
			truncated = true
		}
		return map[string]interface{}{
			"spec":            spec,
			"diff_count":      len(diffs),
			"diffs_truncated": truncated,
			"diffs":           diffs,
			"note":            "diff_type 含义：MISSING_IN_RUNTIME 规范有而运行时无 / MISSING_IN_SPEC 运行时有而规范无 / CHANGED 跨版本参数变化；对比仅作解释，AI 不得据此自动登记或下线接口",
		}, nil
	}
	// 列表模式：按名称/状态列出版本（不含 spec_json 原文与差异，差异请按 spec_id 再查）
	status := strings.ToUpper(StrField(m, "status", 20))
	if status != "" && !apiSpecStatusWhitelist[status] {
		return nil, fmt.Errorf("%w: invalid status", ErrInvalidInput)
	}
	page, limit := pageLimit(m, 20, 50)
	items, total, err := t.g.specs.ListSpecs(ctx, StrField(m, "name", 255), status, page, limit)
	if err != nil {
		return nil, err
	}
	return map[string]interface{}{"total": total, "page": page, "limit": limit, "items": items}, nil
}

// ---------- 5. api_posture.get ----------

type apiPostureGet struct {
	baseTool
	g *apiOpsTools
}

func (t *apiPostureGet) Run(ctx context.Context, _ json.RawMessage) (interface{}, error) {
	posture, err := t.g.posture.GetPosture(ctx)
	if err != nil {
		return nil, err
	}
	return posture, nil
}
