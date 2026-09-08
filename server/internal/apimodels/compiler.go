// compiler.go Runtime Model Compiler（P0-03 补全）：
// 输入 FORMAL 模型版本（schema_json + confirmed 参数约束 + 端点信息），
// 输出端点级运行时策略 CompiledEndpointPolicy（api_runtime_policies.content_json）。
// 编译器为纯函数：同输入恒得同输出（content_hash 稳定），不触库、不依赖时间，可独立单测。
package apimodels

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// CompilerVersion 编译器版本常量：编译输出结构或词汇变化时递增，
// 落库 api_runtime_policies.compiler_version，用于区分历史产物与定位回归。
const CompilerVersion = "v1"

// CompileInput 编译输入（FORMAL 模型版本快照 + 端点信息 + 该版本确认参数行）。
type CompileInput struct {
	EndpointID     uuid.UUID
	EndpointKey    string // endpoint_key（METHOD + 归一化路径）
	Method         string // api_endpoints.http_method
	NormalizedPath string // api_endpoints.normalized_path
	ProtocolType   string // api_endpoints.protocol_type（REST → content_type=application/json）
	AssetStatus    string // api_endpoints.asset_status → lifecycle 字段
	// 来源模型版本（必须为 FORMAL；由调用方在 Confirm 事务内保证）
	ModelVersionID     uuid.UUID
	ModelVersionNumber int
	Schema             map[string]string // schema_json（字段路径 → 期望类型）
	Parameters         []Parameter       // 该版本 REQUEST 方向参数行（含 confirmed 词汇）
}

// CompiledParamConstraint 单参数编译约束（全量 confirmed 词汇；
// 词汇超集于发布通道 GuardParamConstraint，nullable/empty_allowed 等由网关侧逐步消费）。
type CompiledParamConstraint struct {
	Location         string         `json:"location"`                    // QUERY / HEADER / BODY / PATH / COOKIE
	Name             string         `json:"name"`                        // 参数名（QUERY/HEADER 键名；BODY 末段名）
	Path             string         `json:"path"`                        // 结构化路径（BODY 点路径）
	BaseType         string         `json:"base_type"`                   // string|number|bool|object|array|null
	SemanticType     string         `json:"semantic_type,omitempty"`     // 语义类型（供对象标识联动）
	Required         bool           `json:"required"`                    // 必填
	Nullable         bool           `json:"nullable"`                    // 允许 null
	EmptyAllowed     bool           `json:"empty_allowed"`               // 允许空串/空值
	SensitivityLevel string         `json:"sensitivity_level,omitempty"` // 敏感级别
	Constraints      map[string]any `json:"constraints"`                 // confirmed_constraints 原样（min_length/max_length/minimum/maximum/enum 等）
}

// CompiledEndpointPolicy 端点级运行时策略编译产物（content_json 结构）。
// 字段序列化序固定 + map 键序由 encoding/json 排序，保证规范序列化确定（content_hash 稳定）。
type CompiledEndpointPolicy struct {
	EndpointKey              string                    `json:"endpoint_key"`
	Method                   string                    `json:"method"`
	NormalizedPath           string                    `json:"normalized_path"`
	ContentType              string                    `json:"content_type"` // 请求体协议；空串 = 不约束
	Lifecycle                string                    `json:"lifecycle"`    // 端点资产生命周期（asset_status 快照）
	SourceModelVersionID     uuid.UUID                 `json:"source_model_version_id"`
	SourceModelVersionNumber int                       `json:"source_model_version_number"`
	CompilerVersion          string                    `json:"compiler_version"`
	RequestSchema            map[string]string         `json:"request_schema"`        // 请求体字段 → 期望类型
	ParameterConstraints     []CompiledParamConstraint `json:"parameter_constraints"` // 全量 confirmed 词汇（确定性排序）
	// auth_requirement 预留占位（P0-15/16 认证/授权基线另一波补全），本波恒为 null。
	AuthRequirement any `json:"auth_requirement"`
	// response_schema 预留占位（P0-06 响应模型另一波补全），本波恒为 null。
	ResponseSchema any `json:"response_schema"`
}

// deriveContentType 由端点协议类型推导请求体 content_type：
// REST（含空值缺省）与 GRAPHQL（over HTTP 主体即 JSON）按 JSON 学习 → application/json；
// 其余协议（GRPC/SOAP/WEBSOCKET 等）本波不约束（空串）。
func deriveContentType(protocolType string) string {
	switch strings.ToUpper(strings.TrimSpace(protocolType)) {
	case "", "REST", "GRAPHQL":
		return "application/json"
	default:
		return ""
	}
}

// Compile 编译 FORMAL 模型版本为端点级运行时策略（纯函数）。
// 参数约束输出按 (location, path, name) 排序，map 键序由序列化层排序，
// 同输入恒得同 content_hash；任一输入字段变化产生新 hash。
func Compile(in CompileInput) (*CompiledEndpointPolicy, error) {
	schema := map[string]string{}
	for k, v := range in.Schema {
		schema[k] = v
	}
	params := make([]CompiledParamConstraint, 0, len(in.Parameters))
	for _, p := range in.Parameters {
		constraints := map[string]any{}
		for k, v := range p.ConfirmedConstraints {
			constraints[k] = v
		}
		params = append(params, CompiledParamConstraint{
			Location:         p.Location,
			Name:             p.ParameterName,
			Path:             p.StructuredPath,
			BaseType:         p.BaseType,
			SemanticType:     p.SemanticType,
			Required:         p.Required,
			Nullable:         p.Nullable,
			EmptyAllowed:     p.EmptyAllowed,
			SensitivityLevel: p.SensitivityLevel,
			Constraints:      constraints,
		})
	}
	sort.Slice(params, func(i, j int) bool {
		if params[i].Location != params[j].Location {
			return params[i].Location < params[j].Location
		}
		if params[i].Path != params[j].Path {
			return params[i].Path < params[j].Path
		}
		return params[i].Name < params[j].Name
	})
	return &CompiledEndpointPolicy{
		EndpointKey:              in.EndpointKey,
		Method:                   strings.ToUpper(strings.TrimSpace(in.Method)),
		NormalizedPath:           in.NormalizedPath,
		ContentType:              deriveContentType(in.ProtocolType),
		Lifecycle:                in.AssetStatus,
		SourceModelVersionID:     in.ModelVersionID,
		SourceModelVersionNumber: in.ModelVersionNumber,
		CompilerVersion:          CompilerVersion,
		RequestSchema:            schema,
		ParameterConstraints:     params,
		AuthRequirement:          nil, // 预留占位（P0-15/16）
		ResponseSchema:           nil, // 预留占位（P0-06）
	}, nil
}

// CanonicalJSON 规范序列化：结构体字段序固定 + map 键序由 encoding/json 排序，
// 输出确定字节流（content_hash 的输入）。
func CanonicalJSON(v any) ([]byte, error) {
	return json.Marshal(v)
}

// ContentHash 计算编译产物内容哈希（规范序列化的 sha256 hex）。
func ContentHash(policy *CompiledEndpointPolicy) (string, []byte, error) {
	raw, err := CanonicalJSON(policy)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), raw, nil
}
