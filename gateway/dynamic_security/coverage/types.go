// Package coverage 执行覆盖账本（NG-COV-01）：按 NG-BASE-02（ADR-0007）§2.2 契约，
// 为 API 管线内各检测器提供 CoverageObservation 的类型定义、五态枚举、
// reason code 注册表与有界非阻断发射器。
//
// 安全不变量：
//   - Observation 永不贡献攻击分数（ADR-2），本包不提供任何评分/动作语义；
//   - 发射失败与队列溢出只记丢弃计数，绝不阻断或降级请求处理；
//   - 热路径零网络 IO：仅内存队列，由装配层异步消费。
package coverage

import "time"

// Status 覆盖五态（契约 §2.2）。
type Status string

const (
	StatusFull          Status = "FULL"           // 声明范围内全部完成（范围必须如实，如仅首帧）
	StatusPartial       Status = "PARTIAL"        // 执行过但存在截断/抽样/未覆盖字段或单侧
	StatusSkipped       Status = "SKIPPED"        // 本应可评估但因关闭/规则选择/能力缺失/依赖未满足未执行
	StatusError         Status = "ERROR"          // 执行异常或结果不可用（不转成 FULL）
	StatusNotApplicable Status = "NOT_APPLICABLE" // 按冻结分类规则确定不适用（不得用来隐藏超限与错误）
)

// Valid 状态合法性校验。
func (s Status) Valid() bool {
	switch s {
	case StatusFull, StatusPartial, StatusSkipped, StatusError, StatusNotApplicable:
		return true
	}
	return false
}

// RequiresReason 该状态是否必须携带 reason code（契约：SKIPPED/ERROR/NOT_APPLICABLE 必填）。
func (s Status) RequiresReason() bool {
	return s == StatusSkipped || s == StatusError || s == StatusNotApplicable
}

// Phase 检查方向（契约 §2.2 phase）。
type Phase string

const (
	PhaseRequest  Phase = "request"
	PhaseResponse Phase = "response"
)

// Valid 方向合法性校验。
func (p Phase) Valid() bool { return p == PhaseRequest || p == PhaseResponse }

// ReasonCode 覆盖原因码（命名空间 COV_*，冻结枚举；新增必须同步注册表与文档）。
type ReasonCode string

const (
	ReasonDisabled              ReasonCode = "COV_DISABLED"               // 功能/检测器被配置关闭
	ReasonRuleUnselected        ReasonCode = "COV_RULE_UNSELECTED"        // 策略未选择该检测器
	ReasonCapabilityMissing     ReasonCode = "COV_CAPABILITY_MISSING"     // 节点能力缺失
	ReasonDependencyUnavailable ReasonCode = "COV_DEPENDENCY_UNAVAILABLE" // 依赖（关系快照/状态存储/描述符）不可用
	ReasonInputTruncated        ReasonCode = "COV_INPUT_TRUNCATED"        // 输入超硬上限被截断
	ReasonParseError            ReasonCode = "COV_PARSE_ERROR"            // 解析异常
	ReasonNAFrozenRule          ReasonCode = "COV_NA_FROZEN_RULE"         // 按冻结分类规则不适用（必须附 NARuleID）
	ReasonUpstreamRejected      ReasonCode = "COV_UPSTREAM_REJECTED"      // 请求已被上游环节（白名单/封禁/CC/Bot/JWT）拒绝
	ReasonPipelineDisabled      ReasonCode = "COV_PIPELINE_DISABLED"      // API 管线整体未启用（模式 OFF/未配置）
	// ---- NG-GRPC G1 grpcguard 专项（D8 五态 SKIPPED 子形态；注册即生效，文档见
	// docs/nextgen/NG-GRPC-g1-unary.md §1.8）----
	ReasonNotGRPC           ReasonCode = "COV_NOT_GRPC"           // 形似 gRPC 但非 unary 候选（非 POST 等判定形态不符）
	ReasonStreamingDegraded ReasonCode = "COV_STREAMING_DEGRADED" // 请求帧序列 >1 条消息（client streaming 降级不覆盖）
	ReasonNoDescriptor      ReasonCode = "COV_NO_DESCRIPTOR"      // 服务未在（绑定）注册表登记（缺描述符不称完整深检）
	ReasonNonProtoCodec     ReasonCode = "COV_NON_PROTO_CODEC"    // application/grpc+ 非 proto 编码变体（+json 等不解码）
	// ---- NG-MCP G1 mcpguard 专项（D12 五态 SKIPPED 子形态；注册即生效，文档见
	// docs/nextgen/NG-MCP-g1-toolcall.md §1.12）----
	ReasonNotMCP           ReasonCode = "COV_NOT_MCP"            // 绑定端点命中但非 MCP 候选（非 POST/非 JSON 族 Content-Type）
	ReasonNoCatalog        ReasonCode = "COV_NO_CATALOG"         // 目录缺失/摘要重算比对不符/装配失败（不消费未验证摘要的目录）
	ReasonNoTrustedSubject ReasonCode = "COV_NO_TRUSTED_SUBJECT" // PROTECT 绑定端点未被 jwt_trust 覆盖（依赖缺席放行+披露）
	// ---- NG-ID G1 machineid 专项（D13：新增注册仅此 1 个，其余全复用存量）----
	ReasonNoRegistry ReasonCode = "COV_NO_REGISTRY" // 机器身份登记册缺席/装配失败（不消费未验证登记册）
)

// validReasons reason code 注册表（唯一事实源；测试枚举全覆盖校验）。
var validReasons = map[ReasonCode]bool{
	ReasonDisabled:              true,
	ReasonRuleUnselected:        true,
	ReasonCapabilityMissing:     true,
	ReasonDependencyUnavailable: true,
	ReasonInputTruncated:        true,
	ReasonParseError:            true,
	ReasonNAFrozenRule:          true,
	ReasonUpstreamRejected:      true,
	ReasonPipelineDisabled:      true,
	ReasonNotGRPC:               true,
	ReasonStreamingDegraded:     true,
	ReasonNoDescriptor:          true,
	ReasonNonProtoCodec:         true,
	ReasonNotMCP:                true,
	ReasonNoCatalog:             true,
	ReasonNoTrustedSubject:      true,
	ReasonNoRegistry:            true,
}

// Valid reason code 合法性校验。
func (r ReasonCode) Valid() bool { return validReasons[r] }

// ScopeDeclared 声明的检查范围（契约 §2.2：仅检查首帧时 messages=1 且 direction 如实）。
type ScopeDeclared struct {
	Bytes     int64    `json:"bytes"`
	Messages  int      `json:"messages"`
	Fields    []string `json:"fields,omitempty"`
	Direction string   `json:"direction"` // request / response / both
}

// Observation 覆盖观测记录（契约 §2.2 CoverageObservation）。
// 该结构独立于攻击 Finding，禁止进入决策评分链路。
type Observation struct {
	RequestID     string        `json:"request_id"`
	ApplicationID string        `json:"application_id"`
	EndpointKey   string        `json:"endpoint_key"`
	Detector      string        `json:"detector"` // 命名空间检测器（如 graphql.cost_v1）
	Phase         Phase         `json:"phase"`
	Scope         ScopeDeclared `json:"scope_declared"`
	Status        Status        `json:"status"`
	ReasonCode    ReasonCode    `json:"reason_code,omitempty"`
	NARuleID      string        `json:"na_rule_id,omitempty"` // NOT_APPLICABLE 时的冻结分类规则 ID（ReasonNAFrozenRule 必填）
	BytesExamined int64         `json:"bytes_examined"`
	Truncated     bool          `json:"truncated"`
	PolicyVersion string        `json:"policy_version"`
	NodeID        string        `json:"node_id"`
	OccurredAt    time.Time     `json:"occurred_at"`
}

// Validate 字段级契约校验：返回首个违规描述，合法返回空串。
// 规则：五态与方向枚举合法；SKIPPED/ERROR/NOT_APPLICABLE 必须带合法 reason；
// NOT_APPLICABLE 的 reason 必须为 COV_NA_FROZEN_RULE 且附 NARuleID；
// PARTIAL 必须有截断或范围不足的证据（truncated 或 bytes_examined<scope.bytes）；
// bytes_examined 不得为负且不得超过声明范围 +1。
func (o Observation) Validate() string {
	if o.RequestID == "" {
		return "request_id 必填"
	}
	if o.Detector == "" {
		return "detector 必填"
	}
	if !o.Phase.Valid() {
		return "phase 非法: " + string(o.Phase)
	}
	if !o.Status.Valid() {
		return "status 非法: " + string(o.Status)
	}
	if o.Status.RequiresReason() && o.ReasonCode == "" {
		return "status=" + string(o.Status) + " 必须携带 reason_code"
	}
	if o.ReasonCode != "" && !o.ReasonCode.Valid() {
		return "reason_code 未注册: " + string(o.ReasonCode)
	}
	if o.Status == StatusNotApplicable {
		if o.ReasonCode != ReasonNAFrozenRule {
			return "NOT_APPLICABLE 的 reason_code 必须为 COV_NA_FROZEN_RULE"
		}
		if o.NARuleID == "" {
			return "NOT_APPLICABLE 必须携带 na_rule_id（冻结分类规则）"
		}
	}
	if o.BytesExamined < 0 {
		return "bytes_examined 不得为负"
	}
	if o.Scope.Bytes >= 0 && o.BytesExamined > o.Scope.Bytes+1 {
		return "bytes_examined 超过声明范围"
	}
	if o.Truncated && o.Status == StatusFull {
		return "截断记录不得标 FULL"
	}
	return ""
}
