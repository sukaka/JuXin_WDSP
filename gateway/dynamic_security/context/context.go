// Package context 定义 WDSP/阶段8 统一请求上下文（RequestContext）。
// 同一 HTTP 请求只创建一份上下文；检测器只写结论，不直接决定阻断（统一决策在后续波次）。
//
// 数据最小化：不得在上下文中长期保存完整密码、Token、Cookie 明文等高敏感数据。
package context

import (
	"net/netip"
	"sync"
	"time"
)

// FinalAction 统一决策动作（检测器不得擅自执行，仅由决策引擎写入）。
type FinalAction string

const (
	ActionAllow     FinalAction = "ALLOW"
	ActionObserve   FinalAction = "OBSERVE"
	ActionBlock     FinalAction = "BLOCK"
	ActionRateLimit FinalAction = "RATE_LIMIT"
	ActionTempBlock FinalAction = "TEMP_BLOCK"
	ActionMaskResp  FinalAction = "MASK_RESPONSE"
	// ActionChallenge Bot 挑战终止动作（WDSP P1-02 B3 版本化增量；与 jiuzhang_guard
	// disposition.go DisActionChallenge 同词）。仅作枚举增量登记：Bot 挑战在 guard
	// 请求链的 Bot 步骤执行（CC 之后、API 动态防护之前），不经本决策引擎裁决，
	// 不改变既有动作含义；未知该值的旧消费端按原始字符串安全回退。
	ActionChallenge FinalAction = "CHALLENGE"
	ActionUnset     FinalAction = ""
)

// RiskLevel 风险等级。
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// ParseLimits 大报文与结构解析上限（防内存失控）。
type ParseLimits struct {
	MaxBodyParseBytes  int // 完整解析上限
	MaxBodySampleBytes int // 超限采样长度
	MaxJSONDepth       int
	MaxXMLDepth        int
	MaxFieldCount      int
	MaxFileMetaCount   int
	// RetainJSONScalarValues 为 true 时 walkJSON 额外留存标量值（截断 256 字符，
	// 仅请求内存活，供参数约束检测取值；默认 false 零行为变化）
	RetainJSONScalarValues bool
	// RetainFormScalarValues 为 true 时表单解析额外留存标量值（截断 256 字符，
	// 仅请求内存活，供值级敏感检测取值；默认 false 零行为变化）
	RetainFormScalarValues bool
	// MaxGRPCFrameBytes gRPC 单帧声明长度上限（P2-05 帧结构校验；≤0 由
	// DefaultGRPCMaxFrameBytes 兜底，发布通道经 api_grpc_max_frame_bytes 下发覆盖）
	MaxGRPCFrameBytes int
	// ResponseSampleRatio 响应体采样比例（任务书 §7.2，取值 0..1）：
	// 1 = 全量解析（默认，保持现行为）；0 = 不解析响应体；
	// (0,1) 仅对超过 MaxBodyParseBytes 的超大响应生效——确定性截断到
	// ceil(ratio×MaxBodyParseBytes) 字节前缀后尝试解析，前缀非完整 JSON 按
	// 不可解析处理（与请求侧截断体不产出部分 schema 同一纪律）；
	// 非法值（<0 / >1 / NaN / ±Inf）由消费方归一为 1；Guard 配置加载时显式拒绝。
	// 挂点侧通过 api_response_sample_ratio 下发并统一装配，未下发保持默认 1。
	ResponseSampleRatio float64
}

// DefaultGRPCMaxFrameBytes gRPC 单帧声明长度默认上限（4 MiB，与常见 gRPC 服务端
// maxReceiveMessageSize 默认量级对齐；声明超限即 grpc.malformed_frame，不解消息内容）。
const DefaultGRPCMaxFrameBytes = 4 << 20

// DefaultParseLimits 安全默认值。
func DefaultParseLimits() ParseLimits {
	return ParseLimits{
		MaxBodyParseBytes:   1 << 20, // 1 MiB
		MaxBodySampleBytes:  64 << 10,
		MaxJSONDepth:        32,
		MaxXMLDepth:         32,
		MaxFieldCount:       2048,
		MaxFileMetaCount:    64,
		MaxGRPCFrameBytes:   DefaultGRPCMaxFrameBytes,
		ResponseSampleRatio: 1, // §7.2 默认全量解析（保持现行为）
	}
}

// SensitiveFieldHit 响应侧敏感字段命中（证据只含字段路径与数据类型标签，绝不含值）。
type SensitiveFieldHit struct {
	Path     string `json:"path"`
	DataType string `json:"data_type"`
}

// ResponseObservation 响应结构观测（P0-06 响应 Schema 学习生产方）：
// 一级字段路径→类型 + 响应元信息，供管理面按 端点×状态码 合并学习响应 Schema。
// 证据纪律与敏感检测一致：只含字段路径与类型标签，绝不含值；
// 仅 API 流量且捕获到合法 JSON 时产生（截断/流式/非 JSON 不产生）。
type ResponseObservation struct {
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	BodySize    int64  `json:"body_size"`
	// Fields 一级字段路径 → 类型（string/number/bool/object/array/null）；
	// 数组元素形态（users[]）视为一级的一部分，更深层路径（users[].id）不收录。
	Fields map[string]string `json:"fields"`
	// FieldCount 观测到的一级字段总数（截断前；超护栏时大于 len(Fields)）。
	FieldCount int `json:"field_count"`
	// Truncated 字段数/路径长超护栏被截断的说明标记。
	Truncated bool `json:"truncated,omitempty"`
}

// FieldTransform 响应字段级脱敏计划项（由响应相位按 api_mask_rules 与解析产物生成，
// 由 Response Transformer 执行；Algorithm 取值 MASK | HASH | REMOVE | ENCRYPT | MAP）。
type FieldTransform struct {
	FieldPath string `json:"field_path"`          // 点路径，数组段以 [] 结尾（如 users[].phone）
	DataType  string `json:"data_type,omitempty"` // 规则声明的数据类型标签（描述性，不参与匹配）
	Algorithm string `json:"algorithm"`
	KeepHead  int    `json:"keep_head,omitempty"` // MASK：前保留字符数（默认 3）
	KeepTail  int    `json:"keep_tail,omitempty"` // MASK：后保留字符数（默认 4）
	KeyID     string `json:"key_id,omitempty"`    // ENCRYPT：配置的密钥标识（不含密钥材料）
	MapID     string `json:"map_id,omitempty"`    // MAP：映射标识（不含密钥材料）
}

// ResponseContext 响应侧上下文（仅 API 流量在下游响应完成后由响应相位填充）。
// 数据最小化纪律与请求侧一致：不保存响应明文体，解析产物只含字段路径与类型。
type ResponseContext struct {
	Status          int                 `json:"status"`
	ContentType     string              `json:"content_type,omitempty"`
	Headers         map[string]string   `json:"headers,omitempty"` // 已脱敏（set-cookie 等仅标记存在）
	BodySize        int64               `json:"body_size"`         // 捕获/传输字节数（脱敏改写时为改写前大小）
	BodyHash        string              `json:"body_hash,omitempty"`
	Truncated       bool                `json:"truncated,omitempty"` // 体超捕获上限，未完整解析
	Streamed        bool                `json:"streamed,omitempty"`  // 流式/非可安全重编码，未缓冲
	IsJSON          bool                `json:"is_json,omitempty"`
	ParsedBody      map[string]string   `json:"parsed_body,omitempty"` // JSON 字段路径 -> 类型
	SensitiveFields []SensitiveFieldHit `json:"sensitive_fields,omitempty"`
	ErrorSignatures []string            `json:"error_signatures,omitempty"`
	TransformPlan   []FieldTransform    `json:"transform_plan,omitempty"`
	// Observation 响应结构观测（P0-06；仅合法 JSON 解析成功时填充，否则为 nil 零变化）
	Observation *ResponseObservation `json:"observation,omitempty"`
	// FileObservation 文件下载观测（P1-04；仅 Content-Disposition 携带 filename 的
	// 响应由响应相位填充，否则为 nil 零变化；仅元数据不落体）
	FileObservation *FileObservation `json:"file_observation,omitempty"`
}

// ObjectIdentifier 请求对象标识（任务书 §7 object_identifiers）：归一化路径模板的
// 位置参数值与请求体主键字段值的脱敏引用。只记来源/参数名/值哈希，绝不落明文值；
// ValueHash 为 HMAC-SHA256 截断指纹（hex 32 字符，盐来自 identity_salt）。
type ObjectIdentifier struct {
	Source    string `json:"source"`     // path | body_json | body_form
	Param     string `json:"param"`      // 路径占位符名（id/uuid/hex）或 body 字段路径
	ValueHash string `json:"value_hash"` // HMAC 指纹，非明文
}

// MaxObjectIdentifiers 单请求对象标识上限（防超大报文/深路径撑爆上下文与事件体积）。
const MaxObjectIdentifiers = 16

// DetectorMatch 单条检测结论（WAF/API/敏感数据等写入同一列表）。
type DetectorMatch struct {
	Detector   string            `json:"detector"` // waf / api_schema / auth / ...
	RuleID     string            `json:"rule_id,omitempty"`
	Category   string            `json:"category,omitempty"`
	Severity   string            `json:"severity,omitempty"`
	Message    string            `json:"message,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"` // 已脱敏的键值
	ScoreDelta int               `json:"score_delta,omitempty"`
	// Confidence 结论置信度（0-1）：零值由 AddMatch 按检测器保守默认填充；检测器可显式覆盖
	Confidence float64 `json:"confidence,omitempty"`
	// ModelVersion/PolicyVersion 命中时生效的模型/策略版本快照：
	// 零值由 AddMatch 从 RequestContext 快照填充（检测器不感知版本，禁止各自拼装）
	ModelVersion  string `json:"model_version,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`
	// Excepted 被受限例外命中（WDSP P0-04）：证据保留于 Matches，仅取消本次执法贡献；
	// 仅由决策引擎经 MarkMatchExcepted 打标（检测器不得自标），omitempty 保证未打标零变化
	Excepted         bool   `json:"excepted,omitempty"`
	ExceptionID      string `json:"exception_id,omitempty"`
	ExceptionVersion int    `json:"exception_version,omitempty"`
}

// defaultConfidenceByDetector 各检测器置信度保守默认（0-1）。
// 取值纪律：确定性规则（schema/约束/响应事实/凭据存在性）1.0；词表/基线成员判定 0.7-0.8；
// 统计/行为推断 0.5；下游归因（waf）按机制强度 0.8。未列出的检测器回落 0.5（中性，不高估）。
var defaultConfidenceByDetector = map[string]float64{
	"api_schema":      1.0, // 类型/约束违例为确定性判定
	"api_parser":      1.0, // 解析事实（多值/重复键计数为确定性观测）
	"api_response":    1.0, // 响应相位事实（签名/计划/脱敏执行）
	"identity":        1.0, // 凭据存在性事实（不含值）
	"sensitive_data":  0.8, // 字段名词表匹配
	"waf":             0.8, // 下游阻断归因（消息特征匹配，无规则明细）
	"authentication":  0.7, // 凭据格式检查与环境异常推断混合
	"lifecycle":       0.7, // 基线成员判定（基线本身为学习产物）
	"api_ratelimit":   0.7, // 计数阈值判定
	"behavior":        0.5, // 统计基线偏离
	"resource_access": 0.5, // 对象游标启发式
	"api_authz":       0.7, // 基线成员判定（人工确认基线，但角色取自未验签 JWT 声明，保守取值）
	"llm":             0.7, // 词表匹配与名单成员判定（OBSERVE 信号级）
	"grpc":            1.0, // 帧结构事实（5 字节前缀逐帧校验，不解消息内容）
	"api_flow":        0.5, // 会话轨迹重建推断（基线成员为配置事实，但窗口状态为观测近似）
}

// defaultConfidenceFallback 未列出检测器的置信度兜底（中性 0.5，不高估）。
const defaultConfidenceFallback = 0.5

// defaultConfidenceFor 检测器置信度保守默认（显式 Confidence 优先，见 AddMatch）。
func defaultConfidenceFor(detector string) float64 {
	if v, ok := defaultConfidenceByDetector[detector]; ok {
		return v
	}
	return defaultConfidenceFallback
}

// RequestContext 统一请求上下文（请求路径只建一份）。
// 字段按任务书 §7 裁剪为核心可序列化集合；扩展经 Extensions 注册写入。
type RequestContext struct {
	mu sync.RWMutex
	// detectorStoreOverrides 是请求级运行时依赖，不参与事件序列化。具体类型由
	// detectors 包解释；context 包保持底层无依赖，避免形成 import cycle。
	detectorStoreOverrides      any
	detectorStoreOverridesBound bool

	// --- 关联与连接 ---
	RequestID string
	TraceID   string
	// SpanID 本网关段 span id（APM 阶段1 D6 新增；与 TraceID 同源于 guard ServeHTTP 入口，
	// 仅作关联键，不回传客户端、不注入上游）
	SpanID            string
	ConnectionID      string
	ConnectionIP      netip.Addr
	ClientIP          netip.Addr
	TrustedProxyChain []string
	OccurredAt        time.Time

	// --- 应用与请求线 ---
	ApplicationID  string
	DomainID       string
	Domain         string
	Scheme         string
	ProtocolVer    string
	HTTPMethod     string
	RawPath        string
	NormalizedPath string

	// --- API 识别（Wave B 填充）---
	APIEndpointID  string
	APICandidateID string
	APIConfidence  float64 // 0..1

	// --- 内容类型与体量 ---
	RequestContentType  string
	ResponseContentType string
	RequestBodySize     int64
	RequestBodyHash     string // 哈希，非明文
	ResponseStatus      int
	ResponseBodySize    int64
	ResponseBodyHash    string

	// --- 身份指纹（仅指纹，不存明文 Token）---
	AuthenticationType  string
	IdentityFingerprint string
	// IdentityID is the server-side UUID when one is known. Gateway identity
	// resolution intentionally leaves it empty rather than conflating it with
	// the deterministic identity fingerprint.
	IdentityID         string
	IdentityType       string
	IdentityConfidence uint8
	IdentityEvidence   []string
	TokenFingerprint   string
	APIKeyFingerprint  string
	SessionFingerprint string
	TenantFingerprint  string
	// DeviceFingerprint 被动客户端指纹（任务书 §7 device_fingerprint）：UA/Accept 族
	// 请求头的 HMAC 哈希（产出点 parser.DeriveDeviceFingerprint，与 identitybehavior
	// BrowserFingerprint 同口径）。粒度限制：纯被动头部指纹是低熵群体特征——同型号
	// 浏览器+同语言环境的大量客户端共享同一指纹，不是设备唯一标识；不做客户端采集
	// （无 JS/Canvas），不得用作封禁/归因的唯一依据。空 = UA 缺失未计算。
	DeviceFingerprint string
	// ObjectIdentifiers 对象标识哈希集合（任务书 §7 object_identifiers；产出点
	// parser.ExtractObjectIdentifiers；只记哈希不落明文，条数经 SetObjectIdentifiers
	// 封顶 MaxObjectIdentifiers）。空 = 请求未携带可识别对象标识。
	ObjectIdentifiers []ObjectIdentifier

	// --- 解析限制与截断标记 ---
	Limits           ParseLimits
	BodyTruncated    bool
	FieldCountCapped bool

	// --- 检测与决策 ---
	Matches     []DetectorMatch
	RiskScore   int
	RiskLevel   RiskLevel
	FinalAction FinalAction
	EventID     string

	// --- 版本快照（装配层在检测器运行前写入一次；AddMatch 逐条盖章到 DetectorMatch）---
	ModelVersion  string // 命中端点的 FORMAL 模型版本（未下发为空）
	PolicyVersion string // 生效运行时策略版本（未下发为空）

	// Response 响应侧上下文（仅 API 流量、下游响应完成后由响应相位写入一次）
	Response *ResponseContext

	// LLMObservation LLM API 观测（P2-04；仅识别为 LLM 端点的流量由 LLM 检测器写入，
	// 响应相位补全 token 用量；nil = 非 LLM 流量，事件零变化）
	LLMObservation *LLMObservation

	// Extensions 受控扩展（检测器写入前应使用已知键；禁止无界动态膨胀）
	Extensions map[string]any
}

// BindDetectorStoreOverrides 将本次管线的检测器存储选择绑定到请求上下文。
// overrides 可为 nil：bound=true 明确表示使用默认内存，避免回退到进程级兼容注入。
func (c *RequestContext) BindDetectorStoreOverrides(overrides any) {
	if c == nil {
		return
	}
	c.detectorStoreOverrides = overrides
	c.detectorStoreOverridesBound = true
}

// DetectorStoreOverrides 返回请求级检测器存储与是否已由管线显式绑定。
func (c *RequestContext) DetectorStoreOverrides() (overrides any, bound bool) {
	if c == nil {
		return nil, false
	}
	return c.detectorStoreOverrides, c.detectorStoreOverridesBound
}

// SetIdentity sets the normalized identity contract on the request context.
// Evidence is copied because the context may outlive the resolver's scratch
// slice; confidence is always bounded to the documented [0,100] range.
func (c *RequestContext) SetIdentity(identityType string, confidence int, evidence []string) {
	if c == nil {
		return
	}
	if confidence > 100 {
		confidence = 100
	}
	if confidence < 0 {
		confidence = 0
	}
	if identityType == "UNKNOWN" || confidence == 0 {
		confidence = 0
		evidence = nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.IdentityType = identityType
	c.IdentityConfidence = uint8(confidence)
	c.IdentityEvidence = append([]string(nil), evidence...)
}

// SetObjectIdentifiers 写入对象标识集合（任务书 §7 object_identifiers）：
// 拷贝并封顶 MaxObjectIdentifiers（防无界膨胀；调用方保证值已脱敏为哈希）。
// nil/空入参清空为 nil（事件经 omitempty 省略，保持零变化）。
func (c *RequestContext) SetObjectIdentifiers(ids []ObjectIdentifier) {
	if c == nil {
		return
	}
	if len(ids) > MaxObjectIdentifiers {
		ids = ids[:MaxObjectIdentifiers]
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ObjectIdentifiers = append([]ObjectIdentifier(nil), ids...)
}

// CopyObjectIdentifiers 返回 ObjectIdentifiers 副本（事件装配与测试用）。
func (c *RequestContext) CopyObjectIdentifiers() []ObjectIdentifier {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.ObjectIdentifiers) == 0 {
		return nil
	}
	out := make([]ObjectIdentifier, len(c.ObjectIdentifiers))
	copy(out, c.ObjectIdentifiers)
	return out
}

// New 创建上下文；limits 为零值时使用 DefaultParseLimits。
func New(requestID string, limits ParseLimits) *RequestContext {
	if limits.MaxBodyParseBytes <= 0 {
		limits = DefaultParseLimits()
	}
	return &RequestContext{
		RequestID:  requestID,
		OccurredAt: time.Now().UTC(),
		Limits:     limits,
		RiskLevel:  RiskNone,
		Extensions: map[string]any{},
	}
}

// AddMatch 追加检测结论（线程安全）：零值 Confidence 按检测器保守默认填充，
// 零值 ModelVersion/PolicyVersion 从上下文版本快照盖章（显式值优先，不覆盖）。
func (c *RequestContext) AddMatch(m DetectorMatch) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if m.Confidence <= 0 {
		m.Confidence = defaultConfidenceFor(m.Detector)
	}
	if m.ModelVersion == "" {
		m.ModelVersion = c.ModelVersion
	}
	if m.PolicyVersion == "" {
		m.PolicyVersion = c.PolicyVersion
	}
	c.Matches = append(c.Matches, m)
	if m.ScoreDelta != 0 {
		c.RiskScore += m.ScoreDelta
		c.RiskLevel = scoreToLevel(c.RiskScore)
	}
}

// MarkMatchExcepted 将下标 index 的检测明细标记为被受限例外豁免（WDSP P0-04；
// 幂等，线程安全口径与 AddMatch 一致）。detector/ruleID 校验快照未过期（不一致
// 拒绝写回）；已打标明细不覆盖（先入例外优先，重复打标不产生变化）。
// 仅置标记位，不删证据、不回溯 RiskScore（豁免只取消定案贡献，风险分事实保留）。
// 返回本次是否新打标。
func (c *RequestContext) MarkMatchExcepted(index int, detector, ruleID, exceptionID string, exceptionVersion int) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if index < 0 || index >= len(c.Matches) {
		return false
	}
	m := &c.Matches[index]
	if m.Detector != detector || m.RuleID != ruleID {
		return false
	}
	if m.Excepted {
		return false
	}
	m.Excepted = true
	m.ExceptionID = exceptionID
	m.ExceptionVersion = exceptionVersion
	return true
}

// MatchCount 当前检测明细数。
func (c *RequestContext) MatchCount() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.Matches)
}

// CopyMatches 返回 Matches 副本（决策引擎与测试用）。
func (c *RequestContext) CopyMatches() []DetectorMatch {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.Matches) == 0 {
		return nil
	}
	out := make([]DetectorMatch, len(c.Matches))
	copy(out, c.Matches)
	return out
}

// SetFinalAction 仅决策引擎应调用。
func (c *RequestContext) SetFinalAction(a FinalAction) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.FinalAction = a
}

// GetFinalAction 读取最终动作。
func (c *RequestContext) GetFinalAction() FinalAction {
	if c == nil {
		return ActionUnset
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.FinalAction
}

// SetExtension 写入扩展字段（键非空；值由调用方保证可序列化且已脱敏）。
func (c *RequestContext) SetExtension(key string, value any) {
	if c == nil || key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Extensions == nil {
		c.Extensions = map[string]any{}
	}
	c.Extensions[key] = value
}

// GetExtension 读取扩展字段（未写入时 ok=false）。
func (c *RequestContext) GetExtension(key string) (any, bool) {
	if c == nil || key == "" {
		return nil, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.Extensions[key]
	return v, ok
}

// SetResponse 写入响应侧上下文（仅响应相位调用一次）。
func (c *RequestContext) SetResponse(rc *ResponseContext) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Response = rc
}

// GetResponse 读取响应侧上下文（未执行响应相位时为 nil）。
func (c *RequestContext) GetResponse() *ResponseContext {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Response
}

// HasTransformPlan 响应脱敏计划非空（决策引擎 MASK_RESPONSE 分支依据）。
func (c *RequestContext) HasTransformPlan() bool {
	if c == nil {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.Response != nil && len(c.Response.TransformPlan) > 0
}

func scoreToLevel(score int) RiskLevel {
	switch {
	case score >= 80:
		return RiskCritical
	case score >= 50:
		return RiskHigh
	case score >= 25:
		return RiskMedium
	case score > 0:
		return RiskLow
	default:
		return RiskNone
	}
}
