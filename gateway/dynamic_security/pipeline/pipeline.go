// Package pipeline 统一防护管线：一次解析 → 分类 → 检测器写 Matches → 统一决策。
// API 动态防护关闭时 Process 直接跳过 API 检测，由调用方继续既有 WAF 路径。
package pipeline

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/grpcguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/metrics"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// Config 管线配置。
type Config struct {
	Enabled bool // API_DYNAMIC_PROTECTION_ENABLED
	Mode    decision.Mode
	Limits  dsctx.ParseLimits
	// FormalSchema 可选：字段名 → 期望类型（冻结模型）；nil 表示不跑偏离
	FormalSchema map[string]string
	// ParamConstraints FORMAL 端点请求侧确认参数约束（发布通道下发）；nil 关闭参数约束检测
	ParamConstraints []detectors.ParamConstraint
	// KnownEndpoints 已知端点基线（endpoint_key → asset_status，发布通道下发）；nil 关闭生命周期检测
	KnownEndpoints map[string]string
	// Admission 本请求所属应用的 API 准入策略（WDSP P1；装配层按 application_id 解析
	// 发布通道 api_admission 段；nil = 应用未识别或无准入策略——不做准入判定直接放行，
	// 与 KnownEndpoints 解析不到应用的现状行为一致）
	Admission *detectors.AdmissionPolicy
	// RoleBaselines 本端点 confirmed 角色功能级基线（装配层按端点解析；发布通道下发 api_role_baselines）；
	// nil/空 = 无端点基线，BFLA 检测零行为（基线缺失不判）
	RoleBaselines []detectors.RoleBaseline
	// FieldPermissions 本端点字段权限（装配层按端点解析；发布通道下发 api_field_permissions）；
	// nil/空 = 无字段权限基线，Mass Assignment 检测零行为
	FieldPermissions []detectors.FieldPermission
	// ParamRelations 本端点已确认参数条件关系（装配层按端点解析；发布通道下发
	// api_parameter_relations，仅管理面 confirmed 行）；nil/空 = 无端点关系，关系检测零行为
	ParamRelations []detectors.ParamRelation
	// FlowBaselines 本端点适用业务流程基线（§44；装配层按命中端点经
	// detectors.GroupFlowBaselines 解析后传入；发布通道下发 api_flow_baselines，
	// 加载前须经 detectors.ValidateFlowBaselines 校验）；nil/空 = 无端点流程基线，
	// 流程偏离检测零行为（基线缺失不判，不编造基线）。全部明细 OBSERVE 级只记录不阻断
	FlowBaselines []detectors.FlowBaseline
	// APIWriteRatePerMinute 写方法 API 每分钟限速（≤0 用 detectors.DefaultAPIWriteRatePerMinute）
	APIWriteRatePerMinute int
	// SensitivePatterns 敏感字段名模式（nil 用内置默认表；编译失败返回错误）
	SensitivePatterns []detectors.SensitivePattern
	// SensitiveValueRules 值级敏感检测规则（发布通道下发 api_sensitive_value_rules；
	// nil 时值级检测与 HEADER/PATH 位置扩展关闭，行为与历史版本一致；编译失败返回错误）
	SensitiveValueRules []detectors.SensitiveValueRule
	// IdentitySalt 身份/来源指纹 HMAC 盐（空 = 未加盐，以固定域分隔前缀代替）
	IdentitySalt string
	// CredentialIPSpreadLimit 同凭据滑窗 distinct IP 阈值（≤0 用 detectors.DefaultCredentialIPSpreadLimit）
	CredentialIPSpreadLimit int
	// CredentialConcurrencyLimit 同凭据并发 in-flight 阈值（≤0 用 detectors.DefaultCredentialConcurrencyLimit）
	CredentialConcurrencyLimit int
	// ApplicationID 本请求所属应用 ID（装配层取自 Guard.AppID；空 = 应用未识别，
	// 凭据跨应用检测跳过——不凭空捏造应用归属）
	ApplicationID string
	// CredentialCrossAppLimit 同凭据滑窗 distinct 应用阈值（≤0 用 detectors.DefaultCredentialCrossAppLimit）
	CredentialCrossAppLimit int
	// CredentialDeviceSpreadLimit 同凭据滑窗 distinct UA 族阈值（≤0 用 detectors.DefaultCredentialDeviceSpreadLimit）
	CredentialDeviceSpreadLimit int
	// SharedDeviceAccountLimit 同应用同设备可信账号观察阈值（非法/零值回退检测器默认值3）
	SharedDeviceAccountLimit int
	// RevokedCredentials 已吊销凭据清单（发布通道下发 api_revoked_credentials，§35 第10项；
	// 装配层经 detectors.ValidateRevokedCredentials 校验后传入）；nil/空 = 无吊销清单，
	// 吊销检测零行为。比对口径：请求凭据键（auth:/key:/sess: + 指纹）与清单
	// credential_type + ":" + fingerprint 全等；expires_at 已过期条目不判定
	RevokedCredentials []detectors.RevokedCredential
	// 配额/对象/分页/批量上限（§36 可行子集）。发布通道已下发（system_settings
	// gateway_runtime 组 api_quota_per_hour/api_quota_per_day/object_rate_per_minute/
	// max_page_size/max_batch_size 五键，迁移 000152 种子）；语义「配置未到 = 不启用」
	// 不变——≤0 时管线不调用对应检测器，不走引擎默认值冒充已配置。
	// APIQuotaPerHour 身份+端点每小时配额（定窗，>0 启用）
	APIQuotaPerHour int
	// APIQuotaPerDay 身份+端点每日配额（UTC 自然日定窗，>0 启用）
	APIQuotaPerDay int
	// ObjectRatePerMinute 同身份对同对象每分钟上限（>0 启用）
	ObjectRatePerMinute int
	// CredentialRatePerMinute 同凭据自然分钟窗口上限（>0 启用；匿名跳过，不回退 IP）
	CredentialRatePerMinute int
	// TenantRatePerMinute 可信 JWT 租户自然分钟窗口上限（>0 启用；未验证/缺 tenant 跳过）
	TenantRatePerMinute int
	// ActionRatePerMinute 应用内操作动作自然分钟窗口上限（>0 启用）
	ActionRatePerMinute int
	// APIEndpointActions 发布下发的 endpoint_key → ACTION 表；未分类端点不猜测、不限速
	APIEndpointActions map[string]string
	// GroupRatePerMinute 应用内业务功能接口组自然分钟窗口上限（>0 启用）
	GroupRatePerMinute int
	// APIEndpointGroups 发布下发的 application_id → endpoint_key → []group_code 嵌套表；
	// 仅当前应用与端点的组参与计数，未分组端点不猜测、不限速
	APIEndpointGroups map[string]map[string][]string
	// RateLimitAction RATE_LIMIT 类处置（空/RATE_LIMIT/BLOCK/TEMP_BLOCK；由决策引擎映射）
	RateLimitAction string
	// MaxPageSize 分页大小上限（>0 启用）
	MaxPageSize int
	// MaxBatchSize 批量数量上限（>0 启用）
	MaxBatchSize int
	// Stores 检测器计数存储覆盖（装配层按 behavior_store 配置注入；nil = 进程内默认内存）。
	// Process 将它绑定到本次请求的上下文，各 Guard 实例互不影响。
	Stores *detectors.StoreOverrides
	// PolicyVersion 生效运行时策略版本戳（发布通道下发；快照进 RequestContext，逐条 Finding 盖章）
	PolicyVersion string
	// ModelVersion 当前端点 FORMAL 模型版本（装配层按端点解析；快照进 RequestContext）
	ModelVersion string
	// ScanVerificationKey 扫描流量识别签名密钥（发布通道下发 api_scan_verification.key_hex 解码；
	// nil/空 = 未下发，仅按 X-JiuZhang-Scan 头存在性识别扫描流量，无法防伪造）
	ScanVerificationKey []byte
	// FileComplianceRules 文件合规规则编译产物（发布通道下发 api_file_compliance_rules；
	// nil/无上传方向规则 = 上传侧合规检测零行为）
	FileComplianceRules *detectors.FileComplianceRuleSet
	// LLMAllowedModels LLM 授权模型名单（发布通道下发 api_llm_allowed_models；
	// nil/空 = 不下发不判定未授权模型，与 LLM 端点识别/观测解耦——识别与观测恒开启）
	LLMAllowedModels []string
	// LLMSecurityPolicy 当前应用的输入、输出与资源预算策略（nil = 保持既有 LLM 观测与规则行为）
	LLMSecurityPolicy *detectors.LLMSecurityPolicy
	// GRPCMaxFrameBytes gRPC 单帧声明长度上限（发布通道下发 api_grpc_max_frame_bytes；
	// ≤0 用 dsctx.DefaultGRPCMaxFrameBytes 4 MiB 兜底）
	GRPCMaxFrameBytes int
	// GRPCAllowCompression 是否允许 gRPC 压缩帧（发布通道下发 api_grpc_allow_compression；
	// false = 压缩标志位置位产 grpc.unexpected_compression OBSERVE）
	GRPCAllowCompression bool
	// GRPCDescriptors gRPC 描述符注册表（装配层 grpcdesc 编译产物；nil = 无描述符下发，
	// gRPC 处理与 v1 完全一致：仅帧结构校验与计数观测，不做字段级解析）
	GRPCDescriptors *grpcdesc.Registry
	// GRPCGuard G1 unary 深检执行配置（NG-GRPC 批次 B2；装配层 buildGRPCGuardConfig
	// 产物；nil = 无描述符且无绑定，grpcguard 零行为 NG-T-C01——与现状 grpc/grpc_desc
	// 观测并行共存，既有观测键形不变）
	GRPCGuard *grpcguard.Config
	// GRPCBody gRPC 帧源（装配层保全的完整请求体——G1 协议专属读取预算，不经公共
	// 1MiB 解析上限（§1.2）；nil/空 = 体不可得，读取器零消息如实处理）
	GRPCBody []byte
	// Exceptions 本请求适用的受限例外规则引用（WDSP P0-04；装配层经
	// jiuzhang_guard FilterAPIExceptions 按应用/域名/路径/方法/可信 IP/有效期完成
	// 范围筛选后传入；nil 与空切片等价，零行为变化。命中 Finding 保留证据并打标
	// Excepted，其 ScoreDelta 与执法类别从本次定案排除后按既有优先级重算——
	// 契约 S4_DESIGN_BASELINE §6/§10）
	Exceptions []decision.ExceptionRef
	// Authorization is the independent, confirmed AUTHZ-01 model snapshot.
	// JWTVerification must come from the completed local trust-chain verifier.
	Authorization   detectors.AuthorizationConfig
	JWTVerification *jwtverify.VerificationResult
	// Coverage 执行覆盖观测发射器（NG-COV-01）：nil = 关闭，零行为变化零开销；
	// 仅由装配层在覆盖功能启用时接入。观测永不贡献攻击分（ADR-2）。
	Coverage *coverage.Emitter
	// NodeName 网关节点名（GATEWAY_NODE_NAME；覆盖观测 node_id；空 = 未命名节点）
	NodeName string
	// GraphQL 成本预算策略（NG-GQL-03；发布通道下发 api_graphql 段按应用解析；
	// nil/Enabled=false = 关闭，GraphQL 流量与历史版本零行为变化）
	GraphQL *GraphQLPolicy
	// StrongFlows 本端点命中的强流程步骤绑定（NG-FLOW-02；装配层按 endpoint_key
	// 归组后传入；发布通道下发 api_strong_flows，加载前须经 flowguard.BuildRegistry
	// 校验）；nil/空 = 无端点强流程定义，强流程检测零行为（NG-T-C01）。
	// 与 FlowBaselines（观察态七类信号）并行共存互不消费。
	StrongFlows []flowguard.BoundStep
	// StrongFlowRuntime 强流程运行时（Valkey 原子域 + 实例引用 HMAC 密钥；
	// nil = 未下发定义，零行为。Valkey/密钥缺席不置 nil——D8 恒 UNKNOWN 放行+披露
	// 语义的承载在 Runtime 内部，严禁本地内存回退）
	StrongFlowRuntime *flowguard.Runtime
	// MCPGuard MCP 工具调用执行配置（NG-MCP G1 批次 B2；装配层 buildMCPGuardConfig
	// 产物；nil = 无目录且无绑定，mcpguard 零行为 NG-T-C01——与现状启发式
	// llm.mcp_* 观测并行共存，键形不变）
	MCPGuard *mcpguard.Config
	// MCPBody MCP 候选请求体（装配层保全的完整请求体——§1.10 协议专属预算
	// （≤4MiB 保全同源），不经公共 1MiB 解析上限与 256 字符截留；nil/空 =
	// 体不可得，ParseMessage 按形态不可判定 SKIPPED 如实）
	MCPBody []byte
	// BodyPreserveSkipped 挂点层请求体超过保全上限（>4MiB）或读取失败，仅保留元数据进入管线。
	BodyPreserveSkipped bool
	// BodyPreserveSkipReason 请求体未保全的原因标识（用于 request.body_preserve_skipped 明细）。
	BodyPreserveSkipReason string
	// BodyInspectionFailClosed 响应/大报文失败策略为 FAIL_CLOSED 时，截断或未保全请求体在
	// PROTECT 下执行 413 fail-closed 拦截而非静默跳过。
	BodyInspectionFailClosed bool
}

// Result 管线输出。
type Result struct {
	Context     *dsctx.RequestContext
	Parsed      *parser.Parsed
	API         classifier.Result
	EndpointKey string
	FinalAction dsctx.FinalAction
	Skipped     bool // API 管线关闭
}

// Process 执行统一管线。enabled=false 时返回 Skipped=true，不设置 final action（由遗留 WAF 负责）。
func Process(r *http.Request, cfg Config, externalMatches []dsctx.DetectorMatch) (*Result, error) {
	if !cfg.Enabled {
		cfg.emitCov(coverage.Observation{
			RequestID:  requestIDOf(r),
			Detector:   "pipeline",
			Phase:      coverage.PhaseRequest,
			Scope:      coverage.ScopeDeclared{Messages: 1, Direction: "request"},
			Status:     coverage.StatusSkipped,
			ReasonCode: coverage.ReasonPipelineDisabled,
		})
		return &Result{Skipped: true}, nil
	}
	limits := cfg.Limits
	if limits.MaxBodyParseBytes <= 0 {
		limits = dsctx.DefaultParseLimits()
	}
	// gRPC 单帧声明长度上限（发布通道下发覆盖；≤0 由 limits 默认值/引擎兜底）
	if cfg.GRPCMaxFrameBytes > 0 {
		limits.MaxGRPCFrameBytes = cfg.GRPCMaxFrameBytes
	}
	// 参数约束检测与值观测均需要 BODY 标量值（截断留存，仅请求内存活；不入事件明文）
	// API 动态防护开启时统一保留，供 CollectParamObservations 与 CheckParamConstraints 使用。
	limits.RetainJSONScalarValues = true
	// 值级敏感检测需要 FORM 标量值留存（仅配置了值级规则时开启，无规则零变化）
	if len(cfg.SensitiveValueRules) > 0 {
		limits.RetainFormScalarValues = true
	}
	reqID := ""
	if r != nil {
		reqID = r.Header.Get("X-Request-Id")
		if reqID == "" {
			reqID = r.Header.Get("X-Jiuzhang-Request-ID")
		}
	}
	ctx := dsctx.New(reqID, limits)
	ctx.BindDetectorStoreOverrides(cfg.Stores)
	// 版本快照须在检测器运行前写入：AddMatch 逐条 Finding 盖章 model_version/policy_version
	ctx.ModelVersion = cfg.ModelVersion
	ctx.PolicyVersion = cfg.PolicyVersion
	parsed, err := parser.ParseRequest(r, ctx)
	if err != nil {
		return nil, err
	}
	if cfg.BodyPreserveSkipped {
		if parsed != nil {
			parsed.BodyTruncated = true
		}
		ctx.BodyTruncated = true
		evidence := map[string]string{"reason": cfg.BodyPreserveSkipReason}
		if r != nil && r.ContentLength >= 0 {
			evidence["content_length"] = strconv.FormatInt(r.ContentLength, 10)
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "api_request",
			RuleID:     "request.body_preserve_skipped",
			Category:   "OBSERVE",
			Severity:   "HIGH",
			Message:    "api request body exceeds preserve limit or read failed: metadata-only inspection performed",
			Confidence: 1.0,
			Evidence:   evidence,
		})
	}
	// §7 标识字段在管线内落 ctx（device_fingerprint/object_identifiers）：请求相位检测器
	// 自此可读（对象维度限速直接消费 ctx.ObjectIdentifiers）；产出为 parser 纯函数、
	// 与挂点侧 enrichContextIdentifiers 同口径同盐，仅空值写入——挂点侧幂等回填不覆盖
	if r != nil && ctx.DeviceFingerprint == "" {
		ctx.DeviceFingerprint = parser.DeriveDeviceFingerprint(cfg.IdentitySalt, r.Header)
	}
	if parsed != nil && len(ctx.ObjectIdentifiers) == 0 {
		ctx.SetObjectIdentifiers(parser.ExtractObjectIdentifiers(parsed, cfg.IdentitySalt))
	}
	// external (WAF/guard) matches only recorded — never finalize here
	for _, m := range externalMatches {
		ctx.AddMatch(m)
	}
	api := classifier.Classify(parsed)
	ctx.APIConfidence = api.Confidence
	if api.IsAPI {
		ctx.SetExtension("api.is_api", true)
		ctx.SetExtension("api.signals", api.Signals)
	}
	// §8.2 四级识别标签 + 0-100 置信度（与 IsAPI/Confidence 同源同分，仅量纲/粒度不同；
	// 扩展留存供事件与端点发现链路消费，不参与决策）
	ctx.SetExtension("api.classification", api.Level)
	ctx.SetExtension("api.confidence100", api.Confidence100)
	// 值级敏感规则编译产物（gRPC 描述符扫描与下方 CheckSensitiveData/CheckMCP 共享；
	// 编译经 detectors 并发安全缓存：同一配置装配期单次编译，热路径为缓存查找；
	// 发布通道下发，编译失败为配置错误如实返回，不静默吞错）
	var valueRules []detectors.CompiledSensitiveValueRule
	valueRulesReady := false
	// gRPC 流量识别（W14-GW / P2-05 首批）：Content-Type + 路径形态双重确认；
	// 不挂 api.IsAPI 分类门槛（gRPC 二进制体在 JSON 信号驱动的分类下天然低分，
	// 分类漏判不应关掉帧校验）。端点键路径全保留——服务/方法名即端点稳定身份，
	// 归一化会破坏方法名语义；protocol=GRPC 打标进事件与端点发现（装配层透传）。
	// W14-DESC / P2-05 深化：有描述符注册表下发时随 CheckGRPC 做字段级解析
	// （解码失败降级为 v1 观测不报错）；无注册表时行为与 v1 完全一致。
	grpcRes := classifier.ClassifyGRPC(parsed)
	ek := normalizer.EndpointKey(parsed.Method, parsed.RawPath)
	if grpcRes.IsGRPC {
		ek = normalizer.EndpointKeyPreserve(parsed.Method, parsed.RawPath)
		ctx.SetExtension("api.protocol", "GRPC")
		var scan *detectors.GRPCDescriptorScan
		if cfg.GRPCDescriptors != nil {
			vr, err := detectors.CompileSensitiveValueRules(cfg.SensitiveValueRules)
			if err != nil {
				return nil, fmt.Errorf("compile sensitive value rules: %w", err)
			}
			valueRules, valueRulesReady = vr, true
			scan = &detectors.GRPCDescriptorScan{
				Registry:   cfg.GRPCDescriptors,
				Service:    grpcRes.Service,
				Method:     grpcRes.Method,
				ValueRules: vr,
			}
		}
		detectors.CheckGRPC(ctx, parsed, cfg.GRPCAllowCompression, scan)
		// G1 unary 深检执行（NG-GRPC 批次 B2，grpcguard 检测器：绑定消费/结构校验/
		// 协议化执行/覆盖五态；既有 grpc/grpc_desc 观测不变并行共存。识别为 gRPC
		// 即进入——非 POST/codec 变体/streaming/缺描述符等形态由 grpcguard 内部分类
		// 为 SKIPPED 五态如实覆盖；nil 配置零行为 NG-T-C01；双闸实断经 category=BLOCK
		// 明细走统一决策，apiprotect 按 api.protocol=GRPC 分流 trailers-only）
		if cfg.GRPCGuard != nil {
			// 引擎 PROTECT 判定内联（mode 变量在下方统一解析——同一兜底链：
			// 缺省 PROTECT；本段位于其前故就地求值，语义一致）
			engineProtect := cfg.Mode == decision.ModeProtect || cfg.Mode == ""
			if cov := grpcguard.Evaluate(ctx, parsed, grpcRes, cfg.GRPCBody, cfg.GRPCGuard, cfg.ApplicationID, engineProtect); cov != nil {
				cov.EndpointKey = ek
				cfg.emitCov(*cov)
			}
		}
	} else if proto := classifier.ClassifyProtocol(parsed, api.IsAPI); proto != "" {
		// 协议类型打标（任务书 §9 词表，13 值）：逐值判定规则见 classifier.ClassifyProtocol；
		// 结构性协议（WEBSOCKET_HANDSHAKE/GRAPHQL/SOAP/RPC/SSE/文件传输/WEBHOOK）不挂
		// api.IsAPI 分类门槛（分类漏判不应关掉协议标注）；通用 REST 族仅 API 分类命中时
		// 打标，非 API 普通 Web 流量不带扩展（采集端缺省 REST 口径，事件零变化）。
		ctx.SetExtension("api.protocol", proto)
	}
	ctx.SetExtension("api.endpoint_key", ek)

	// 检测耗时埋点（§54 进程内指标：覆盖下方检测段全程含统一决策，错误路径同样计入；
	// 与 parser 解析耗时埋点同一 Track 模式，热路径零网络 IO）
	defer metrics.Track(metrics.DetectDuration)()

	// 扫描流量识别（W9-GW）：X-JiuZhang-Scan 头签名校验/存在性打标；
	// 不挂 api.IsAPI 分类门槛（扫描探针目标即 API 端点，分类漏判不应关掉识别）。
	// 消费者：管理面学习样本排除规则（apiruntime/samples.go：details 含
	// detector=scanner 明细即排除，「扫描流量不进学习/不进行为基线」）与事件打标。
	detectors.CheckScannerSignal(ctx, r, cfg.ScanVerificationKey)

	// LLM API 端点识别与请求侧观测（W10-LLM / P2-04）：路径词表+内容形态双重确认，
	// 不挂 api.IsAPI 分类门槛（LLM 端点识别保守精确，分类漏判不应关掉观测）；
	// 识别后产出 llm_observation（响应相位补全 token 用量），并跑注入词表/未授权模型判定。
	// 识别结果留存 llmRes：MCP 内容级检测在值级敏感规则编译后统一执行（见下方 CheckMCP）。
	var llmRes classifier.LLMResult
	if parsed != nil {
		if llm := classifier.ClassifyLLM(parsed); llm.IsLLM {
			llmRes = llm
			ctx.SetExtension("api.llm_kind", string(llm.Kind))
			detectors.CheckLLMWithPolicy(ctx, parsed, llm, cfg.LLMAllowedModels, cfg.LLMSecurityPolicy)
		}
	}

	// 防护模式提前解析（required 约束升级的判定依据；与决策定案同一模式）
	mode := cfg.Mode
	if mode == "" {
		mode = decision.ModeProtect
	}

	// API 准入判定（WDSP P1，api_admission 发布段，设计 §4.1）：仅 API 分类流量
	// （§4.3 决策点 4：页面/静态资源不受准入），在检测段最前执行——集合查找 O(1)。
	// PROTECT 命中（BLOCK 类 finding 已写入上下文）时短路后续全部重检测器直达统一决策
	// （早退优化：准入拒绝下 schema/模型/行为等重计算无意义；finding/事件/定案照常产出）。
	// OBSERVE 命中不短路：观测 finding 与后续检测器并存，学习期需要完整信号。
	var admissionOutcome detectors.AdmissionOutcome
	if api.IsAPI && cfg.Admission != nil {
		admissionOutcome = detectors.CheckAdmission(ctx, ek, *cfg.Admission, cfg.KnownEndpoints)
	}
	if admissionOutcome.ProtectDenied {
		act := decision.Decide(ctx, decision.Input{Mode: mode, RateLimitAction: cfg.RateLimitAction, Exceptions: cfg.Exceptions})
		cfg.emitCov(cfg.covScopeRecord(ctx, parsed, ek))
		return &Result{
			Context:     ctx,
			Parsed:      parsed,
			API:         api,
			EndpointKey: ek,
			FinalAction: act,
		}, nil
	}

	// GraphQL 成本预算（NG-GQL-03，api_graphql 发布段）：Admission 之后、决策之前——
	// 结构准入（五道硬边界/操作选择）→ 可信文档直通 → 单请求成本 → 时间窗预算；
	// 仅 GraphQL 分类请求进入（非 GraphQL 直返零开销）；策略 nil/disabled 零行为变化。
	cfg.checkGraphQL(ctx, r, parsed, mode, ek)

	// schema deviation against formal model
	if cfg.FormalSchema != nil && parsed != nil {
		detectors.CheckSchemaDeviation(ctx, parsed.JSONFields, cfg.FormalSchema)
	}
	// 解析歧义（阶段2 Parser Detector：重复 JSON 键/多值 query/header/form 重复键）：
	// 解析层已登记即检测，不挂任何下发配置门槛；OBSERVE 级（api_parser 非可信阻断源，
	// PROTECT 下也仅定案观测）
	if parsed != nil {
		detectors.CheckParserAmbiguity(ctx, parsed)
	}
	// 参数级确认约束（QUERY/HEADER/BODY；required 违例按模式定类别）
	if len(cfg.ParamConstraints) > 0 && parsed != nil {
		detectors.CheckParamConstraints(ctx, parsed, cfg.ParamConstraints, mode)
	}
	// 参数条件关系（W11-REL：REQUIRES/MUTEX 违例按模式定类别；CO_OCCURS 仅 INFO 观察）
	if len(cfg.ParamRelations) > 0 && parsed != nil {
		detectors.CheckParamRelations(ctx, parsed, cfg.ParamRelations, mode)
	}
	// identity fingerprint (presence only)
	if parsed != nil {
		detectors.CheckIdentitySignals(ctx, parsed)
	}

	// 追加检测器（只 AddMatch，统一由 decision 定案）
	// 追踪键：凭据指纹优先、无凭据回退 IP——只做滑窗/游标计数维度，不充当身份
	tracking := detectors.TrackingKey(r, cfg.IdentitySalt)
	if parsed != nil {
		// 认证有效性（scheme/格式/弱凭据；凭据值不入证据）
		detectors.CheckAuthentication(ctx, r, api.IsAPI)
		// 同凭据环境异常（跨 IP / 并发 / 时段 / UA；匿名跳过，OBSERVE 级不定案）
		credKey := detectors.CredentialKey(r, cfg.IdentitySalt)
		if cfg.CredentialRatePerMinute > 0 {
			detectors.CheckCredentialRate(ctx, credKey, cfg.CredentialRatePerMinute)
		}
		if cfg.TenantRatePerMinute > 0 {
			detectors.CheckTenantRate(ctx, cfg.JWTVerification, cfg.IdentitySalt, cfg.TenantRatePerMinute)
		}
		detectors.CheckCredentialIPSpread(ctx, r, credKey, cfg.IdentitySalt, cfg.CredentialIPSpreadLimit)
		detectors.CheckCredentialConcurrency(ctx, credKey, cfg.CredentialConcurrencyLimit)
		detectors.CheckCredentialUnusualHour(ctx, credKey)
		detectors.CheckCredentialUAChange(ctx, r, credKey)
		// 凭据异常补充（§35：跨应用/多设备窗口计数/URL 明文凭据位置；匿名跳过，
		// OBSERVE 级只 AddMatch；须在 CheckEnvAnomalyStack 之前产出，叠加统计才含新信号）
		detectors.CheckCredentialCrossApp(ctx, credKey, cfg.ApplicationID, cfg.CredentialCrossAppLimit)
		detectors.CheckCredentialDeviceSpread(ctx, r, credKey, cfg.CredentialDeviceSpreadLimit)
		detectors.CheckSharedDeviceAccountsWithLimit(ctx, cfg.JWTVerification, cfg.ApplicationID, cfg.SharedDeviceAccountLimit)
		detectors.CheckCredentialLocationAnomaly(ctx, r)
		// 已吊销凭据使用（§35 第10项；发布通道下发清单，nil/空零行为，匿名跳过；
		// 集合查找 O(1)，过期条目自行失效；索引编译失败为配置错误如实返回，不静默吞错；
		// OBSERVE 级只 AddMatch，须在 CheckEnvAnomalyStack 之前产出）
		if len(cfg.RevokedCredentials) > 0 {
			revokedIdx, err := detectors.IndexRevokedCredentials(cfg.RevokedCredentials)
			if err != nil {
				return nil, fmt.Errorf("index revoked credentials: %w", err)
			}
			detectors.CheckCredentialRevoked(ctx, credKey, revokedIdx, time.Now())
		}
		detectors.CheckEnvAnomalyStack(ctx)
		// 敏感字段名（编译经 detectors 并发安全缓存，热路径为缓存查找；
		// 自定义模式编译失败为配置错误，不静默吞错）
		patterns, err := detectors.CompileSensitivePatterns(cfg.SensitivePatterns)
		if err != nil {
			return nil, fmt.Errorf("compile sensitive patterns: %w", err)
		}
		// 值级敏感规则（发布通道下发；编译失败为配置错误，不静默吞错；
		// gRPC 描述符扫描已编译时复用同一产物，缓存命中零重复编译）
		if !valueRulesReady {
			vr, err := detectors.CompileSensitiveValueRules(cfg.SensitiveValueRules)
			if err != nil {
				return nil, fmt.Errorf("compile sensitive value rules: %w", err)
			}
			valueRules = vr
		}
		detectors.CheckSensitiveData(ctx, parsed, patterns, valueRules)
		// WP1-A：凭据传输弱点（URL 明文密码与敏感 Cookie 名），请求值只用于内存判定，不落事件
		detectors.CheckCredentialTransport(ctx, r, parsed, mode)
		// MCP 内容级检测（W12-GW / P2-04 续，任务书 §154）：method 词表核对 +
		// tools/call 参数值敏感检测 + mcp_method 观测扩展；复用上方值级敏感规则
		// 同一编译产物（单次编译，不重跑）；非 MCP 端点零行为
		if llmRes.Kind == classifier.LLMKindMCP {
			detectors.CheckMCP(ctx, parsed, valueRules)
		}
		// 对象级访问辅助（BOLA/BFLA 前置信号；BODY 经 semantic_type 联动）；
		// 端点键传管线统一口径 ek（gRPC 为 EndpointKeyPreserve），游标键不再内部重算
		semIDs := detectors.SemanticIDPathsFromConstraints(cfg.ParamConstraints)
		detectors.CheckResourceAccess(ctx, parsed, tracking, ek, semIDs)
		// WP1-B：可信身份 + 明确对象模板 + 时间窗对象集合；只产 OBSERVE，不替代 BOLA 权属判定。
		// 应用 ID 进入窗口和 HMAC 域，避免同主体同路径模板在不同应用间串计数。
		detectors.CheckObjectEnumeration(ctx, parsed, cfg.JWTVerification, cfg.IdentitySalt, cfg.ApplicationID+"\x00"+ek, semIDs)
		if api.IsAPI {
			// 生命周期（依赖 endpoint_key；仅 API 流量，静态路径不参与基线比对）；
			// 准入已判 unknown（端点不在基线）时跳过 new_endpoint——两者同语义且 server 侧
			// OBSERVE 期同映射 SHADOW finding，并存即重复（去重策略：准入覆盖后 lifecycle 跳过；
			// deprecated_api_call 语义不同，不受 UnknownCovered 影响照常判定）
			if !admissionOutcome.UnknownCovered {
				detectors.CheckLifecycle(ctx, ek, cfg.KnownEndpoints)
			}
			// 写方法 API 限速信号
			if detectors.IsWriteMethod(parsed.Method) {
				detectors.CheckAPIWriteRate(ctx, tracking, ek, cfg.APIWriteRatePerMinute)
			}
			// 小时/日配额与对象/动作/接口组/分页/批量上限（发布通道下发阈值，>0 才启用，
			// 配置未到不启用，不走引擎默认值冒充已配置）。
			if cfg.APIQuotaPerHour > 0 {
				detectors.CheckAPIHourlyQuota(ctx, tracking, ek, cfg.APIQuotaPerHour)
			}
			if cfg.APIQuotaPerDay > 0 {
				detectors.CheckAPIDailyQuota(ctx, tracking, ek, cfg.APIQuotaPerDay)
			}
			if cfg.ObjectRatePerMinute > 0 {
				detectors.CheckObjectRate(ctx, parsed, credKey, ek, cfg.IdentitySalt, cfg.ObjectRatePerMinute)
			}
			if cfg.ActionRatePerMinute > 0 {
				detectors.CheckActionRate(ctx, cfg.ApplicationID, cfg.APIEndpointActions[ek], cfg.ActionRatePerMinute)
			}
			if cfg.GroupRatePerMinute > 0 {
				for _, groupCode := range cfg.APIEndpointGroups[cfg.ApplicationID][ek] {
					detectors.CheckGroupRate(ctx, cfg.ApplicationID, groupCode, cfg.GroupRatePerMinute)
				}
			}
			if cfg.MaxPageSize > 0 {
				detectors.CheckPaginationSize(ctx, parsed, cfg.MaxPageSize)
			}
			if cfg.MaxBatchSize > 0 {
				detectors.CheckBatchSize(ctx, parsed, cfg.MaxBatchSize)
			}
		}
		// 授权基线运行时检测（BFLA/字段权限；发布通道下发，仅端点有基线时判定）：
		// 不挂 api.IsAPI 分类门槛——有 confirmed 基线的端点即 API 端点，分类漏判不应关掉授权基线
		if len(cfg.RoleBaselines) > 0 {
			detectors.CheckRoleBaseline(ctx, r, ek, parsed.Method, cfg.RoleBaselines)
		}
		if len(cfg.Authorization.Models) > 0 || len(cfg.Authorization.RoleBaselines) > 0 {
			azCfg := cfg.Authorization
			if azCfg.EndpointKey == "" {
				azCfg.EndpointKey = ek
			}
			// NG-AZ-03 §1.1：决策引擎 PROTECT 语义下行（VERIFIED_VIOLATION 双闸
			// 之一；OBSERVE 模式下资格全真也降级 OBSERVE_VIOLATION 同语义记录，
			// 不实断——与 decision.Decide 的 BLOCK→OBSERVE 降级链双重兜底）
			azCfg.EngineProtect = mode == decision.ModeProtect
			detectors.EvaluateAuthorization(ctx, parsed, azCfg, cfg.JWTVerification)
		}
		if len(cfg.FieldPermissions) > 0 {
			detectors.CheckFieldPermissions(ctx, cfg.JWTVerification, ek, cfg.FieldPermissions, parsed)
		}
		// 强流程原子预留与违规判定（NG-FLOW-02，api_strong_flows 发布段；API 管线内、
		// 授权评估之后——实例键可信主体分量消费 JWT VERIFIED 信号，与 authz 同一信任序）。
		// 检测器 flowguard 产决策组（ALLOW/VIOLATION/UNKNOWN + reason 词表）：
		// 定义级 OBSERVE（缺省）只记录；PROTECT 且引擎 PROTECT 双闸全真时违规
		// Category=BLOCK 可定案 403（统一 JSON 不泄露实例细节）；UNKNOWN 恒不阻断
		// （Valkey 故障/密钥缺席/证据不足 → 放行+dependency_unavailable 披露，
		// D8 严禁本地内存回退）。不挂 api.IsAPI 分类门槛——配置了定义即表强制意图，
		// 分类漏判不应关掉强流程判定；nil 绑定/Runtime = 零行为（NG-T-C01）
		if len(cfg.StrongFlows) > 0 && cfg.StrongFlowRuntime != nil {
			flowguard.Evaluate(ctx, r, parsed, ek, cfg.StrongFlows, cfg.StrongFlowRuntime, cfg.JWTVerification, tracking, mode == decision.ModeProtect)
		}
		// MCP G1 tools/call 转发前检查链（NG-MCP 批次 B2，mcpguard 检测器：绑定驱动
		// 识别（api_mcp_bindings endpoint_path 精确匹配）→ 候选判定 → 预算内全量解析
		// → 固定序检查链（可信主体/白名单/ACL/Schema/范围/预算/高风险）；双闸实断经
		// category=BLOCK 明细走统一决策，apiprotect 按 mcp_error_code 分流 JSON-RPC
		// 错误对象；UNKNOWN 恒不阻断（目录缺失/解析失败/Schema 降级/jwt 未覆盖全
		// SKIPPED 五态如实）。绑定缺失 = 零行为 NG-T-C01，现状 llm.mcp_* 观测并行不动）
		if cfg.MCPGuard != nil && parsed != nil && r != nil && r.URL != nil {
			if scoped := cfg.MCPGuard.ForEndpoint(cfg.ApplicationID, normalizer.CanonicalPath(r.URL.Path)); scoped != nil {
				engineProtect := mode == decision.ModeProtect
				if candidate, cov := mcpguard.EvaluateCandidate(ctx, parsed, r, scoped, cfg.ApplicationID); cov != nil {
					cov.EndpointKey = ek
					cfg.emitCov(*cov)
				} else if candidate {
					mcpguard.NoteHeadObservations(ctx, r.Header.Get, scoped)
					if cfg.BodyPreserveSkipped {
						budgets := mcprpc.DefaultBudgets()
						actual := budgets.MaxMessageBytes + 1
						if r != nil && r.ContentLength > int64(actual) {
							actual = int(r.ContentLength)
						}
						be := &mcprpc.BudgetError{Rule: "message_bytes", Limit: budgets.MaxMessageBytes, Actual: actual}
						if cov := mcpguard.HandleParseError(ctx, be, scoped, cfg.ApplicationID, engineProtect, actual); cov != nil {
							cov.EndpointKey = ek
							cfg.emitCov(*cov)
						}
					} else {
						msg, perr := mcprpc.ParseMessage(cfg.MCPBody, mcprpc.DefaultBudgets())
						if perr != nil {
							if cov := mcpguard.HandleParseError(ctx, perr, scoped, cfg.ApplicationID, engineProtect, len(cfg.MCPBody)); cov != nil {
								cov.EndpointKey = ek
								cfg.emitCov(*cov)
							}
						} else if cov := mcpguard.Evaluate(ctx, msg, scoped, cfg.JWTVerification, cfg.ApplicationID, engineProtect); cov != nil {
							cov.EndpointKey = ek
							cfg.emitCov(*cov)
						}
					}
				}
			}
		}
		// 文件合规检测（W13-GW / P2-03 上传方向，任务书 §44 子集）：multipart 文件 part
		// 元数据按下发规则评估（EXT 精确/MIME 前缀/文件名 RE2；BLOCK 动作 PROTECT 升级
		// BLOCK 类可定案 403）；不挂 api.IsAPI 分类门槛——配置了合规规则即表强制意图，
		// 分类漏判不应关掉检测；证据只含文件名/扩展名/MIME/规则不落内容；无下发规则零行为
		if cfg.FileComplianceRules.HasUploadRules() && len(parsed.MultipartParts) > 0 {
			detectors.CheckFileCompliance(ctx, parser.BuildUploadFileObservations(parsed.MultipartParts), cfg.FileComplianceRules, mode)
			// WP2-B：只消费 multipart 有界前缀，截断或 part 数溢出明确披露，不扫描整个上传体。
			detectors.CheckUploadFileContentTypes(ctx, parsed.MultipartParts, parsed.MultipartCapped, cfg.FileComplianceRules)
		}
		// WP2-C：仅 file 位置的值级规则启用文本敏感内容检测，类型标签回写文件观测。
		if len(cfg.SensitiveValueRules) > 0 && len(parsed.MultipartParts) > 0 {
			fileValueRules, err := detectors.CompileSensitiveValueRules(cfg.SensitiveValueRules)
			if err != nil {
				return nil, fmt.Errorf("compile file sensitive value rules: %w", err)
			}
			detectors.CheckUploadFileSensitiveContent(ctx, parsed.MultipartParts, parsed.MultipartCapped, fileValueRules)
		}
		// 行为基线（tracking+endpoint 进程内滑窗）
		detectors.CheckBehavior(ctx, tracking, ek)
		// 业务流程偏离（§44 首批四类：跳过前置/重复提交/逆序/非法状态转换；
		// 发布通道下发流程基线，nil/空零行为；全部 OBSERVE 级只 AddMatch 不定案；
		// 不挂 api.IsAPI 分类门槛——配置了流程基线即表观测意图，分类漏判不应关掉检测。
		// 会话键含主体指纹+流程标识（流程绑定端点集合），须随行为检测同段执行以共享 tracking）
		if len(cfg.FlowBaselines) > 0 {
			detectors.CheckFlowDeviation(ctx, r, tracking, ek, cfg.IdentitySalt, cfg.FlowBaselines)
		}
		// C-10：当请求体超过解析上限（>1MiB）或保全上限（>4MiB）被截断时，若本端点存在依赖请求体的
		// PROTECT 策略（Schema / Body 参数约束 / 请求侧字段权限 / LLM PROTECT）或全局 FAIL_CLOSED，
		// 在 PROTECT 模式下执行 fail-closed 413 阻断，禁止通过超大请求体静默绕过体级检测。
		if parsed.BodyTruncated && mode == decision.ModeProtect {
			if reason := cfg.truncatedBodyFailClosedReason(parsed, llmRes); reason != "" {
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector:   "api_schema",
					RuleID:     "request.body_too_large_fail_closed",
					Category:   "BLOCK",
					Severity:   "HIGH",
					Confidence: 1.0,
					Message:    "request body exceeds inspection limit under fail-closed or body-dependent PROTECT policy",
					Evidence: map[string]string{
						"endpoint_key": ek,
						"http_status":  "413",
						"reason":       reason,
					},
				})
			}
		}
	}

	act := decision.Decide(ctx, decision.Input{Mode: mode, RateLimitAction: cfg.RateLimitAction, Exceptions: cfg.Exceptions})
	cfg.emitCov(cfg.covScopeRecord(ctx, parsed, ek))
	return &Result{
		Context:     ctx,
		Parsed:      parsed,
		API:         api,
		EndpointKey: ek,
		FinalAction: act,
	}, nil
}

// truncatedBodyFailClosedReason 判断截断/未保全请求体在 PROTECT 模式下是否必须 fail-closed 413 拒收。
func (cfg *Config) truncatedBodyFailClosedReason(parsed *parser.Parsed, llmRes classifier.LLMResult) string {
	if len(cfg.FormalSchema) > 0 {
		return "schema_protect"
	}
	for _, pc := range cfg.ParamConstraints {
		loc := strings.ToUpper(strings.TrimSpace(pc.Location))
		if loc == "BODY" || loc == "JSON" || loc == "FORM" {
			return "body_param_constraint_protect"
		}
	}
	for _, fp := range cfg.FieldPermissions {
		if fp.Direction != "" && !strings.EqualFold(fp.Direction, "REQUEST") {
			continue
		}
		switch strings.ToUpper(strings.TrimSpace(fp.Attribute)) {
		case "FORBIDDEN", "READ_ONLY", "SERVER_GENERATED", "ADMIN_WRITABLE":
			return "forbidden_field_protect"
		}
	}
	if cfg.LLMSecurityPolicy != nil && strings.EqualFold(cfg.LLMSecurityPolicy.Mode, detectors.LLMSecurityProtect) {
		if llmRes.IsLLM || classifier.IsLLMCandidatePath(parsed) {
			return "llm_protect"
		}
	}
	if cfg.BodyInspectionFailClosed {
		return "fail_closed_policy"
	}
	return ""
}

// emitCov 发射覆盖观测（NG-COV-01）：cfg.Coverage 为 nil 时零开销直返；
// 应用/策略版本/节点字段缺省从管线配置回填。观测失败只记丢弃，绝不阻断请求。
func (cfg *Config) emitCov(o coverage.Observation) {
	if cfg.Coverage == nil {
		return
	}
	if o.ApplicationID == "" {
		o.ApplicationID = cfg.ApplicationID
	}
	if o.PolicyVersion == "" {
		o.PolicyVersion = cfg.PolicyVersion
	}
	if o.NodeID == "" {
		o.NodeID = cfg.NodeName
	}
	cfg.Coverage.Emit(o)
}

// covScopeRecord 管线成功处理后的范围记账：体截断时如实 PARTIAL+COV_INPUT_TRUNCATED，
// 否则 FULL（范围为本次实际检查字节与消息数，不夸大）。
func (cfg *Config) covScopeRecord(ctx *dsctx.RequestContext, parsed *parser.Parsed, ek string) coverage.Observation {
	o := coverage.Observation{
		RequestID: ctx.RequestID,
		Detector:  "pipeline",
		Phase:     coverage.PhaseRequest,
		Status:    coverage.StatusFull,
		Scope:     coverage.ScopeDeclared{Messages: 1, Direction: "request"},
	}
	if parsed != nil {
		o.Scope.Bytes = int64(parsed.BodySize)
		o.BytesExamined = int64(parsed.BodySize)
		if parsed.BodyTruncated {
			o.Status = coverage.StatusPartial
			o.ReasonCode = coverage.ReasonInputTruncated
			o.Truncated = true
		}
	}
	o.EndpointKey = ek
	return o
}

// requestIDOf 提取请求关联号（与 Process 主路径同口径）。
func requestIDOf(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Header.Get("X-Request-Id"); v != "" {
		return v
	}
	return r.Header.Get("X-Jiuzhang-Request-ID")
}
