// Package pipeline 统一防护管线：一次解析 → 分类 → 检测器写 Matches → 统一决策。
// API 动态防护关闭时 Process 直接跳过 API 检测，由调用方继续既有 WAF 路径。
package pipeline

import (
	"fmt"
	"net/http"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/metrics"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
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
	// GRPCMaxFrameBytes gRPC 单帧声明长度上限（发布通道下发 api_grpc_max_frame_bytes；
	// ≤0 用 dsctx.DefaultGRPCMaxFrameBytes 4 MiB 兜底）
	GRPCMaxFrameBytes int
	// GRPCAllowCompression 是否允许 gRPC 压缩帧（发布通道下发 api_grpc_allow_compression；
	// false = 压缩标志位置位产 grpc.unexpected_compression OBSERVE）
	GRPCAllowCompression bool
	// GRPCDescriptors gRPC 描述符注册表（装配层 grpcdesc 编译产物；nil = 无描述符下发，
	// gRPC 处理与 v1 完全一致：仅帧结构校验与计数观测，不做字段级解析）
	GRPCDescriptors *grpcdesc.Registry
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
			detectors.CheckLLM(ctx, parsed, llm, cfg.LLMAllowedModels)
		}
	}

	// 防护模式提前解析（required 约束升级的判定依据；与决策定案同一模式）
	mode := cfg.Mode
	if mode == "" {
		mode = decision.ModeProtect
	}

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
		detectors.CheckCredentialIPSpread(ctx, r, credKey, cfg.IdentitySalt, cfg.CredentialIPSpreadLimit)
		detectors.CheckCredentialConcurrency(ctx, credKey, cfg.CredentialConcurrencyLimit)
		detectors.CheckCredentialUnusualHour(ctx, credKey)
		detectors.CheckCredentialUAChange(ctx, r, credKey)
		// 凭据异常补充（§35：跨应用/多设备窗口计数/URL 明文凭据位置；匿名跳过，
		// OBSERVE 级只 AddMatch；须在 CheckEnvAnomalyStack 之前产出，叠加统计才含新信号）
		detectors.CheckCredentialCrossApp(ctx, credKey, cfg.ApplicationID, cfg.CredentialCrossAppLimit)
		detectors.CheckCredentialDeviceSpread(ctx, r, credKey, cfg.CredentialDeviceSpreadLimit)
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
		if api.IsAPI {
			// 生命周期（依赖 endpoint_key；仅 API 流量，静态路径不参与基线比对）
			detectors.CheckLifecycle(ctx, ek, cfg.KnownEndpoints)
			// 写方法 API 限速信号
			if detectors.IsWriteMethod(parsed.Method) {
				detectors.CheckAPIWriteRate(ctx, tracking, ek, cfg.APIWriteRatePerMinute)
			}
			// 小时/日配额与对象/分页/批量上限（§36；发布通道下发阈值，>0 才启用——
			// 下发配置面当前无对应字段，配置未到不启用，不走引擎默认值冒充已配置）
			if cfg.APIQuotaPerHour > 0 {
				detectors.CheckAPIHourlyQuota(ctx, tracking, ek, cfg.APIQuotaPerHour)
			}
			if cfg.APIQuotaPerDay > 0 {
				detectors.CheckAPIDailyQuota(ctx, tracking, ek, cfg.APIQuotaPerDay)
			}
			if cfg.ObjectRatePerMinute > 0 {
				detectors.CheckObjectRate(ctx, parsed, tracking, ek, cfg.IdentitySalt, cfg.ObjectRatePerMinute)
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
			detectors.EvaluateAuthorization(ctx, parsed, azCfg, cfg.JWTVerification)
		}
		if len(cfg.FieldPermissions) > 0 {
			detectors.CheckFieldPermissions(ctx, cfg.JWTVerification, ek, cfg.FieldPermissions, parsed)
		}
		// 文件合规检测（W13-GW / P2-03 上传方向，任务书 §44 子集）：multipart 文件 part
		// 元数据按下发规则评估（EXT 精确/MIME 前缀/文件名 RE2；BLOCK 动作 PROTECT 升级
		// BLOCK 类可定案 403）；不挂 api.IsAPI 分类门槛——配置了合规规则即表强制意图，
		// 分类漏判不应关掉检测；证据只含文件名/扩展名/MIME/规则不落内容；无下发规则零行为
		if cfg.FileComplianceRules.HasUploadRules() && len(parsed.MultipartParts) > 0 {
			detectors.CheckFileCompliance(ctx, parser.BuildUploadFileObservations(parsed.MultipartParts), cfg.FileComplianceRules, mode)
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
	}

	act := decision.Decide(ctx, decision.Input{Mode: mode, Exceptions: cfg.Exceptions})
	return &Result{
		Context:     ctx,
		Parsed:      parsed,
		API:         api,
		EndpointKey: ek,
		FinalAction: act,
	}, nil
}
