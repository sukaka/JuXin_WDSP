// Package pipeline 统一防护管线：一次解析 → 分类 → 检测器写 Matches → 统一决策。
// API 动态防护关闭时 Process 直接跳过 API 检测，由调用方继续既有 WAF 路径。
package pipeline

import (
	"fmt"
	"net/http"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
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
	} else if classifier.ClassifyWebSocket(parsed) {
		// WebSocket 升级握手（RFC 6455）：Upgrade/Connection 双头确认。
		// 仅标注握手；升级后的帧不是 HTTP，不在本管线覆盖范围。
		ctx.SetExtension("api.protocol", "WEBSOCKET")
	} else if classifier.ClassifyGraphQL(parsed) {
		// GraphQL：解析层已双重确认（application/graphql 或 /graphql+JSON query 字段）。
		// 端点键仍按路径归一化——按 operationName 拆端点属更大语义变更，本波不做。
		ctx.SetExtension("api.protocol", "GRAPHQL")
	} else if classifier.ClassifySOAP(parsed) {
		// SOAP：application/soap+xml，或 text/xml|application/xml + SOAPAction 头。
		ctx.SetExtension("api.protocol", "SOAP")
	}
	ctx.SetExtension("api.endpoint_key", ek)

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
		}
		// 授权基线运行时检测（BFLA/字段权限；发布通道下发，仅端点有基线时判定）：
		// 不挂 api.IsAPI 分类门槛——有 confirmed 基线的端点即 API 端点，分类漏判不应关掉授权基线
		if len(cfg.RoleBaselines) > 0 {
			detectors.CheckRoleBaseline(ctx, r, ek, parsed.Method, cfg.RoleBaselines)
		}
		if len(cfg.FieldPermissions) > 0 {
			detectors.CheckFieldPermissions(ctx, r, ek, cfg.FieldPermissions, parsed)
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
