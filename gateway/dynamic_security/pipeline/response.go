package pipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/metrics"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

// ResponseInput 响应相位输入（由挂点侧的响应捕获提供）。
type ResponseInput struct {
	Status      int
	ContentType string
	// ContentDisposition 原始 Content-Disposition 头值（未截断未脱敏；仅用于文件下载
	// 观测提取，原始值只在请求内存活、不落事件——观测落库的 FileName 仍截断 128）。
	// 挂点侧响应头快照按 256 字节截断值，超长 Content-Disposition 经快照解析必然失败
	// （下载合规 BLOCK 与 OOXML 水印门禁随之静默失效），故必须传原始值；
	// 为空时回退 Headers 快照（兼容未传原始值的挂点，快照截断场景观测仍可能缺失）。
	ContentDisposition string
	Headers            map[string]string // 已脱敏快照（可为 nil）
	Body               []byte            // 捕获体（流式未缓冲为 nil；截断时为已捕获前缀）
	BodySize           int64             // 实际传输字节数
	Truncated          bool              // 体超捕获上限（未完整捕获，禁止解析与改写）
	Streamed           bool              // 流式/非可安全重编码直通（未缓冲）
}

// ResponseConfig 响应相位配置。
type ResponseConfig struct {
	Mode   decision.Mode
	Limits dsctx.ParseLimits
	// MaskRules 当前端点的响应脱敏规则（挂点侧按 endpoint_key 选取；nil 关闭计划生成）
	MaskRules []response.MaskRule
	// SensitivePatterns 敏感字段名模式（nil 用 detectors 内置默认表；编译失败返回错误）
	SensitivePatterns []detectors.SensitivePattern
	// ResponseBaselines 本端点响应结构基线（挂点侧按 endpoint_key 选取；
	// 发布通道下发 api_response_baselines，sample_count≥20 学习行）；
	// nil/空 = 无端点基线，响应偏离检测零行为（基线缺失不判）
	ResponseBaselines []detectors.ResponseBaseline
	// EndpointKey 本端点键（挂点侧按请求归一化结果传入；响应侧字段权限证据用）
	EndpointKey string
	// FieldPermissions 本端点字段权限（挂点侧按 endpoint_key 选取；发布通道下发
	// api_field_permissions）；本相位仅消费 direction=RESPONSE 行，
	// nil/空 = 响应侧字段权限检测零行为（基线缺失不判）
	FieldPermissions []detectors.FieldPermission
	// RequestRoles 请求角色集（挂点侧复用 detectors.ExtractRequestRoles 提取；
	// nil = 匿名或无角色声明，仅默认行参与响应侧判定）
	RequestRoles []string
	// FileComplianceRules 文件合规规则编译产物（发布通道下发 api_file_compliance_rules；
	// nil/无下载方向规则 = 下载侧合规检测零行为）
	FileComplianceRules *detectors.FileComplianceRuleSet
	// Request 原请求（webshell C2 会话行为检测响应评估需要请求方法门槛与会话 URI 同源取值；
	// nil = 该检测零行为）
	Request *http.Request
	// Identity 身份追踪键（挂点侧复用 detectors.TrackingKey 提取，与请求相位同一取值口径；
	// 空 = webshell C2 响应评估零行为）
	Identity string
}

// 响应侧单事件敏感字段命中上限（与请求侧 maxSensitiveMatches 对齐，防超大报文撑爆事件）。
const maxResponseSensitiveFindings = 20

// ProcessResponse 统一引擎响应相位（仅 API 流量、下游响应完成后调用一次）：
//  1. JSON 解析（非 JSON / 截断 / 流式跳过，解析失败按非 JSON 处理），
//     成功后提取响应结构观测（一级字段路径+类型，P0-06 学习生产方，不落值）；
//  2. 响应敏感字段检测（复用 detectors 词表做字段名匹配，证据不含值）；
//  3. 错误签名提取（5xx / 堆栈与数据库错误特征）；
//  4. transform plan 生成（端点脱敏规则 ∩ 解析产物，仅可执行项）；
//  5. 响应方向字段权限判定（RESPONSE 方向 FORBIDDEN/SENSITIVE 行；与脱敏计划/敏感检测去重）；
//  6. 统一决策（计划非空且 PROTECT → MASK_RESPONSE；OBSERVE 仅记录）。
//
// 检测结论一律经 AddMatch 写入同一 RequestContext（随主事件输出），动作只由 decision 定案。
func ProcessResponse(ctx *dsctx.RequestContext, in ResponseInput, cfg ResponseConfig) (dsctx.FinalAction, error) {
	if ctx == nil {
		return dsctx.ActionAllow, nil
	}
	rc := &dsctx.ResponseContext{
		Status:      in.Status,
		ContentType: in.ContentType,
		Headers:     in.Headers,
		BodySize:    in.BodySize,
		Truncated:   in.Truncated,
		Streamed:    in.Streamed,
	}
	if len(in.Body) > 0 {
		sum := sha256.Sum256(in.Body)
		rc.BodyHash = hex.EncodeToString(sum[:8]) // 哈希，非明文
	}
	ctx.SetResponse(rc)

	limits := cfg.Limits
	if limits.MaxBodyParseBytes <= 0 {
		limits = dsctx.DefaultParseLimits()
	}

	// §7.2 响应体采样比例归一：有效区间 [0,1]，非法值（<0 / >1 / NaN）归一为 1
	// （全量解析，保持现行为）；0 = 不解析响应体（IsJSON 保持 false，下游敏感字段/
	// transform plan/结构观测自然零行为，与非 JSON 同口径；错误签名与体哈希不受影响）。
	sampleRatio := limits.ResponseSampleRatio
	if sampleRatio < 0 || sampleRatio > 1 || math.IsNaN(sampleRatio) {
		sampleRatio = 1
	}

	// 防护模式提前解析（文件合规 BLOCK 动作升级的判定依据；与决策定案同一模式）
	mode := cfg.Mode
	if mode == "" {
		mode = decision.ModeProtect
	}

	// 1. JSON 解析（仅完整捕获的 JSON 族响应；截断/流式无法安全解析与改写）
	// jsonRoot 复用首次解析产物，供 LLM 观测窄提取（任务书原则 2.1：同一响应只解析一次）
	var jsonRoot any
	if !in.Truncated && !in.Streamed && len(in.Body) > 0 && sampleRatio > 0 && response.IsJSONContentType(in.ContentType, in.Body) {
		// §7.2 超大响应采样：比例 <1 且体长超 MaxBodyParseBytes 时，确定性截断到
		// ceil(ratio×MaxBodyParseBytes) 字节前缀再解析（有界、可重现；前缀非完整
		// JSON 则按不可解析处理，不产出部分 schema——与请求侧截断体同一纪律）；
		// 体长未超限时全量解析，非超大响应不受采样比例影响。
		parseBody := in.Body
		if sampleRatio < 1 && len(in.Body) > limits.MaxBodyParseBytes {
			budget := int(math.Ceil(sampleRatio * float64(limits.MaxBodyParseBytes)))
			if budget < len(parseBody) {
				parseBody = parseBody[:budget]
			}
		}
		parseDone := metrics.Track(metrics.ResponseParseDuration) // §54 响应解析耗时埋点（仅真实解析时计入）
		fields, root, isJSON := response.ParseJSON(parseBody, limits)
		rc.IsJSON = isJSON
		if isJSON {
			rc.ParsedBody = fields
			jsonRoot = root
			// 1b. 响应结构观测（P0-06 学习生产方）：一级字段路径+类型，护栏内截断；
			// 只含路径与类型不落值，随主事件 response_observations 上报
			rc.Observation = response.BuildObservation(in.Status, in.ContentType, in.BodySize, fields)
		}
		parseDone()
	}

	// 1c. 文件下载观测（P1-04 文件资产生产方）：Content-Disposition 携带 filename 的
	// 响应记一条 DOWNLOAD 观测（仅元数据不落体；流式直通同样可观测——头与字节数可用）；
	// 观测取原始头值（快照 256 字节截断会使超长 Content-Disposition 解析失败、观测缺失），
	// 挂点未供原始值时回退已脱敏快照（兼容口径）；无 filename 响应不产出，事件保持零变化
	cd := in.ContentDisposition
	if cd == "" {
		cd = in.Headers["content-disposition"]
	}
	ct := in.ContentType
	if ct == "" {
		ct = in.Headers["content-type"]
	}
	if fo := response.BuildDownloadFileObservation(cd, ct, in.BodySize); fo != nil {
		rc.FileObservation = fo
		// §9 词表 FILE_DOWNLOAD 响应侧升级：Content-Disposition 携带 filename 的附件
		// 下载是强信号，优先于请求相位按请求形态打的通用 REST 族/UNKNOWN 标签；
		// 已落结构性协议（GRAPHQL/SOAP/RPC/SSE/WS/GRPC 等）时不覆盖。
		if cur, _ := ctx.GetExtension("api.protocol"); cur == nil || classifier.IsGenericProtocol(cur) {
			ctx.SetExtension("api.protocol", classifier.ProtocolFileDownload)
		}
	}

	// 1d. 文件合规检测（W13-GW / P2-03 下载方向，任务书 §44 子集）：Content-Disposition
	// 下载观测按下发规则评估（BLOCK 动作 PROTECT 升级 BLOCK 类——挂点侧据最终动作将
	// 已缓冲下载响应抑制为 403；已直通/溢出的无法撤回，诚实降级见挂点侧注释）；
	// 证据只含文件名/扩展名/MIME/规则不落内容；无下载观测/无下载方向规则零行为
	if rc.FileObservation != nil && cfg.FileComplianceRules.HasDownloadRules() {
		detectors.CheckFileCompliance(ctx, []dsctx.FileObservation{*rc.FileObservation}, cfg.FileComplianceRules, mode)
	}

	// 1e. 响应偏离检测（W9-GW，任务书 §64 UNKNOWN_RESPONSE/UNKNOWN_STATUS 侧）：
	// 端点有下发基线时比对状态码与一级字段（新字段/字段缺失/未见状态码）；
	// 证据只含字段路径与状态码不落值；无基线下发时零行为
	if len(cfg.ResponseBaselines) > 0 {
		detectors.CheckResponseDeviation(ctx, in.Status, rc.IsJSON, rc.ParsedBody, cfg.ResponseBaselines)
	}

	// 1f. LLM 观测响应侧补全（W10-LLM / P2-04）：仅请求相位已识别 LLM 端点
	// （观测存在）时生效；补 model/usage.total_tokens（OpenAI 兼容字段，缺失容忍）、
	// SSE/流式响应标记 stream；非 LLM 流量零行为
	detectors.EnrichLLMResponse(ctx, in.ContentType, in.Body, in.Truncated, in.Streamed, jsonRoot)

	// 1g. webshell C2 会话行为检测（BAS 覆盖基线，响应收束评估）：请求相位已记账的会话
	// 在此累计响应侧统计并评估四组弱特征（≥3 组命中产 webshell.c2_suspected
	// OBSERVE/MEDIUM，ScoreDelta 20 < 50 定案线，绝不单独定案阻断）；不挂 api.IsAPI
	// 分类门槛（本相位天然仅 API 流量到达，分类漏判由挂点侧路径约束，无需重复判定）；
	// 挂点侧未供给原请求/身份时零行为
	checkWebShellC2Response(ctx, in, cfg)

	// 2. 响应敏感字段检测（字段名匹配，证据只含路径与数据类型标签）
	if len(rc.ParsedBody) > 0 {
		// 编译经 detectors 并发安全缓存：同一配置装配期单次编译，响应相位为缓存查找
		patterns, err := detectors.CompileSensitivePatterns(cfg.SensitivePatterns)
		if err != nil {
			return "", fmt.Errorf("compile sensitive patterns: %w", err)
		}
		paths := make([]string, 0, len(rc.ParsedBody))
		for p := range rc.ParsedBody {
			paths = append(paths, p)
		}
		sort.Strings(paths) // 确定性顺序（事件可重现）
		n := 0
		for _, p := range paths {
			if n >= maxResponseSensitiveFindings {
				break
			}
			typ, ok := detectors.MatchSensitiveDataType(p, patterns)
			if !ok {
				continue
			}
			rc.SensitiveFields = append(rc.SensitiveFields, dsctx.SensitiveFieldHit{Path: p, DataType: typ})
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "sensitive_data",
				RuleID:   "sensitive.response_field",
				Category: "OBSERVE",
				Severity: "MEDIUM",
				Message:  "sensitive field name observed in response body",
				Evidence: map[string]string{
					"field":     p,
					"data_type": typ,
					"location":  "response_json",
					"direction": "RESPONSE",
				},
				ScoreDelta: 10,
			})
			n++
		}
	}

	// 3. 错误签名（5xx / 堆栈特征；证据只含签名标签与状态码）
	sigs := response.ExtractErrorSignatures(in.Status, in.Body)
	rc.ErrorSignatures = sigs
	if len(sigs) > 0 {
		sev := "LOW"
		if in.Status >= 500 && in.Status < 600 {
			sev = "MEDIUM"
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "api_response",
			RuleID:   "response.error_signature",
			Category: "OBSERVE",
			Severity: sev,
			Message:  "response error signature observed",
			Evidence: map[string]string{
				"signatures": strings.Join(sigs, ","),
				"status":     strconv.Itoa(in.Status),
			},
			ScoreDelta: 5,
		})
	}

	// 4. transform plan（仅完整 JSON 可安全改写；截断/流式由挂点侧按失败策略处理）
	if rc.IsJSON && len(cfg.MaskRules) > 0 {
		plan := response.BuildTransformPlan(cfg.MaskRules, rc.ParsedBody)
		rc.TransformPlan = plan
		if len(plan) > 0 {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "api_response",
				RuleID:   "response.mask_plan",
				Category: "OBSERVE",
				Severity: "LOW",
				Message:  "response transform plan generated",
				Evidence: map[string]string{
					"fields": strconv.Itoa(len(plan)),
				},
			})
		}
	}

	// 5. 响应方向字段权限（W11-RAUTHZ / P0-17 响应侧防越权读取）：排在 transform plan 之后——
	// FORBIDDEN 字段被本相位 REMOVE/MASK 计划覆盖时不重复产出（脱敏治理优先于越权观察）；
	// SENSITIVE 字段已被敏感字段检测命中时不重复产出；证据只含字段路径/属性不落值；无下发零行为
	if len(cfg.FieldPermissions) > 0 {
		detectors.CheckResponseFieldPermissions(ctx, cfg.RequestRoles, cfg.EndpointKey, cfg.FieldPermissions, rc.ParsedBody, rc.TransformPlan, rc.SensitiveFields)
	}

	// 6. 响应相位统一决策（请求侧阻断类请求不会到达本相位，优先级语义不变）
	return decision.Decide(ctx, decision.Input{Mode: mode}), nil
}
