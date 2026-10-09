// Package grpcguard gRPC G1 unary 有界深检执行器（NG-GRPC 批次 B2，
// docs/nextgen/NG-GRPC-g1-unary.md §1.1/§1.3/§1.4/§1.6/§1.8 + D1/D4/D6/D8）。
//
// 判定形态（D1 冻结）：application/grpc（+proto 深检；+json 等编码变体
// SKIPPED(non_proto_codec) 不冒充深检）且方法 POST 且 :path=/pkg.Service/Method
// （classifier 拆分口径）；非候选零开销零记录。请求帧序列 >1 条消息 =
// client streaming → SKIPPED(streaming_degraded)+观测明细（降级即如实声明
// 不覆盖，不是「只检首帧」——R05）；帧结构校验不受降级影响照判。
//
// 缺描述符红线（D3）：服务未在（绑定）注册表登记 → SKIPPED(no_descriptor)
// 只帧观测，PROTECT 不误断（缺描述符不是违规证据——UNKNOWN 恒不阻断）。
// 绑定消费（§1.3）：应用存在任一绑定行时该应用只用其绑定集编译的注册表
// （同名服务跨应用不错配）；空绑定=全局生效（现状语义，回退 mode=OBSERVE——
// PROTECT 须显式绑定，能力门 grpc/2 随 PROTECT 绑定触发）。
//
// 执行（D6）：OBSERVE 缺省记录；PROTECT（绑定 mode=PROTECT 且引擎 PROTECT
// 双闸）违规 → trailers-only 响应（apiprotect 按 api.protocol=GRPC 分流，
// committed 直写）：结构违规 PERMISSION_DENIED(7)/预算 RESOURCE_EXHAUSTED(8)/
// 未知压缩算法 UNIMPLEMENTED(12)；UNKNOWN 恒不阻断（解码失败/依赖缺席→
// 放行+如实披露）；错误三分类（grpcframe ProtocolError/BudgetError/
// EncodingError）→ 状态码映射表冻结落码。
//
// 覆盖五态（D8）：检测器名 grpcguard——SKIPPED（non_grpc/streaming_degraded/
// no_descriptor/non_proto_codec/compression_disabled）/FULL/PARTIAL；每 gRPC
// 候选请求一条 grpc.coverage_v1 INFO 记录（方向/消息序号/压缩方式/描述符集名
// 与 content_hash 前 8/实际读取/解压字节量/深检完成度）。既有 grpc/grpc_desc
// 观测键形不变（并行共存）。
package grpcguard

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/coverage"
	"github.com/jiuzhang-waf/gateway/dynamic_security/grpcdesc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/grpcframe"
)

// 模式词表（绑定 mode；缺省 OBSERVE——NG-T-C01 零变化承载）。
const (
	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"
)

// grpc-status 映射（D6 冻结；16/14 为本批预留常量——JWT 信任链 gRPC 拒（16）
// 走 jwt_trust 既有通道不在本检测器产出；依赖不可用（14）在 G1 语义内按
// UNKNOWN 放行披露不映射——见包注释红线）。
const (
	StatusPermissionDenied  = 7  // 策略违规（field_violation/enum 实断面）
	StatusResourceExhausted = 8  // 畸形帧/超预算
	StatusUnimplemented     = 12 // 未支持压缩算法
	StatusUnavailable       = 14 // 依赖失败（预留；G1 内 UNKNOWN 恒不阻断不产出）
	StatusUnauthenticated   = 16 // 认证失败（预留；JWT 信任链 PROTECT 拒走既有通道）
)

// Binding 服务级绑定（发布通道 api_grpc_bindings 段行消费形态）。
type Binding struct {
	DescriptorName string // 引用的描述符集名（grpcdesc Set.Name）
	Mode           string // OBSERVE|PROTECT（装配期归一；缺省 OBSERVE）
}

// Config grpcguard 装配产物（Provision 后只读，热加载经实例整体替换）。
type Config struct {
	// GlobalRegistry 全局注册表（现状 grpcdesc 装配产物引用——空绑定应用可见）。
	GlobalRegistry *grpcdesc.Registry
	// SetRegistries 绑定集名 → 专用注册表（per-app 语义：绑定应用只用绑定集，
	// 同名服务跨应用不错配）；绑定引用未知/编译失败集 → 无注册表条目
	// （运行期 SKIPPED(no_descriptor)，装配期 Warn 留痕，不误断）。
	SetRegistries map[string]*grpcdesc.Registry
	// SetHashes 集名 → content_hash 前 8（覆盖读数 descriptor_hash）。
	SetHashes map[string]string
	// Bindings application_id → service → Binding（仅显式绑定行；
	// 无行应用 = 空绑定 = 全局生效）。
	Bindings map[string]map[string]Binding
	// AllowCompression 压缩许可三态（发布通道 api_grpc_allow_compression）：
	// nil = 未下发（G1 默认 true 允许 gzip 并深检，D5）；显式 false 维持现状
	// 二态（标记不解不进入解压深检，SKIPPED(compression_disabled)）。
	AllowCompression *bool
}

// AllowGzip 压缩许可生效值（三态归一）。
func (c *Config) AllowGzip() bool {
	if c == nil || c.AllowCompression == nil {
		return true // G1 默认 true（D5）
	}
	return *c.AllowCompression
}

// resolution 服务级解析产物。
type resolution struct {
	registry *grpcdesc.Registry
	setName  string
	mode     string // 绑定 mode；无绑定回退 OBSERVE（PROTECT 须显式绑定）
}

// resolve 应用+服务 → 描述符注册表/集名/绑定 mode（§1.3 消费语义：
// 应用存在任一绑定行 → 只用绑定集（本服务无行 = 无描述符）；空绑定 = 全局）。
func (c *Config) resolve(appID, service string) resolution {
	if c == nil {
		return resolution{mode: ModeObserve}
	}
	if appBindings, ok := c.Bindings[appID]; ok && len(appBindings) > 0 {
		if b, ok := appBindings[service]; ok {
			return resolution{registry: c.SetRegistries[b.DescriptorName], setName: b.DescriptorName, mode: b.Mode}
		}
		return resolution{mode: ModeObserve} // 绑定应用未绑定服务：无描述符
	}
	return resolution{registry: c.GlobalRegistry, mode: ModeObserve}
}

// 跳过原因词表（grpc.coverage_v1 evidence.skip_reason；与 D8 命名一致）。
const (
	skipNonGRPC           = "non_grpc"
	skipNonProtoCodec     = "non_proto_codec"
	skipStreamingDegraded = "streaming_degraded"
	skipNoDescriptor      = "no_descriptor"
	skipCompressionOff    = "compression_disabled"
)

// Evaluate grpcguard 主入口（pipeline 在既有 CheckGRPC 之后调用；grpcRes 为
// 分类器拆分结果；body 为装配层保全的完整请求体——G1 协议专属读取预算，
// 不经公共 1MiB 解析上限；engineProtect 为引擎 PROTECT 双闸之一）。
// 返回覆盖观测（候选请求恒非 nil；pipeline 经 emitCov 发射——观测永不贡献评分）。
func Evaluate(ctx *dsctx.RequestContext, p *parser.Parsed, grpcRes classifier.GRPCResult, body []byte, cfg *Config, appID string, engineProtect bool) *coverage.Observation {
	if ctx == nil || p == nil || cfg == nil {
		return nil
	}
	cov := &coverage.Observation{
		RequestID:   ctx.RequestID,
		Detector:    "grpcguard",
		Phase:       coverage.PhaseRequest,
		Scope:       coverage.ScopeDeclared{Bytes: int64(len(body)), Messages: 1, Direction: "request"},
		EndpointKey: grpcRes.Service + "/" + grpcRes.Method,
	}
	rec := &coverageRecorder{ctx: ctx, p: p, grpcRes: grpcRes, body: body, cfg: cfg, cov: cov}

	// 非 POST：形似 gRPC 但非 unary 候选（D1 判定形态冻结）
	if !strings.EqualFold(p.Method, http.MethodPost) {
		return rec.skip(skipNonGRPC, coverage.ReasonNotGRPC)
	}
	// 编码变体：+json 等非 proto codec → 不冒充深检（帧结构校验由现状 parse 承担）
	if nonProtoCodec(p.ContentType) {
		return rec.skip(skipNonProtoCodec, coverage.ReasonNonProtoCodec)
	}
	// 压缩许可三态（D5）：显式 false → 维持现状二态（标记不解；现状
	// grpc.unexpected_compression 由既有检测器产出），不进入解压深检
	frameCompressed := len(body) > 0 && body[0]&0x01 != 0
	if frameCompressed && !cfg.AllowGzip() {
		return rec.skip(skipCompressionOff, coverage.ReasonDisabled)
	}
	// grpc-encoding 头闸（仅允许压缩时进入）：未知算法 → UNIMPLEMENTED(12)
	// （PROTECT 双闸）/OBSERVE 记录转发不动——协议标准应答非安全误断
	encoding := ""
	if frameCompressed || p.Headers["grpc-encoding"] != "" {
		canon, err := grpcframe.CheckEncoding(p.Headers["grpc-encoding"])
		if err != nil {
			rec.unsupportedEncoding(p.Headers["grpc-encoding"], engineProtect, recResolveMode(cfg, appID, grpcRes.Service))
			return rec.partial()
		}
		encoding = canon
	}
	rec.encoding = encoding
	return rec.evaluateFrames(appID, engineProtect)
}

// recResolveMode 提前解析绑定 mode（编码闸实断判定需要）。
func recResolveMode(cfg *Config, appID, service string) string {
	return cfg.resolve(appID, service).mode
}

// nonProtoCodec 编码变体判定：application/grpc 裸类型与 +proto 按 proto 深检；
// +json 等其他后缀按非 proto（SKIPPED non_proto_codec——不做 protobuf 解码）。
func nonProtoCodec(contentType string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if mt == "application/grpc" || mt == "application/grpc+proto" {
		return false
	}
	return strings.HasPrefix(mt, "application/grpc+")
}

// coverageRecorder 单次评估的记录器（明细/覆盖收集）。
type coverageRecorder struct {
	ctx     *dsctx.RequestContext
	p       *parser.Parsed
	grpcRes classifier.GRPCResult
	body    []byte
	cfg     *Config
	cov     *coverage.Observation

	encoding     string // identity|gzip
	messagesRead int
	bytesRead    int64
	decompressed int64
	setName      string
	skipReason   string
	violations   []Violation
	unknown      int
}

// skip SKIPPED 五态收口（覆盖 + coverage_v1 记录）。
func (rc *coverageRecorder) skip(reason string, code coverage.ReasonCode) *coverage.Observation {
	rc.skipReason = reason
	rc.cov.Status = coverage.StatusSkipped
	rc.cov.ReasonCode = code
	rc.emitCoverageMatch("skipped")
	return rc.cov
}

// partial PARTIAL 收口（截断/中途停止如实；Truncated 满足契约校验）。
func (rc *coverageRecorder) partial() *coverage.Observation {
	rc.cov.Status = coverage.StatusPartial
	rc.cov.Truncated = true
	rc.emitCoverageMatch("partial")
	return rc.cov
}

// full FULL 收口（unary 深检完成——违规是判定结果不是覆盖缺失）。
func (rc *coverageRecorder) full() *coverage.Observation {
	rc.cov.Status = coverage.StatusFull
	rc.emitCoverageMatch("full")
	return rc.cov
}

// emitCoverageMatch grpc.coverage_v1 INFO 记录（D8 冻结读数键）。
func (rc *coverageRecorder) emitCoverageMatch(completion string) {
	evidence := map[string]string{
		"direction":   "request",
		"message_seq": "1",
		"compression": orIdentity(rc.encoding),
		"bytes_read":  strconv.FormatInt(rc.bytesRead, 10),
		"completion":  completion,
	}
	if rc.decompressed > 0 {
		evidence["decompressed_bytes"] = strconv.FormatInt(rc.decompressed, 10)
	}
	if rc.setName != "" {
		evidence["descriptor"] = rc.setName
		if h := rc.cfg.SetHashes[rc.setName]; h != "" {
			evidence["descriptor_hash"] = h
		}
	}
	if rc.skipReason != "" {
		evidence["skip_reason"] = rc.skipReason
	}
	if rc.unknown > 0 {
		evidence["unknown_fields"] = strconv.Itoa(rc.unknown)
	}
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "grpcguard",
		RuleID:   "grpc.coverage_v1",
		Category: "INFO",
		Severity: "INFO",
		Message:  "grpc unary coverage",
		Evidence: evidence,
	})
}

func orIdentity(enc string) string {
	if enc == "" {
		return "identity"
	}
	return enc
}

// evaluateFrames 帧读取 → streaming 识别 → 解压 → 描述符解码 → 结构校验主链。
func (rc *coverageRecorder) evaluateFrames(appID string, engineProtect bool) *coverage.Observation {
	// 帧读取（批次 A 读取器：流式重组+四重预算+错误三分类）
	rd := grpcframe.NewReader(bytes.NewReader(rc.body), grpcframe.Config{})
	defer func() { _ = rd.Close() }()
	frame, err := rd.Next()
	if err != nil {
		if isEOF(err) {
			// 零消息（空体/空流）：unary 判定无消息可检——PARTIAL 如实
			// （不定案：空 POST 是否协议违规留集成批裁决，本批不冒充判定）
			rc.ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "grpcguard",
				RuleID:   "grpc.no_unary_message",
				Category: "INFO",
				Severity: "INFO",
				Message:  "grpc request carries no message frame",
			})
			return rc.partial()
		}
		return rc.frameReadError(err, engineProtect, appID)
	}
	rc.messagesRead = 1
	rc.bytesRead = 5 + int64(len(frame.Body))

	// streaming 识别（D1：请求帧序列 >1 条消息 = client streaming）——
	// 降级即如实声明不覆盖（R05：不报告「整个调用通过」）；帧结构校验已由
	// 读取器执行（结构畸形照判，与深检无关）
	if _, err2 := rd.Next(); err2 == nil {
		rc.messagesRead = 2
		rc.bytesRead = 5 + int64(len(frame.Body))
		rc.streamingObserved()
		return rc.skip(skipStreamingDegraded, coverage.ReasonStreamingDegraded)
	} else if err2 != nil && !isEOF(err2) {
		// 第二帧读取即畸形：结构畸形照判（不是 streaming 声明——未确认第二条合法帧）
		return rc.frameReadError(err2, engineProtect, appID)
	}

	// 压缩解压（§1.5 四重预算；嵌套 gzip 不递归）
	msg := frame.Body
	if frame.Compressed {
		out, derr := grpcframe.Gunzip(frame.Body)
		if derr != nil {
			return rc.decompressError(derr, engineProtect, appID)
		}
		msg = out
		rc.decompressed = int64(len(out))
		// 覆盖读数以实际解压行为为准（帧压缩位为真即 gunzip——
		// gzip 唯一支持算法，头缺省时不落 identity 假读数）。
		rc.encoding = "gzip"
	}

	// 描述符解析（绑定消费）：缺描述符红线——SKIPPED(no_descriptor) 只帧观测，
	// PROTECT 不误断（缺描述符不是违规证据）
	res := rc.cfg.resolve(appID, rc.grpcRes.Service)
	rc.setName = res.setName
	md, setName, ok := res.registry.Lookup(rc.grpcRes.Service, rc.grpcRes.Method)
	if !ok {
		return rc.skip(skipNoDescriptor, coverage.ReasonNoDescriptor)
	}
	rc.setName = setName

	// dynamicpb 解码：线格式损坏 → grpc.decode_error（坏消息不是违规消息——
	// UNKNOWN 范畴不升级实断，§1.4 第 4 条）
	m, derr := grpcdesc.DecodeRequest(md, msg)
	if derr != nil {
		rc.ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "grpcguard",
			RuleID:   "grpc.decode_error",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "grpc message decode failed (not a violation, fail-open)",
			Evidence: map[string]string{"service": rc.grpcRes.Service, "method": rc.grpcRes.Method},
		})
		return rc.partial()
	}

	// 结构校验（§1.4 首期检查集；只读不重序列化）
	rc.violations, rc.unknown = CheckStructure(m)
	rc.reportViolations(res.mode, engineProtect)
	return rc.full()
}

// frameReadError 帧读取错误分派：格式错误（framing 层）→ 畸形（8 语义）；
// 预算耗尽 → 超预算（8 语义）；源错误透传按 PARTIAL 如实。
func (rc *coverageRecorder) frameReadError(err error, engineProtect bool, appID string) *coverage.Observation {
	switch {
	case grpcframe.IsProtocolError(err):
		pe := err.(*grpcframe.ProtocolError)
		if pe.Kind == "invalid_gzip" {
			// 压缩流损坏 = 坏消息（codec 层）——decode_error UNKNOWN 不升级实断
			rc.ctx.AddMatch(dsctx.DetectorMatch{
				Detector: "grpcguard",
				RuleID:   "grpc.decode_error",
				Category: "OBSERVE",
				Severity: "LOW",
				Message:  "grpc compressed message stream corrupt (not a violation, fail-open)",
				Evidence: map[string]string{"kind": pe.Kind},
			})
			return rc.partial()
		}
		rc.enforceOrObserve("grpcguard.malformed_frame", StatusResourceExhausted,
			"grpc malformed frame", map[string]string{"kind": pe.Kind}, engineProtect, appID)
	case grpcframe.IsBudgetError(err):
		be := err.(*grpcframe.BudgetError)
		rc.enforceOrObserve("grpcguard.budget_exceeded", StatusResourceExhausted,
			"grpc frame budget exceeded", map[string]string{
				"kind": be.Kind, "limit": strconv.FormatInt(be.Limit, 10), "actual": strconv.FormatInt(be.Actual, 10),
			}, engineProtect, appID)
	default:
		// 源错误（ctx 取消等）：UNKNOWN 如实，不映射
		rc.ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "grpcguard",
			RuleID:   "grpc.read_error",
			Category: "OBSERVE",
			Severity: "LOW",
			Message:  "grpc frame source read error (fail-open)",
			Evidence: map[string]string{"error": err.Error()},
		})
	}
	return rc.partial()
}

// decompressError 解压错误分派（§1.5：预算触顶 → grpc.compression_budget_exceeded
// （8 语义）；gzip 流损坏 → decode_error UNKNOWN）。
func (rc *coverageRecorder) decompressError(err error, engineProtect bool, appID string) *coverage.Observation {
	if grpcframe.IsBudgetError(err) {
		be := err.(*grpcframe.BudgetError)
		rc.enforceOrObserve("grpc.compression_budget_exceeded", StatusResourceExhausted,
			"grpc compression budget exceeded", map[string]string{
				"kind": be.Kind, "limit": strconv.FormatInt(be.Limit, 10), "actual": strconv.FormatInt(be.Actual, 10),
			}, engineProtect, appID)
		return rc.partial()
	}
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "grpcguard",
		RuleID:   "grpc.decode_error",
		Category: "OBSERVE",
		Severity: "LOW",
		Message:  "grpc gzip stream corrupt (not a violation, fail-open)",
		Evidence: map[string]string{"kind": "invalid_gzip"},
	})
	return rc.partial()
}

// streamingObserved streaming 降级观测（D1：方向/首消息序号/不冒充深检文案）。
func (rc *coverageRecorder) streamingObserved() {
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "grpcguard",
		RuleID:   "grpc.streaming_observed",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "grpc streaming call detected: deep inspection degraded (not covered, not passed)",
		Evidence: map[string]string{
			"direction":     "request",
			"message_seq":   "1",
			"messages_seen": strconv.Itoa(rc.messagesRead),
		},
	})
}

// unsupportedEncoding 未知压缩算法（§1.5/D6：UNIMPLEMENTED(12)——协议标准应答；
// OBSERVE 记录转发不动）。
func (rc *coverageRecorder) unsupportedEncoding(encoding string, engineProtect bool, bindingMode string) {
	category := "OBSERVE"
	if bindingMode == ModeProtect && engineProtect {
		category = "BLOCK"
	}
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "grpcguard",
		RuleID:   "grpc.unsupported_encoding",
		Category: category,
		Severity: "MEDIUM",
		Message:  "grpc encoding not implemented",
		Evidence: map[string]string{
			"encoding":    encoding,
			"grpc_status": strconv.Itoa(StatusUnimplemented),
		},
	})
}

// enforceOrObserve 双闸定案：绑定 PROTECT 且引擎 PROTECT → BLOCK 类（apiprotect
// 按 api.protocol=GRPC 分流 trailers-only）；否则 OBSERVE 只记录。
// evidence 注入 grpc_status 供执行面映射。
func (rc *coverageRecorder) enforceOrObserve(ruleID string, grpcStatus int, message string, evidence map[string]string, engineProtect bool, appID string) {
	mode := rc.cfg.resolve(appID, rc.grpcRes.Service).mode
	category := "OBSERVE"
	if mode == ModeProtect && engineProtect {
		category = "BLOCK"
	}
	if evidence == nil {
		evidence = map[string]string{}
	}
	evidence["grpc_status"] = strconv.Itoa(grpcStatus)
	rc.ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "grpcguard",
		RuleID:     ruleID,
		Category:   category,
		Severity:   "HIGH",
		Message:    message,
		Confidence: 1.0,
		Evidence:   evidence,
	})
}

// reportViolations 结构违规定案（§1.4：证据=字段路径+规则名+读取量，不落值；
// 枚举越界独立键 grpc.enum_out_of_range；前 5 条逐条明细+合计摘要防膨胀）。
func (rc *coverageRecorder) reportViolations(bindingMode string, engineProtect bool) {
	if len(rc.violations) == 0 {
		return
	}
	category := "OBSERVE"
	if bindingMode == ModeProtect && engineProtect {
		category = "BLOCK"
	}
	const maxDetail = 5
	for i, v := range rc.violations {
		if i >= maxDetail {
			break
		}
		ruleID := "grpc.field_violation"
		if v.Rule == "enum_out_of_range" {
			ruleID = "grpc.enum_out_of_range"
		}
		rc.ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "grpcguard",
			RuleID:     ruleID,
			Category:   category,
			Severity:   "HIGH",
			Message:    "grpc message structure violation",
			Confidence: 1.0,
			Evidence: map[string]string{
				"rule":        v.Rule,
				"path":        v.Path,
				"read":        v.Read,
				"grpc_status": strconv.Itoa(StatusPermissionDenied),
			},
		})
	}
	if len(rc.violations) > maxDetail {
		rc.ctx.AddMatch(dsctx.DetectorMatch{
			Detector: "grpcguard",
			RuleID:   "grpc.field_violation_summary",
			Category: "INFO",
			Severity: "INFO",
			Message:  "grpc structure violations truncated",
			Evidence: map[string]string{"total": strconv.Itoa(len(rc.violations))},
		})
	}
}

// isEOF 干净结束判定。
func isEOF(err error) bool { return errors.Is(err, io.EOF) }
