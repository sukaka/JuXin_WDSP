// API 动态防护（WDSP / 阶段8）：统一引擎在 jiuzhang_guard 请求链上的挂点。
//
// 设计约束：
//   - 关闭（api_dynamic_protection 缺省/false）时零开销、零行为变化，纯 WAF 路径不受影响；
//   - 所有放行出口（保护地址旁路、白名单、常规链路）统一经 serveNext，保证引擎唯一挂点；
//   - parser 会读取并关闭 Body，必须先完整读出并在管线结束后还原，下游（Coraza/反向代理）才能拿到完整请求体；
//   - 引擎/事件输出故障一律 fail-open（记录告警，不阻断业务），与 guard 既有故障策略一致；
//   - 事件时机：阻断类请求在阻断时输出（状态码按决策映射）；API 放行流量在响应完成后输出
//     （真实 response_status、latency_ms 与响应侧 findings）；非 API 命中维持响应前输出（状态码 0）。
//   - Coraza 合流：统一管线放行但下游 coraza-caddy 阻断（中断哨兵错误）时，归因补记 waf 明细
//     并按实记 final_action=BLOCK（见 apicoraza.go 的调查结论与局限）。
package jiuzhang_guard

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/flowguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/jwtverify"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/behaviorstore"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
	"go.uber.org/zap"
)

// requestContextKey 请求上下文中的统一 RequestContext 键（供下游处理器复用一次解析结果）。
type requestContextKey struct{}

// RequestContextFrom 从请求上下文取统一 RequestContext（未启用 API 动态防护或未执行管线时为 nil）。
func RequestContextFrom(r *http.Request) *dsctx.RequestContext {
	v, _ := r.Context().Value(requestContextKey{}).(*dsctx.RequestContext)
	return v
}

// bridgeRequestContext APM 阶段1（D6）：填充统一 RequestContext 的请求级关联字段（原死字段）。
// ApplicationID 取自 Guard.AppID——events.BuildPrimary 读 ctx.ApplicationID 的口径由此变正确
// （emitAPIEvent 本就以 g.AppID 覆盖输出，既有事件行为不变）。
func (g *Guard) bridgeRequestContext(r *http.Request, rc *dsctx.RequestContext) {
	if rc == nil {
		return
	}
	tc := traceContextFrom(r.Context())
	rc.TraceID = tc.TraceID
	rc.SpanID = tc.SpanID
	rc.ApplicationID = g.AppID
	rc.Domain = requestHost(r)
	if res, ok := clientIPResultFrom(r.Context()); ok {
		rc.ClientIP = res.ClientIP
		rc.ConnectionIP = res.ConnectionIP
		// TrustedProxyChain 取识别到的声明代理链摘要（", " 分隔、截断 128 字符，观测用途）；
		// 未命中可信代理（含伪造/非法头回退场景）不填——该场景摘要为原始头原文，不作链证据
		if res.TrustedProxyUsed != "" && res.ChainSummary != "" {
			rc.TrustedProxyChain = strings.Split(res.ChainSummary, ", ")
		}
	}
	// 身份引擎回填（AI 自动化渗透防护增强 阶段1）：identity_behavior 启用时身份解析
	// 结果经请求上下文传递（serveGuard 身份观测点写入），回填统一 RequestContext 身份
	// 指纹——仅此一项，不改其他字段语义（IdentityFingerprint 当前下游无消费方，回填
	// 供后续身份维度检测桥接复用）
	if id := identitybehavior.IdentityFrom(r.Context()); id != nil {
		rc.IdentityFingerprint = id.Key
		rc.SetIdentity(id.Type, int(id.Confidence), id.Evidence)
	}
}

// enrichContextIdentifiers 填充统一上下文 §7 字段：device_fingerprint（被动 UA/Accept
// 族指纹）与 object_identifiers（路径位置参数 + body 主键字段的对象标识哈希）。
// 产出为 parser 纯函数：热路径零网络 IO，定长 HMAC + 条数/值长双封顶。
// parsed 为 nil（体未保全等场景）时仅产出来自头部的设备指纹与路径侧对象标识
// （调用方可用最小 Parsed{RawPath, NormalizedPath} 供给路径侧）。
func (g *Guard) enrichContextIdentifiers(r *http.Request, rc *dsctx.RequestContext, parsed *parser.Parsed) {
	if rc == nil || r == nil {
		return
	}
	if rc.DeviceFingerprint == "" {
		rc.DeviceFingerprint = parser.DeriveDeviceFingerprint(g.IdentitySalt, r.Header)
	}
	if parsed != nil && len(rc.ObjectIdentifiers) == 0 {
		rc.SetObjectIdentifiers(parser.ExtractObjectIdentifiers(parsed, g.IdentitySalt))
	}
}

// apiDecisionMode 解析防护模式；启用但模式未配置时默认 OBSERVE（fail-safe，不放任阻断）。
func apiDecisionMode(s string) decision.Mode {
	switch decision.Mode(s) {
	case decision.ModeOff, decision.ModeObserve, decision.ModeProtect:
		return decision.Mode(s)
	default:
		return decision.ModeObserve
	}
}

// apiParseLimits 统一生成请求上下文与响应相位使用的解析限制；未下发采样比例保持默认 1。
func (g *Guard) apiParseLimits() dsctx.ParseLimits {
	limits := dsctx.DefaultParseLimits()
	if g.APIResponseSampleRatio != nil {
		limits.ResponseSampleRatio = *g.APIResponseSampleRatio
	}
	return limits
}

// buildBehaviorStores 按 behavior_store 配置构建检测器计数存储注入集合。
// memory（缺省）→ nil（进程内默认实现，零行为变化）；valkey → 复用共享引擎 Valkey 连接
// （behaviorstore：sha256 键 + TTL + Lua 原子计数），连接未建立时告警并回退 nil
// （装配期 Fail-open 不阻断启动）；运行期 Valkey 故障由实现内降级内存兜底。
func buildBehaviorStores(g *Guard, eng *sharedEngine) *detectors.StoreOverrides {
	if g.BehaviorStore != "valkey" {
		return nil
	}
	if eng == nil || eng.valkey == nil {
		g.logger.Warn("behavior_store=valkey 但共享引擎无 Valkey 连接" +
			"（未配置 valkey 地址或 counter_backend 非 valkey），回退进程内存")
		return nil
	}
	ttl := time.Duration(g.BehaviorStoreTTLSeconds) * time.Second
	return behaviorstore.New(eng.valkey, "", ttl, g.logger).Overrides()
}

// buildStrongFlowRuntime 强流程运行时装配（NG-FLOW-02 §1.3/D8）：未下发定义 → nil
// （零行为 NG-T-C01）。定义存在时构建 Valkey 原子操作存储（共享引擎连接，Lua 单
// 次原子往返，fencing=实例级 INCR）——Valkey 连接缺席或实例引用 HMAC 密钥缺席
// 均不拒载：Runtime 内部恒 UNKNOWN 放行 + dependency_unavailable 披露（D8 红线：
// 严格流程严禁切换本地内存，分布式唯一事实源；UNKNOWN 恒不阻断），Warn 留痕。
func (g *Guard) buildStrongFlowRuntime(eng *sharedEngine) *flowguard.Runtime {
	if g.apiStrongFlows == nil {
		return nil
	}
	var cli flowguard.Evaluator
	if eng != nil && eng.valkey != nil {
		cli = eng.valkey
	} else {
		g.logger.Warn("api_strong_flows 已下发但共享引擎无 Valkey 连接（未配置 valkey 块或 counter_backend 非 valkey）：强流程判定恒 UNKNOWN 放行+披露（D8 不切本地内存）")
	}
	if len(g.APIAuthzObjectHMACKey) != 32 {
		g.logger.Warn("api_strong_flows 已下发但 api_authz_object_hmac_key_hex 缺失/非法：实例引用无法键化，强流程判定恒 UNKNOWN 放行+披露（不阻断）")
	}
	return &flowguard.Runtime{
		Store: flowguard.NewStore(cli, func(op string, err error) {
			g.logger.Warn("strong flow valkey op failed, UNKNOWN fail-open (D8: no local fallback)",
				zap.String("op", op), zap.Error(err))
		}),
		HMACKey: g.APIAuthzObjectHMACKey,
	}
}

// serveNext 统一放行出口：先执行 API 动态防护管线，再进入下游（WAF/反向代理）。
// 全量访问日志采集点已上移至 ServeHTTP 入口（APM 阶段1 D9，覆盖前置拦截分支），
// 此处仅打 TTFB 下游链进入点（访问日志关闭时 no-op）。
// redirect_port_rewrite>0 时包装 ResponseWriter 改写 302 Location 端口（默认关闭，零行为变化）。
// trace_inject_upstream=true 时在此注入上游 traceparent（APM 阶段2 前提，ADR D6）：
// 本函数是所有放行路径（保护地址旁路/白名单/L7 allow/常规链路）唯一汇合点，且位于
// 下游链（含 reverse_proxy）之前；前置拦截分支直接回包不经此函数，天然不触达上游。
func (g *Guard) serveNext(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	markAccessLogDownstreamEntry(r.Context())
	if g.TraceInjectUpstream {
		injectTraceparent(traceContextFrom(r.Context()), r)
	}
	handler := func(w http.ResponseWriter, r *http.Request) error {
		// JWT 信任链强制处置（WDSP P0-03）：执行点在 API 动态管线阶段——serveNext
		// 是所有放行出口（保护地址旁路/白名单/L7 allow/常规链路）的唯一汇合点，
		// 白名单/L7 allow 不绕过 JWT PROTECT（安全底线）；VERIFIED 不产生全局放行，
		// 继续 API 管线与 WAF 等后续检测。处置表见 jwt_trust.go enforceJWTTrust。
		if handled, err := g.enforceJWTTrust(w, r); handled {
			return err
		}
		// 机器身份强制处置（NG-ID G1：与 enforceJWTTrust 同段——白名单/L7 allow
		// 不绕过（安全底线）；验证点在 serveGuard 已 compute-only 完成，此处按
		// 结果处置：INVALID→401 固定短语（不带 WWW-Authenticate）/OUT_OF_SCOPE→
		// 403/UNAVAILABLE→503 依赖或 413 体预算；OBSERVE 记录放行；
		// VERIFIED/NOT_PRESENT 原样继续——不产生全局放行）
		if handled, err := g.enforceMachineIdentity(w, r); handled {
			return err
		}
		if !g.APIDynamicProtection {
			return proxyAndCount(w, r, next)
		}
		// 同凭据并发记账：入口 +1、出口（检测+下游转发全程结束）-1；匿名不跟踪。
		// pipeline 无请求生命周期钩子，serveNext 放行链路是最接近的真实 in-flight 埋点。
		_, release := detectors.AcquireCredentialInFlightWithStores(detectors.CredentialKey(r, g.IdentitySalt), g.behaviorStores)
		defer release()
		return g.serveAPIProtected(w, r, next)
	}
	if g.RedirectPortRewrite > 0 {
		w = newRedirectLocationWriter(w, g.RedirectPortRewrite)
	}
	return handler(w, r)
}

// serveAPIProtected API 动态防护主流程：请求相位 → 阻断即时回包 / 放行则捕获响应 →
// 响应相位（仅 API 流量）→ 必要时执行 MASK_RESPONSE → 事件在响应完成后输出（真实状态码与时延）。
func (g *Guard) serveAPIProtected(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	start := time.Now().UTC()
	res, handled, err := g.runAPIProtection(w, r, start)
	if handled {
		return err
	}
	if res == nil || res.Skipped {
		return proxyAndCount(w, r, next)
	}
	if !res.API.IsAPI && !g.hasAPIResponseControls(res.EndpointKey) {
		// 非 API 流量且无响应相位控制：无响应捕获，维持响应前输出（状态码 0 语义不变）。
		// 强流程（NG-FLOW-02）：命中绑定端点即产动作条目——定义绑定本身就是
		// API 语义声明（仅 CONFIRMED 端点可入定义），条目不随分类漏判丢失
		// （PG 事件溯源完整性），故条目存在即输出事件。
		// 强流程响应回程（NG-FLOW-03）：成功预留存在时包装记录器，下游返回后
		// 收口 commit/受理/INDETERMINATE，条目随下方事件一并输出。
		// MCP SSE 逐消息检查（NG-MCP G1 D7）：tools/call 上下文存在时包装——
		// text/event-stream 响应逐事件即检即放（非 SSE 透传零行为）
		mw, sfMCP := g.wrapMCPSSEResponse(w, res.Context)
		sw, sfRec := g.wrapStrongFlowResponse(mw, res.Context)
		nextErr := proxyWithMCPSSEGuard(sw, r, next, sfMCP)
		if sfMCP != nil {
			sfMCP.Finish()
		}
		g.finalizeStrongFlow(res.Context, sfRec, nextErr != nil)
		if len(res.Context.CopyMatches()) > 0 || len(flowguard.ActionsFromContext(res.Context)) > 0 {
			g.emitAPIEvent(r, res, nil)
		}
		return nextErr
	}
	// H-09：FAIL_CLOSED 下存在响应脱敏/水印/签名/下载合规控制时，转发前剥离 Range/If-Range，
	// 防止客户端通过 206 Partial Content 分段响应绕过响应体脱敏、水印、签名或下载合规检查。
	if g.responseFailClosed() && g.requiresResponseTransformOrCompliance(res.EndpointKey) {
		r.Header.Del("Range")
		r.Header.Del("If-Range")
	}
	// API 流量或启用响应控制的端点：包装捕获响应（脱敏/水印/签名/合规改写的执行前提）
	// 水印/签名启用时传入下载改写类型判定（候选文本族下载随 JSON 族同样进入缓冲，改写需完整体）；
	// 合规下载方向规则存在时挂留全部 Content-Disposition 下载（评估与 PROTECT 抑制的前提）
	var downloadTypes func(string) bool
	if g.apiFileWatermark != nil && g.apiFileSignature != nil {
		downloadTypes = func(ct string) bool {
			return g.apiFileWatermark.AllowsContentType(ct) || g.apiFileSignature.AllowsContentType(ct)
		}
	} else if g.apiFileWatermark != nil {
		downloadTypes = g.apiFileWatermark.AllowsContentType
	} else if g.apiFileSignature != nil {
		downloadTypes = g.apiFileSignature.AllowsContentType
	}
	// 下载合规或 file 位置的敏感值规则需要完整缓冲；未配置时不扩大捕获范围。
	downloadHold := g.apiFileCompliance.HasDownloadRules() || detectors.HasFileSensitiveLocation(g.APISensitiveValueRules)
	// SSE 在捕获器之下逐事件即检即放：MCP 调用由专用 writer 接管，其他响应走通用
	// response_body writer，二者互斥避免同一 data 重复检测；非 SSE 透传零行为。
	mw, sfMCP := g.wrapMCPSSEResponse(w, res.Context)
	vw, sfValues := g.wrapResponseBodySSEResponse(mw, res.Context, sfMCP != nil)
	cw := newAPIResponseCapture(vw, g.responseCaptureMax(), g.responseFailClosed(),
		len(g.apiMaskRules[res.EndpointKey]) > 0, downloadTypes, downloadHold, res.EndpointKey, res.Context.RequestID, g.logger)
	cw.inlineHTML = g.apiFileWatermark != nil && g.apiFileWatermark.IncludeInlineHTML
	cw.responseBodyValues = detectors.HasResponseBodySensitiveLocation(g.APISensitiveValueRules)
	// 强流程响应回程（NG-FLOW-03）：成功预留存在时包装记录器于捕获器之上——
	// 采样源站原始字节（脱敏/水印/签名改写之前）；下游返回后先收口
	// （commit/受理/INDETERMINATE 条目入上下文），再进 finishAPIResponse 统一
	// 响应相位与事件输出（条目随主事件 strong_flow 数组一并落盘）。
	sw, sfRec := g.wrapStrongFlowResponse(cw, res.Context)
	nextErr := proxyWithMCPSSEGuard(sw, r, next, sfMCP)
	if sfValues != nil {
		sfValues.Finish()
	}
	if sfMCP != nil {
		sfMCP.Finish()
	}
	g.finalizeStrongFlow(res.Context, sfRec, nextErr != nil)
	g.finishAPIResponse(w, cw, r, res, start, nextErr)
	return nextErr
}

// hasAPIResponseControls 判断端点或应用是否配置了响应相位安全控制（脱敏/下载合规/水印/签名/敏感值/LLM/MCP），
// 确保大请求体或分类漏判时仍包装 apiResponseCapture，不绕过响应相位控制（C-10）。
func (g *Guard) hasAPIResponseControls(ek string) bool {
	return len(g.apiMaskRules[ek]) > 0 ||
		g.apiFileCompliance.HasDownloadRules() ||
		g.apiFileWatermark != nil ||
		g.apiFileSignature != nil ||
		detectors.HasFileSensitiveLocation(g.APISensitiveValueRules) ||
		detectors.HasResponseBodySensitiveLocation(g.APISensitiveValueRules) ||
		g.llmSecurityPolicyForApp() != nil ||
		g.apiMCPGuard != nil
}

// requiresResponseTransformOrCompliance 判断本端点是否存在需完整响应体执行改写或拦截的控制（H-09）。
func (g *Guard) requiresResponseTransformOrCompliance(ek string) bool {
	return len(g.apiMaskRules[ek]) > 0 ||
		g.apiFileWatermark != nil ||
		g.apiFileSignature != nil ||
		g.apiFileCompliance.HasDownloadRules()
}

// partialContentNeedsFailClosed 在 FAIL_CLOSED 策略下，判断 206/Content-Range 分段响应是否会绕过
// 必须执行的脱敏、水印或文件签名转换（H-09）。
func (g *Guard) partialContentNeedsFailClosed(act dsctx.FinalAction, res *pipeline.Result, cw *apiResponseCapture) bool {
	if !g.responseFailClosed() {
		return false
	}
	if act == dsctx.ActionMaskResp || len(g.apiMaskRules[res.EndpointKey]) > 0 {
		return true
	}
	rc := res.Context.GetResponse()
	ct := cw.base.Header().Get("Content-Type")
	isDownload := rc != nil && rc.FileObservation != nil && rc.FileObservation.Direction == dsctx.FileDirectionDownload
	if g.apiFileWatermark != nil {
		isInlineHTML := g.apiFileWatermark.IncludeInlineHTML && !isDownload &&
			cw.base.Header().Get("Content-Disposition") == "" && response.IsHTMLMediaType(ct)
		if (isDownload || isInlineHTML) && g.apiFileWatermark.AllowsContentType(ct) {
			return true
		}
	}
	if g.apiFileSignature != nil && isDownload && g.apiFileSignature.AllowsContentType(ct) {
		return true
	}
	return false
}

// finishAPIResponse 响应收束：响应相位 → MASK_RESPONSE 执行 → 缓冲响应写回 → 事件输出。
// 引擎/转换故障一律按 api_response_fail_policy 处理（FAIL_OPEN 默认放行原响应 + Warn），不 panic、不静默。
// nextErr 非 nil 时跳过响应相位与写回（错误页由 Caddy 错误处理流程写），事件按已捕获状态尽力输出；
// 其中 Coraza 阻断中断（coraza-caddy 哨兵错误）经 attributeWAFIntercept 归因补记（见 apicoraza.go）。
func (g *Guard) finishAPIResponse(w http.ResponseWriter, cw *apiResponseCapture, r *http.Request, res *pipeline.Result, start time.Time, nextErr error) {
	dispo := DispositionFrom(r.Context())
	status, kind := cw.outcome()
	latency := time.Since(start).Milliseconds()
	tail := &apiEventTail{status: status, latencyMS: latency}

	// 下游返回错误：缓冲内容丢弃（客户端由错误页覆盖），状态码按原样捕获值上报（0 = 未采集到）
	if nextErr != nil {
		tail.status = cw.status
		// Coraza 合流：统一管线未判阻断但下游 WAF 中断 → 补记 waf 明细，final_action/状态码按实修正
		if action, code, attributed := attributeWAFIntercept(res.Context, res.FinalAction, nextErr); attributed {
			res.FinalAction = action
			if tail.status == 0 {
				tail.status = code
			}
			// P0-04：WAF 终止事实（同步仅知 executor+status；规则明细由 eventparser
			// 从审计日志异步补全 → PENDING_CORRELATION；cw.status!=0 表示中断码已先行写出）
			if txID, _, ok := corazaInterruption(nextErr); ok && txID != "" {
				dispo.AddEvidenceRef(txID)
			}
			dispo.RecordTerminal(ExecutorWAF, DisActionBlock, code, cw.status != 0, []string{"WAF_INTERCEPT"}, nil)
			dispo.NotePendingCorrelation()
		} else if mcpMidstreamBlocked(res.Context.CopyMatches()) {
			// NG-MCP SSE 中途阻断（批次 C 联调修正）：流式直通路径响应相位未运行，
			// 请求相位 final_action=ALLOW 必须按实修正——不得报告「整个调用通过」
			//（§10.3 共用神门禁；状态码保留已外发 200 如实，已发字节在事件证据披露）
			res.Context.SetFinalAction(dsctx.ActionBlock)
			res.FinalAction = dsctx.ActionBlock
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, cw.status, cw.status != 0,
				[]string{"MCP_RESULT_BLOCKED_MIDSTREAM"}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
		} else {
			// 非 WAF 归因的下游错误（反代 502 等）：ERROR，不硬映射 BLOCK（契约 §2 纪律）
			dispo.RecordError(ExecutorAPI, "downstream error: request did not complete normally")
		}
		g.emitAPIEvent(r, res, tail)
		return
	}

	// 连接劫持：响应已脱离捕获，尽力输出事件（状态码可能为 0 = 未采集到）
	if kind == outcomeHijacked {
		dispo.RecordOrigin(cw.status, true)
		g.emitAPIEvent(r, res, tail)
		return
	}

	decodedBody := cw.body.Bytes()
	compressionFailed := false
	if kind == outcomeBuffered && compressedAPIResponseEncoding(cw.contentEncoding) {
		var decodeErr error
		decodedBody, decodeErr = decodeAPIResponseBody(cw.contentEncoding, cw.body.Bytes(), cw.maxBytes)
		if decodeErr != nil {
			compressionFailed = true
			cw.warnSkip(cw.contentEncoding + " response decode failed: " + decodeErr.Error())
			if g.responseFailClosed() && cw.hasMaskRules {
				kind = outcomeDiscarded
			}
		}
	}

	// FAIL_CLOSED 抑制：原响应未外发，以 500 空明细响应替代（防未脱敏数据泄露）
	if kind == outcomeDiscarded {
		res.Context.AddMatch(dsctx.DetectorMatch{
			Detector: "api_response",
			RuleID:   "response.fail_closed",
			Category: "OBSERVE",
			Severity: "HIGH",
			Message:  "response suppressed: cannot process safely under fail-closed policy",
			Evidence: map[string]string{"endpoint_key": res.EndpointKey},
		})
		g.writeFailClosedResponse(w, res.Context.RequestID)
		tail.status = http.StatusInternalServerError
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusInternalServerError, true,
			[]string{"RESPONSE_FAIL_CLOSED"}, []string{"api_response:response.fail_closed"})
		g.emitAPIEvent(r, res, tail)
		return
	}

	// 响应相位（统一引擎）：JSON 解析/敏感字段/错误签名/transform plan + 响应相位决策
	// BodySize 记录源站实际传输字节；gzip/br 仅以完整解码体供解析，解码失败按未检截断体披露。
	bodySize := cw.bytesStreamed
	if !cw.spilled {
		bodySize += int64(cw.body.Len())
	}
	respIn := pipeline.ResponseInput{
		Status:  status,
		Headers: redactResponseHeaders(cw.base.Header()),
		// ContentDisposition 取截断/脱敏前的原始头值（code-review HIGH-6）：Headers 快照
		// 单值按 256 字节截断，超长 Content-Disposition 经快照解析必然失败，下载观测与
		// 下载方向合规评估随之静默缺失——文件观测必须走原始值通道（不落事件，
		// 观测落库的 FileName 仍由引擎侧截断 128）
		ContentDisposition: cw.base.Header().Get("Content-Disposition"),
		BodySize:           bodySize,
		Truncated:          cw.spilled || compressionFailed,
		Streamed:           kind == outcomeStreamed || compressionFailed,
		ContentType:        cw.base.Header().Get("Content-Type"),
	}
	if kind == outcomeBuffered && !compressionFailed {
		respIn.Body = decodedBody
	} else if cw.spilled && cw.body.Len() > 0 {
		respIn.Body = cw.body.Bytes() // 溢出前缀（Truncated=true，不参与解析/计划）
	}
	act, err := pipeline.ProcessResponse(res.Context, respIn, pipeline.ResponseConfig{
		Mode:      apiDecisionMode(g.APIProtectionMode),
		Limits:    g.apiParseLimits(),
		MaskRules: g.apiMaskRules[res.EndpointKey],
		// 响应结构基线（发布通道下发，按端点选取；nil = 无基线，偏离检测零行为）
		ResponseBaselines: g.apiRespBaselines[res.EndpointKey],
		// 响应方向字段权限（发布通道下发 api_field_permissions，按端点选取；nil = 响应侧检测零行为）；
		// 请求角色复用请求侧同一提取（未验签 JWT 声明，仅作观察信号，不作信任决策）
		EndpointKey:      res.EndpointKey,
		FieldPermissions: g.apiFieldPerms[res.EndpointKey],
		RequestRoles:     detectors.ExtractRequestRoles(r),
		// 文件合规规则（发布通道下发 api_file_compliance_rules，下载方向；nil = 下载侧检测零行为）
		FileComplianceRules: g.apiFileCompliance,
		// webshell C2 会话行为检测（BAS 覆盖基线，响应收束评估）：原请求与身份追踪键
		// （与请求相位同一 TrackingKey 取值口径）；产出信号恒 OBSERVE，绝不参与定案阻断
		Request:  r,
		Identity: detectors.TrackingKey(r, g.IdentitySalt),
		// mcpguard 结果检查（NG-MCP G1 D7；请求相位已确认 tools/call 时生效；
		// nil = 无目录且无绑定零行为；值级规则下发原文经响应相位缓存编译复用）
		MCPGuard:            g.apiMCPGuard,
		SensitiveValueRules: g.APISensitiveValueRules,
		LLMSecurityPolicy:   g.llmSecurityPolicyForApp(),
	})
	if err != nil {
		// 响应相位故障 fail-open：记录并放行原响应（不脱敏）
		g.logger.Warn("api response phase error (fail-open)", zap.Error(err),
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
	} else {
		res.FinalAction = act
	}

	if compressionFailed {
		if act == dsctx.ActionBlock || act == dsctx.ActionMaskResp {
			res.Context.SetFinalAction(dsctx.ActionObserve)
			res.FinalAction = dsctx.ActionObserve
		}
		g.writeBufferedResponse(w, cw, cw.body.Bytes(), false)
		dispo.RecordOrigin(tail.status, true)
		g.emitAPIEvent(r, res, tail)
		return
	}

	// 响应侧阻断（文件合规 / MCP 结果 / LLM 输出保护）：仅完整缓冲且未外发一字节时才能
	// 干净抑制；已直通/溢出的响应无法撤回，必须按实记录降级，不冒充已阻断。
	if err == nil && act == dsctx.ActionBlock {
		if kind == outcomeBuffered {
			// MCP 结果检查实断（NG-MCP §1.7/D11）：mcpguard BLOCK 明细 → -32014
			// JSON-RPC 错误对象（响应未外发一字节，干净阻断零泄漏；id 回显；
			// 固定短语不泄露策略/工具细节，真实原因只落事件）
			if mcpCode, mcpHTTP, ok := mcpguardBlockInfo(res.Context.CopyMatches()); ok {
				dispo.RecordTerminal(ExecutorAPI, DisActionBlock, mcpHTTP, true,
					[]string{"MCP_ERROR_" + strconv.Itoa(mcpCode)}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
				tail.status = mcpHTTP
				g.writeMCPErrorResponse(w, res.Context.RequestID, mcpCode, mcpHTTP, mcpRequestIDRaw(res.Context))
				g.emitAPIEvent(r, res, tail)
				return
			}
			if hasLLMOutputBlock(res.Context.CopyMatches()) {
				g.writeLLMOutputBlockedResponse(w, res.Context.RequestID)
				tail.status = http.StatusForbidden
				dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
					[]string{"LLM_OUTPUT_BLOCK"}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
				g.emitAPIEvent(r, res, tail)
				return
			}
			g.writeFileComplianceBlockedResponse(w, res.Context.RequestID)
			tail.status = http.StatusForbidden
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
				[]string{"FILE_COMPLIANCE_DOWNLOAD_BLOCK"}, []string{"file:download_compliance"})
			g.emitAPIEvent(r, res, tail)
			return
		}
		res.Context.AddMatch(dsctx.DetectorMatch{
			Detector:   "file",
			RuleID:     "file.download_block_unavailable",
			Category:   "OBSERVE",
			Severity:   "HIGH",
			Message:    "file compliance download block not enforced: response already streamed (fail-open)",
			Confidence: 1.0,
			Evidence:   map[string]string{"endpoint_key": res.EndpointKey},
		})
		g.logger.Warn("api file compliance download block not enforced, response already streamed (fail-open)",
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
		res.Context.SetFinalAction(dsctx.ActionObserve)
		res.FinalAction = dsctx.ActionObserve
	}

	// MASK_RESPONSE：仅缓冲完整的响应可执行字段级脱敏（流式/溢出不会产生非空计划）；
	// Range 分段响应（206/Content-Range）与水印/签名同一口径跳过——分段体经字段级改写
	// 会破坏客户端断点续传重组，直通不改写，补记 mask_skipped 明细（不静默）
	masked := false
	var transformed []byte // 脱敏改写后的响应体（masked=true 时有效；写回统一在下方进行）
	partialContent := status == http.StatusPartialContent || cw.base.Header().Get("Content-Range") != ""
	if kind == outcomeBuffered && partialContent && g.partialContentNeedsFailClosed(act, res, cw) {
		res.Context.AddMatch(dsctx.DetectorMatch{
			Detector: "api_response",
			RuleID:   "response.fail_closed",
			Category: "OBSERVE",
			Severity: "HIGH",
			Message:  "partial content (206/Content-Range) suppressed under fail-closed policy to prevent response control bypass",
			Evidence: map[string]string{"endpoint_key": res.EndpointKey, "reason": "partial_content_fail_closed"},
		})
		g.logger.Warn("api partial content (206/Content-Range) suppressed under fail-closed policy",
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
		g.writeFailClosedResponse(w, res.Context.RequestID)
		tail.status = http.StatusInternalServerError
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusInternalServerError, true,
			[]string{"RESPONSE_FAIL_CLOSED"}, []string{"api_response:response.fail_closed"})
		g.emitAPIEvent(r, res, tail)
		return
	}
	if act == dsctx.ActionMaskResp && kind == outcomeBuffered && partialContent {
		res.Context.AddMatch(dsctx.DetectorMatch{
			Detector: "api_response",
			RuleID:   "response.mask_skipped",
			Category: "INFO",
			Severity: "INFO",
			Message:  "response mask skipped: partial content (206/Content-Range), original delivered",
			Evidence: map[string]string{"endpoint_key": res.EndpointKey},
		})
	}
	if act == dsctx.ActionMaskResp && kind == outcomeBuffered && !partialContent {
		if rc := res.Context.GetResponse(); rc != nil && len(rc.TransformPlan) > 0 {
			out, terr := response.ApplyJSONWithKey(decodedBody, rc.TransformPlan, g.apiMaskCrypto)
			switch {
			case terr != nil && g.responseFailClosed():
				res.Context.AddMatch(dsctx.DetectorMatch{
					Detector: "api_response",
					RuleID:   "response.mask_failed",
					Category: "OBSERVE",
					Severity: "HIGH",
					Message:  "response mask transform failed, suppressed by fail-closed policy",
					Evidence: map[string]string{"endpoint_key": res.EndpointKey, "error": terr.Error()},
				})
				g.logger.Warn("api response mask failed, suppressed by fail-closed policy", zap.Error(terr),
					zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
				g.writeFailClosedResponse(w, res.Context.RequestID)
				tail.status = http.StatusInternalServerError
				dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusInternalServerError, true,
					[]string{"RESPONSE_FAIL_CLOSED"}, []string{"api_response:response.mask_failed"})
				g.emitAPIEvent(r, res, tail)
				return
			case terr != nil:
				res.Context.AddMatch(dsctx.DetectorMatch{
					Detector: "api_response",
					RuleID:   "response.mask_failed",
					Category: "OBSERVE",
					Severity: "HIGH",
					Message:  "response mask transform failed, original delivered (fail-open)",
					Evidence: map[string]string{"endpoint_key": res.EndpointKey, "error": terr.Error()},
				})
				g.logger.Warn("api response mask failed (fail-open, original delivered)", zap.Error(terr),
					zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
			default:
				masked = true
				transformed = out.Body
				res.Context.AddMatch(dsctx.DetectorMatch{
					Detector: "api_response",
					RuleID:   "response.mask_applied",
					Category: "INFO",
					Severity: "INFO",
					Message:  "response fields masked",
					Evidence: map[string]string{
						"endpoint_key":   res.EndpointKey,
						"applied_fields": strconv.Itoa(out.AppliedFields),
						"skipped_fields": strconv.Itoa(out.SkippedFields),
					},
				})
			}
		}
	}
	if kind == outcomeBuffered {
		body := decodedBody
		modified := false
		if masked {
			body = transformed
			modified = true
		}
		// 文件下载水印 v1（W12-GW / P2-01 最小可行子集）：与 MASK 共存时先 mask 后水印——
		// 水印盖在脱敏产物上，避免水印标记被字段级改写；失败一律 FAIL_OPEN 直通
		// （水印为审计能力，不阻断业务，不随 api_response_fail_policy 升级抑制）
		if wmBody, applied := g.maybeApplyFileWatermark(res, r, cw, body, status, start); applied {
			body = wmBody
			modified = true
		}
		// 文件签名 v1（W13-GW / P2-02）：与水印同捕获路径、水印之后执行——签名覆盖
		// 脱敏/水印后的最终交付内容（验证外发文件实际内容语义）；失败同样 FAIL_OPEN 直通
		if sigBody, applied := g.maybeApplyFileSignature(res, r, cw, body, status, start); applied {
			body = sigBody
			modified = true
		}
		deliveryBody := cw.body.Bytes()
		if modified {
			deliveryBody = body
			if compressedAPIResponseEncoding(cw.contentEncoding) {
				encodedBody, encodeErr := encodeAPIResponseBody(cw.contentEncoding, body)
				if encodeErr != nil {
					cw.warnSkip(cw.contentEncoding + " response re-encode failed: " + encodeErr.Error())
					if g.responseFailClosed() && cw.hasMaskRules {
						res.Context.AddMatch(dsctx.DetectorMatch{
							Detector: "api_response",
							RuleID:   "response.fail_closed",
							Category: "OBSERVE",
							Severity: "HIGH",
							Message:  "response suppressed: cannot process safely under fail-closed policy",
							Evidence: map[string]string{"endpoint_key": res.EndpointKey},
						})
						g.writeFailClosedResponse(w, res.Context.RequestID)
						tail.status = http.StatusInternalServerError
						dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusInternalServerError, true,
							[]string{"RESPONSE_FAIL_CLOSED"}, []string{"api_response:response.fail_closed"})
						g.emitAPIEvent(r, res, tail)
						return
					}
					deliveryBody = cw.body.Bytes()
					modified = false
					masked = false
					res.Context.SetFinalAction(dsctx.ActionObserve)
					res.FinalAction = dsctx.ActionObserve
				} else {
					deliveryBody = encodedBody
				}
			}
		}
		if modified && res != nil && res.Context != nil {
			if rc := res.Context.GetResponse(); rc != nil && rc.FileObservation != nil {
				rc.FileObservation.ContentSHA256 = response.FileContentSHA256(body)
			}
		}
		g.writeBufferedResponse(w, cw, deliveryBody, modified)
	}
	// P0-04 源站完成事实：响应脱敏实改写时 security_action=MASK_RESPONSE
	// （response_source 仍落 ORIGIN——契约 §7）；tail.status 为实际写出码
	if masked {
		dispo.RecordMaskResponse()
	}
	dispo.RecordOrigin(tail.status, true)
	g.emitAPIEvent(r, res, tail)
}

// maybeApplyFileWatermark 文件下载与可选内联 HTML 水印执行：
// 下载路径沿用既有 DOWNLOAD 文件观测；include_inline_html=true 时另接受无下载头的
// text/html 网页，产 file.watermark_applied 并以 delivery 区分 INLINE_HTML/DOWNLOAD。
// 两者均需完整解码缓冲（identity 或 gzip/br；流式/溢出/解码失败不会进入改写）
// + 2xx 状态 + 非 Range 分段（206/Content-Range 分段体加水印会破坏断点续传重组）
// + Content-Type 白名单。命中时产 file.watermark_applied INFO 明细（证据不含水印内容）；
// 失败 FAIL_OPEN 直通原响应并 Warn（不静默）。
func (g *Guard) maybeApplyFileWatermark(res *pipeline.Result, r *http.Request, cw *apiResponseCapture, body []byte, status int, start time.Time) ([]byte, bool) {
	cfg := g.apiFileWatermark
	if cfg == nil || res == nil || res.Context == nil {
		return body, false
	}
	rc := res.Context.GetResponse()
	ct := cw.base.Header().Get("Content-Type")
	isDownload := rc != nil && rc.FileObservation != nil && rc.FileObservation.Direction == dsctx.FileDirectionDownload
	isInlineHTML := cfg.IncludeInlineHTML && !isDownload && cw.base.Header().Get("Content-Disposition") == "" && response.IsHTMLMediaType(ct)
	if !isDownload && !isInlineHTML {
		return body, false
	}
	if status < 200 || status > 299 {
		return body, false // 仅 2xx 成功交付加水印（204 无体、错误页/重定向不改写）
	}
	if status == http.StatusPartialContent || cw.base.Header().Get("Content-Range") != "" {
		return body, false // Range 分段体：加水印会破坏断点续传重组
	}
	if !cfg.AllowsContentType(ct) {
		return body, false
	}
	// OOXML 族（W14-GW）：Content-Type 白名单之外加 filename 扩展名双重一致门禁
	// （防伪造扩展名绕过/误标；MIME 取观测内已归一化主类型）
	if isDownload {
		if ext := response.OOXMLWatermarkExtension(rc.FileObservation.MIME); ext != "" && rc.FileObservation.Extension != ext {
			return body, false
		}
	}
	// 占位变量与 emitAPIEvent 同一取值口径：真实客户端 IP（入口已改写 RemoteAddr）、
	// 身份指纹（仅凭据派生，匿名为空串）、请求时间（UTC RFC3339）、域名（去端口小写）
	ip := ""
	if addr, err := clientip.ConnectionIP(r); err == nil && addr.IsValid() {
		ip = addr.String()
	}
	text := response.RenderFileWatermark(cfg.TextTemplate, response.WatermarkVars{
		IP:       ip,
		Identity: detectors.CredentialKey(r, g.IdentitySalt),
		Time:     start.UTC().Format(time.RFC3339),
		Domain:   requestHost(r),
	})
	out, applied, err := response.ApplyFileWatermark(body, ct, cfg, text)
	if err != nil {
		g.logger.Warn("api file watermark failed (fail-open, original delivered)", zap.Error(err),
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
		return body, false
	}
	if !applied {
		return body, false
	}
	message := "inline html watermark applied"
	evidence := map[string]string{"endpoint_key": res.EndpointKey, "delivery": "INLINE_HTML", "mime": "text/html"}
	if isDownload {
		message = "download file watermark applied"
		evidence["delivery"] = "DOWNLOAD"
		evidence["filename"] = rc.FileObservation.FileName
		evidence["mime"] = rc.FileObservation.MIME
	}
	res.Context.AddMatch(dsctx.DetectorMatch{
		Detector: "file",
		RuleID:   "file.watermark_applied",
		Category: "INFO",
		Severity: "INFO",
		Message:  message,
		Evidence: evidence,
	})
	return out, true
}

// maybeApplyFileSignature 文件签名 v1 执行（W13-GW / P2-02，任务书 §110 子集）：
// 命中条件与水印同一口径：发布通道下发且启用 + 响应相位已产 DOWNLOAD 文件观测 +
// 完整解码缓冲（identity 或 gzip/br 编码）+ 2xx 状态 + 非 Range 分段 + 文本族或 OOXML 能力（text/*、
// application/json、docx/xlsx/pptx，契约无白名单段）。在水印之后调用——签名覆盖脱敏/水印后的最终交付内容。
// 命中时产 file.signature_embedded INFO 明细（证据含 kid/filename/mime，不含密钥与完整内容哈希）；
// 失败 FAIL_OPEN 直通原响应并 Warn（不静默，与水印同一纪律）。
func (g *Guard) maybeApplyFileSignature(res *pipeline.Result, r *http.Request, cw *apiResponseCapture, body []byte, status int, start time.Time) ([]byte, bool) {
	cfg := g.apiFileSignature
	if cfg == nil || res == nil || res.Context == nil {
		return body, false
	}
	rc := res.Context.GetResponse()
	if rc == nil || rc.FileObservation == nil || rc.FileObservation.Direction != dsctx.FileDirectionDownload {
		return body, false
	}
	if status < 200 || status > 299 {
		return body, false // 仅 2xx 成功下载签名（与水印同一口径）
	}
	if status == http.StatusPartialContent || cw.base.Header().Get("Content-Range") != "" {
		return body, false // Range 分段体：嵌入签名会破坏断点续传重组
	}
	ct := cw.base.Header().Get("Content-Type")
	if !cfg.AllowsContentType(ct) {
		return body, false
	}
	// 身份指纹与 emitAPIEvent 同一取值口径（仅凭据派生，匿名为空串；IP 属环境维度不冒充身份）
	out, _, applied, err := response.ApplyFileSignature(body, ct, cfg,
		rc.FileObservation.FileName, detectors.CredentialKey(r, g.IdentitySalt), start)
	if err != nil {
		g.logger.Warn("api file signature failed (fail-open, original delivered)", zap.Error(err),
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
		return body, false
	}
	if !applied {
		return body, false
	}
	res.Context.AddMatch(dsctx.DetectorMatch{
		Detector: "file",
		RuleID:   "file.signature_embedded",
		Category: "INFO",
		Severity: "INFO",
		Message:  "download file signature embedded",
		Evidence: map[string]string{
			"endpoint_key": res.EndpointKey,
			"kid":          cfg.KID,
			"filename":     rc.FileObservation.FileName,
			"mime":         rc.FileObservation.MIME,
		},
	})
	return out, true
}

// admissionBlockMatched 判定本次 BLOCK 定案是否含准入拒绝贡献（未被例外豁免的
// BLOCK 类 admission finding；WDSP P1）。存在即按准入统一 JSON 响应——准入 PROTECT
// 短路保证其为唯一实质阻断源；与受限例外（P0-04）兼容：被豁免的 admission finding
// 已不贡献定案，不构成本分支资格（若定案仍 BLOCK 则必有其他阻断源，走既有错误链路径）。
func admissionBlockMatched(matches []dsctx.DetectorMatch) bool {
	for _, m := range matches {
		if m.Excepted || m.Detector != "admission" {
			continue
		}
		if strings.EqualFold(m.Category, "BLOCK") {
			return true
		}
	}
	return false
}

// writeAPIAdmissionDeniedResponse API 准入拒绝统一响应：403 + 规范 JSON 体
// {"code":"API_ADMISSION_DENIED","message":"该接口未开放访问","request_id":"<id>"}
// （unknown/unconfirmed 不区分，不返回原因明细——防资产探测，设计 §4.1/§7）。
// 键序由 encoding/json 字典序保证（code < message < request_id），响应体精确匹配测试依赖此序。
func (g *Guard) writeAPIAdmissionDeniedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"code":       "API_ADMISSION_DENIED",
		"message":    "该接口未开放访问",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("api admission denied response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// graphqlBlockReason 取首条 GraphQL BLOCK 明细的 reason（evidence.reason；
// 仅未豁免明细参与——例外命中的 Finding 不驱动响应 reason）。无 GraphQL BLOCK 返回 false。
func graphqlBlockReason(matches []dsctx.DetectorMatch) (string, bool) {
	for _, m := range matches {
		if m.Excepted || m.Detector != "graphql" {
			continue
		}
		if !strings.EqualFold(m.Category, "BLOCK") {
			continue
		}
		if r := m.Evidence["reason"]; r != "" {
			return r, true
		}
		return "GQL_ADMISSION_REJECTED", true
	}
	return "", false
}

// writeGraphQLDeniedResponse GraphQL 拒绝统一响应：403 + GraphQL 协议错误语义 JSON
// （{"errors":[{"message":...,"extensions":{"code":<reason>,"request_id":...}}]}；
// GraphQL 调用方按协议消费 errors 数组，非 WAF HTML 阻断页；message 通用文案不泄露
// 成本/预算细节，reason 经 extensions.code 传递——防探测与可排障的平衡）。
func (g *Guard) writeGraphQLDeniedResponse(w http.ResponseWriter, requestID, reason string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]any{
		"errors": []map[string]any{{
			"message": "GraphQL request rejected by protection policy",
			"extensions": map[string]string{
				"code":       reason,
				"request_id": requestID,
			},
		}},
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("graphql denied response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// authzBlockMatched 判定本次 BLOCK 定案是否含授权实断贡献（NG-AZ-03：未被例外
// 豁免的 api_authz BLOCK 类明细——authzdecide 仅在八因子资格全真 + 端点
// enforcement=PROTECT + 决策引擎 PROTECT 语义时产出 VERIFIED_VIOLATION 对应的
// BLOCK finding）。存在即按授权拒绝统一 JSON 响应——UNKNOWN 永不映射 BLOCK
// （红线），故本分支等价于「可信违规实断」。
func authzBlockMatched(matches []dsctx.DetectorMatch) bool {
	for _, m := range matches {
		if m.Excepted || m.Detector != "api_authz" {
			continue
		}
		if strings.EqualFold(m.Category, "BLOCK") {
			return true
		}
	}
	return false
}

// writeAPIAuthzDeniedResponse API 授权拒绝统一响应（NG-AZ-03 D4）：403 + 规范
// JSON 体 {"code":"AUTHZ_VIOLATION_DENIED","message":"无权访问该对象","request_id":"<id>"}
// ——与 admission 同形态、不泄露对象/主体细节（防探测）；真实原因（AUTHZ-BOLA-001/
// AUTHZ-BFLA-001 与 authz_enforcement 证据）只落事件。键序由 encoding/json 字典序
// 保证（code < message < request_id），响应体精确匹配测试依赖此序。
func (g *Guard) writeAPIAuthzDeniedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"code":       "AUTHZ_VIOLATION_DENIED",
		"message":    "无权访问该对象",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("api authz denied response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// flowguardBlockMatched 判定本次 BLOCK 定案是否含强流程违规实断贡献（NG-FLOW-02：
// 未被例外豁免的 flowguard BLOCK 类明细——检测器仅在定义 PROTECT + 引擎 PROTECT
// 双闸全真时对 REJECTED/CONFLICT 违规产出 BLOCK finding；UNKNOWN 恒 OBSERVE
// 永不进本分支——红线）。
func flowguardBlockMatched(matches []dsctx.DetectorMatch) bool {
	for _, m := range matches {
		if m.Excepted || m.Detector != "flowguard" {
			continue
		}
		if strings.EqualFold(m.Category, "BLOCK") {
			return true
		}
	}
	return false
}

// writeAPIStrongFlowDeniedResponse 强流程违规拒绝统一响应（NG-FLOW-02 D6）：
// 403 + 规范 JSON 体 {"code":"FLOW_VIOLATION_DENIED","message":"流程状态不允许该操作",
// "request_id":"<id>"}——与 authz 同形态、不泄露实例/步骤/fencing 细节（防探测）；
// 真实原因（FLOW-RESERVE-001/FENCE-001/IDEMPOTENT-CONFLICT-001 与 strong_flow 动作
// 条目）只落事件。键序由 encoding/json 字典序保证，响应体精确匹配测试依赖此序。
func (g *Guard) writeAPIStrongFlowDeniedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"code":       "FLOW_VIOLATION_DENIED",
		"message":    "流程状态不允许该操作",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("api strong flow denied response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// grpcguardBlockStatus 判定本次 BLOCK 定案是否含 gRPC 深检实断贡献（NG-GRPC D6：
// 未被例外豁免的 grpcguard BLOCK 类明细——双闸全真时产出），并取首个 grpc-status
// 映射值（7/8/12；evidence.grpc_status 由检测器注入）。非 gRPC 分流返回 false。
func grpcguardBlockStatus(matches []dsctx.DetectorMatch) (int, bool) {
	for _, m := range matches {
		if m.Excepted || m.Detector != "grpcguard" {
			continue
		}
		if !strings.EqualFold(m.Category, "BLOCK") {
			continue
		}
		if code, err := strconv.Atoi(m.Evidence["grpc_status"]); err == nil && code != 0 {
			return code, true
		}
		return 8, true // 缺省 RESOURCE_EXHAUSTED（预算/畸形族——策略违规恒显式带码）
	}
	return 0, false
}

// grpcErrorMessages grpc-message 固定短语（D6：不泄露策略/字段细节——防探测；
// 真实原因只落事件。ASCII 仅（gRPC percent-encoding 纪律））。
var grpcErrorMessages = map[int]string{
	7:  "grpc request rejected by protection policy",
	8:  "grpc request exceeds resource budget",
	12: "grpc encoding not implemented",
	14: "grpc protection dependency unavailable",
	16: "grpc request unauthenticated",
}

// writeAPIGRPCErrorResponse gRPC 协议化错误响应（NG-GRPC D6）：trailers-only
// 形态——HTTP 200 + content-type: application/grpc + grpc-status/grpc-message
// 响应头 + 空体（Go h2 服务在无体返回时产出单 HEADERS 携带 END_STREAM 的
// trailers-only 语义；gRPC 调用方按协议消费 grpc-status——真实 SDK 对测属
// stage5 E2E）。本函数直接写出 committed=true，不经 Caddy 错误链阻断页。
func (g *Guard) writeAPIGRPCErrorResponse(w http.ResponseWriter, requestID string, grpcStatus int) {
	msg, ok := grpcErrorMessages[grpcStatus]
	if !ok {
		grpcStatus = 8 // 未登记码防御归一 RESOURCE_EXHAUSTED（不编造短语）
		msg = grpcErrorMessages[grpcStatus]
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/grpc")
	h.Set("Grpc-Status", strconv.Itoa(grpcStatus))
	h.Set("Grpc-Message", msg)
	h.Set("X-Jiuzhang-Request-ID", requestID)
	w.WriteHeader(http.StatusOK)
	// 无响应体：trailers-only 语义（END_STREAM 由 h2 服务在无体返回时产出）
}

// mcpguardBlockInfo 判定本次定案是否含 MCP 检查链实断贡献（NG-MCP D11：
// 未被例外豁免的 mcpguard BLOCK 类（检查链违规）或 RATE_LIMIT 类（调用预算）
// 明细），并取首个错误码/HTTP 状态（mcp_error_code/mcp_http_status 证据由
// 检测器注入——冻结表 -32010~-32014，HTTP 403/413/429 分明）。
func mcpguardBlockInfo(matches []dsctx.DetectorMatch) (code, httpStatus int, ok bool) {
	for _, m := range matches {
		if m.Excepted || m.Detector != "mcpguard" {
			continue
		}
		if !strings.EqualFold(m.Category, "BLOCK") && !strings.EqualFold(m.Category, "RATE_LIMIT") {
			continue
		}
		code, err1 := strconv.Atoi(m.Evidence["mcp_error_code"])
		status, err2 := strconv.Atoi(m.Evidence["mcp_http_status"])
		if err1 != nil || code == 0 {
			code = -32011 // 缺省 MCP_TOOL_DENIED（防御归一不编造）
		}
		if err2 != nil || status == 0 {
			status = 403
		}
		return code, status, true
	}
	return 0, 0, false
}

// mcpMidstreamBlocked 判定明细含 MCP SSE 中途阻断（mcp.result_blocked_midstream；
// finishAPIResponse 下游错误分支按实修正 final_action——流式直通响应相位未运行，
// 不得沿用请求相位 ALLOW 冒充「整个调用通过」）。
func mcpMidstreamBlocked(matches []dsctx.DetectorMatch) bool {
	for _, m := range matches {
		if m.Detector == "mcpguard" && m.RuleID == "mcp.result_blocked_midstream" {
			return true
		}
	}
	return false
}

// mcpRequestIDRaw MCP 错误对象 id 回显原文（mcp.call 上下文 Message.ID——
// JSON-RPC 语义原文回显；未携 id/无调用上下文回显 "null"）。
func mcpRequestIDRaw(ctx *dsctx.RequestContext) string {
	if call := mcpguard.CallFromContext(ctx); call != nil && call.Message != nil && call.Message.HasID && len(call.Message.ID) > 0 {
		return string(call.Message.ID)
	}
	return "null"
}

// mcpErrorMessages 固定短语（§1.11 冻结表——不泄露策略/工具/字段细节，
// 防探测；真实原因只落事件。标准码不冒用：产品扩展段 -32010~-32014）。
var mcpErrorMessages = map[int]string{
	-32010: "mcp tool call requires verified caller",
	-32011: "mcp tool call rejected by protection policy",
	-32012: "mcp tool call arguments rejected",
	-32013: "mcp request exceeds resource budget",
	-32014: "mcp tool result blocked by protection policy",
}

// writeMCPErrorResponse MCP 协议化错误响应（NG-MCP §1.11/D11）：JSON-RPC 2.0
// 错误对象——{"jsonrpc":"2.0","id":<回显|null>,"error":{"code":<产品扩展码>,
// "message":<固定短语>,"data":{"source":"jiuzhang-wdsp","request_id":<id>}}}；
// HTTP 按冻结表（403/413/429 分明——大小/速率不得一律 403，§13.3）。
// 本函数直接写出 committed=true，不经 Caddy 错误链阻断页（MCP 调用方按
// JSON-RPC 协议消费错误对象，非 WAF HTML 阻断页）。
func (g *Guard) writeMCPErrorResponse(w http.ResponseWriter, requestID string, code, httpStatus int, idRaw string) {
	msg, ok := mcpErrorMessages[code]
	if !ok {
		code = -32011 // 未登记码防御归一 MCP_TOOL_DENIED（不编造短语）
		msg = mcpErrorMessages[code]
	}
	if httpStatus != 403 && httpStatus != 413 && httpStatus != 429 {
		httpStatus = 403
	}
	if idRaw == "" {
		idRaw = "null"
	}
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body := []byte(`{"jsonrpc":"2.0","id":` + idRaw +
		`,"error":{"code":` + strconv.Itoa(code) +
		`,"message":` + strconv.Quote(msg) +
		`,"data":{"source":"jiuzhang-wdsp","request_id":` + strconv.Quote(requestID) + `}}}`)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(httpStatus)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("mcp error response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// writeFileComplianceBlockedResponse 文件合规下载阻断抑制响应：403 + 空明细 JSON 体// （不含上游任何内容）。仅在不曾外发字节（缓冲模式扣留状态行）时调用。
func (g *Guard) writeFileComplianceBlockedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Encoding")
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Del("Content-Disposition") // 抑制下载语义：不得携带原文件名外发
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "file_compliance_blocked",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("file compliance blocked response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// writeBufferedResponse 写回缓冲响应：修正 Content-Length；体已改写（脱敏/水印/签名）时同时
// 清除 ETag/Content-MD5/Content-Range（体已变化，旧校验值与字节区间描述一并失效——三个改写点
// 均已按 206/Content-Range 跳过，此处为兜底一致的失效清理）；未改写且处理器未声明长度时按缓冲长度补 Content-Length。
// 例外：声明 Trailer（Trailer 公告头或 TrailerPrefix 键）的响应不强制 Content-Length
// （处理器已设置的一并移除）——net/http 仅在分块编码下外发 Trailer，强制长度会让
// Trailer 值被静默丢弃而公告头照发（语义漂移，已实验确认）；改由分块编码保留 Trailer 语义。
func (g *Guard) writeBufferedResponse(w http.ResponseWriter, cw *apiResponseCapture, body []byte, modified bool) {
	h := w.Header()
	switch {
	case responseHasTrailers(h):
		h.Del("Content-Length")
	case modified:
		h.Set("Content-Length", strconv.Itoa(len(body)))
	case h.Get("Content-Length") == "" && bodyAllowedForStatus(cw.status):
		h.Set("Content-Length", strconv.Itoa(len(body)))
	}
	if modified {
		h.Del("ETag")
		h.Del("Content-MD5")
		h.Del("Content-Range")
	}
	w.WriteHeader(cw.status)
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			g.logger.Warn("api response write-back failed", zap.Error(err),
				zap.String("endpoint_key", cw.endpointKey), zap.String("request_id", cw.requestID))
		}
	}
}

// responseHasTrailers 响应是否声明 Trailer（Trailer 公告头或已写入 TrailerPrefix 键）。
func responseHasTrailers(h http.Header) bool {
	if h.Get("Trailer") != "" {
		return true
	}
	for k := range h {
		if strings.HasPrefix(k, http.TrailerPrefix) {
			return true
		}
	}
	return false
}

// bodyAllowedForStatus 响应状态是否允许携带 body（1xx/204/304 不允许）。
func bodyAllowedForStatus(status int) bool {
	return status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// writeFailClosedResponse FAIL_CLOSED 抑制响应：500 + 空明细 JSON 体（不含上游任何内容）。
// 仅在不曾外发字节（缓冲/抑制模式扣留状态行）时调用。
func (g *Guard) writeFailClosedResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Del("Content-Encoding")
	h.Del("ETag")
	h.Del("Content-MD5")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "response_processing_failed",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusInternalServerError)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("fail-closed response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

// runAPIProtection 执行统一管线请求相位；handled=true 表示已按决策拦截（阻断事件在此输出）。
// 拦截响应两种形态：err 为 caddyhttp.Error（响应经 Caddy 错误链渲染，阻断页）；
// 或 err=nil 且响应已由本函数直接写出（准入拒绝统一 JSON，见 ActionBlock 准入分支——
// w 仅供该分支直接回包使用，其余路径不触碰）。
func (g *Guard) runAPIProtection(w http.ResponseWriter, r *http.Request, start time.Time) (*pipeline.Result, bool, error) {
	restore, bodySample, skipReason := preserveRequestBody(r)
	bodyPreserveSkipped := restore == nil
	pipeReq := r
	if bodyPreserveSkipped {
		// C-10：请求体超 4MiB 保全上限或读体失败时不再整体跳过 API 管线，
		// 保持 r.Body 原样留给下游，克隆元数据请求（Body=http.NoBody）继续执行
		// URL/方法/头/Query/身份/准入/BOLA/BFLA/限速/强流程/大报文 fail-closed 检查。
		g.warnAPIBodyPreserveSkipped(r, skipReason)
		pipeReq = r.Clone(r.Context())
		pipeReq.Body = http.NoBody
	} else {
		defer restore()
	}

	// 端点键与管线内部同一算法，用于按端点选取冻结模型与参数约束
	ek := normalizer.EndpointKey(r.Method, r.URL.Path)
	// webshell C2 会话行为观测（BAS 覆盖基线，请求相位）：体统计样本只能由读体处供给
	// （parser 之后 r.Body 已消费；样本仅请求内存活，不落证据）；不挂 api.IsAPI 分类门槛——
	// WebShell 端点通常非 API 分类，分类漏判不应关掉观测；只记账不产明细，
	// 评估在响应收束处（见 pipeline webshellc2 挂点）
	if !bodyPreserveSkipped {
		pipeline.ObserveWebShellC2RequestWithStores(r, g.IdentitySalt, bodySample, g.behaviorStores)
	}
	dispo := DispositionFrom(r.Context())
	// API 受限例外（WDSP P0-04；契约 S4_DESIGN_BASELINE §6/§10）：按请求事实范围筛选
	// （domain/path/method/可信 IP/当前 UTC 秒；clientIP 为可信代理处理后值），结果传入
	// 决策引擎 Finding 级豁免重算；适用例外版本记入 disposition effective_config。
	var apiExcRefs []decision.ExceptionRef
	var apiExcList []APIException
	if len(g.apiExceptions) > 0 {
		apiExcList = g.apiExceptions[g.AppCode]
		if len(apiExcList) > 0 {
			clientIP := ""
			if cres, ok := clientIPResultFrom(r.Context()); ok {
				clientIP = cres.ClientIP.String()
			}
			apiExcRefs = FilterAPIExceptions(apiExcList, r.Host, r.URL.Path, r.Method, clientIP, start.Unix())
			for _, ref := range apiExcRefs {
				dispo.NoteExceptionVersion(ref.ExceptionID, ref.Version)
			}
		}
	}
	var jwtVerification *jwtverify.VerificationResult
	if jwtRes, ok := jwtResultFrom(r.Context()); ok {
		jwtCopy := jwtRes
		jwtVerification = &jwtCopy
	}
	cfg := pipeline.Config{
		Enabled:          true,
		Mode:             apiDecisionMode(g.APIProtectionMode),
		Limits:           g.apiParseLimits(),
		FormalSchema:     g.APIFormalSchemas[ek],
		ParamConstraints: g.APIParameterConstraints[ek],
		KnownEndpoints:   g.APIKnownEndpoints,
		// API 准入策略（WDSP P1，发布通道下发 api_admission 段；按本实例 AppID 解析，
		// nil = 应用未识别/无策略——不判定直接放行；判定口径见 detectors/admission.go）
		Admission:             g.apiAdmissionPolicyForApp(),
		APIWriteRatePerMinute: g.APIWriteRatePerMinute,
		// §36 限流下发面（发布通道下发；0 = 不启用，不走引擎默认值）
		APIQuotaPerHour:         g.APIQuotaPerHour,
		APIQuotaPerDay:          g.APIQuotaPerDay,
		ObjectRatePerMinute:     g.ObjectRatePerMinute,
		CredentialRatePerMinute: g.CredentialRatePerMinute,
		TenantRatePerMinute:     g.TenantRatePerMinute,
		ActionRatePerMinute:     g.ActionRatePerMinute,
		APIEndpointActions:      g.APIEndpointActions,
		GroupRatePerMinute:      g.GroupRatePerMinute,
		APIEndpointGroups:       g.APIEndpointGroups,
		RateLimitAction:         normalizedAPIRateLimitAction(g.APIRateLimitAction),
		MaxPageSize:             g.MaxPageSize,
		MaxBatchSize:            g.MaxBatchSize,
		IdentitySalt:            g.IdentitySalt,
		// 值级敏感检测规则（发布通道下发；空 = 关闭值级检测，零行为变化）
		SensitiveValueRules: g.APISensitiveValueRules,
		// 授权基线（发布通道下发；按端点选取，nil = 无端点基线，BFLA/字段权限检测零行为）
		RoleBaselines:    g.apiRoleBaselines[ek],
		FieldPermissions: g.apiFieldPerms[ek],
		// 已确认参数条件关系（发布通道下发；按端点选取，nil = 无端点关系，关系检测零行为）
		ParamRelations: g.apiParamRelations[ek],
		// 业务流程基线（发布通道下发 api_flow_baselines，§44；Provision 按端点归组后选取，
		// nil = 无端点流程基线，流程偏离检测零行为，不编造基线；全部明细 OBSERVE 级）
		FlowBaselines: g.apiFlowBaselines[ek],
		// 强流程定义绑定与运行时（NG-FLOW-02；Provision 装配产物；nil = 无端点强流程
		// 定义，强流程检测零行为 NG-T-C01；与 api_flow_baselines 观察态互不消费）
		StrongFlows:       g.apiStrongFlowIndex[ek],
		StrongFlowRuntime: g.strongFlowRuntime,
		// mcpguard 装配置与候选请求体（NG-MCP G1 批次 B2：Provision 装配产物；
		// nil = 无目录且无绑定零行为 NG-T-C01；候选体为保全的完整请求体
		// （≤4MiB 保全同源——协议专属预算不经公共 1MiB 解析上限与 256 截留））
		MCPGuard: g.apiMCPGuard,
		MCPBody:  bodySample,
		// 已吊销凭据清单（发布通道下发 api_revoked_credentials，§35 第10项；Provision 已校验；
		// nil = 无吊销清单，吊销检测零行为；运行期按请求凭据键集合比对，过期条目自行失效）
		RevokedCredentials: g.APIRevokedCredentials,
		// 同凭据环境异常阈值（≤0 由引擎默认值兜底）
		CredentialIPSpreadLimit:    g.CredentialIPSpreadLimit,
		CredentialConcurrencyLimit: g.CredentialConcurrencyLimit,
		// 应用标识（同凭据跨应用检测；空 = 应用未识别，该项检测跳过）
		ApplicationID: g.AppID,
		// 按应用覆盖的同设备多账号观察阈值；无覆盖保持默认3，只影响观察信号
		SharedDeviceAccountLimit: g.sharedDeviceAccountLimit(),
		// 行为计数存储（nil = 进程内默认内存；valkey 时跨节点共享，故障自动 Fail-open 回内存）
		Stores: g.behaviorStores,
		// 版本快照（Finding 逐条盖章 model_version/policy_version，溯源"当时生效哪版"）
		PolicyVersion: g.APIPolicyVersion,
		ModelVersion:  g.APIFormalModelVersions[ek],
		// 扫描流量识别密钥（nil = 未下发，仅按 X-JiuZhang-Scan 头存在性识别）
		ScanVerificationKey: g.apiScanKey,
		// LLM 授权模型名单（nil/空 = 不下发不判定未授权模型；识别与观测不依赖名单）
		LLMAllowedModels: g.APILLMAllowedModels,
		// 当前应用的 LLM 输入保护策略（nil = 保持既有行为）
		LLMSecurityPolicy: g.llmSecurityPolicyForApp(),
		// 文件合规规则（发布通道下发 api_file_compliance_rules，上传方向；nil = 上传侧检测零行为）
		FileComplianceRules: g.apiFileCompliance,
		// gRPC 帧校验配置（W14-GW / P2-05：发布通道下发 api_grpc_*；零值 = 引擎默认 4MiB/不允许压缩）
		GRPCMaxFrameBytes:    g.APIGRPCMaxFrameBytes,
		GRPCAllowCompression: g.grpcCompressionAllowLegacy(),
		// gRPC 描述符注册表（W14-DESC / P2-05 深化：Provision 装配产物；
		// nil = 无描述符下发或全部编译失败，gRPC 处理与 v1 完全一致）
		GRPCDescriptors: g.apiGRPCRegistry,
		// grpcguard G1 深检执行配置与帧源（NG-GRPC 批次 B2：Provision 装配产物；
		// nil = 无描述符且无绑定，grpcguard 零行为 NG-T-C01。帧源为保全的完整请求体
		// （≤4MiB 保全上限，既有 fail-open 纪律），G1 协议专属读取预算不经公共 1MiB
		// 解析上限；体 >4MiB 跳过管线（body_preserve_skipped 既有披露路径））
		GRPCGuard: g.apiGRPCGuard,
		GRPCBody:  bodySample,
		// GraphQL 成本预算策略（NG-GQL-03，发布通道下发 api_graphql 段按应用解析；
		// nil = 未配置，GraphQL 流量与历史版本零行为变化）
		GraphQL: g.apiGraphQLPolicyForApp(),
		// API 受限例外（WDSP P0-04）：上方范围筛选结果；nil = 无适用例外，零行为变化
		Exceptions: apiExcRefs,
		// 执行覆盖观测（NG-COV-01）：nil = 未启用（COVERAGE_OBSERVATIONS_ENABLED 缺省关闭），零行为
		Coverage: coverageEmitter(),
		NodeName: coverageNodeName(),
		Authorization: detectors.AuthorizationConfig{
			ApplicationID:     g.AppID,
			EndpointKey:       ek,
			Models:            g.APIAuthzModels,
			Relations:         g.APIAuthzRelations,
			RelationIndex:     g.apiAuthzRelationIndex,
			RoleBaselines:     g.APIAuthzRoleBaselines,
			ObjectRefHMACKey:  g.APIAuthzObjectHMACKey,
			PolicyVersion:     g.APIPolicyVersion,
			Stale:             g.APIAuthzSnapshotStale,
			SnapshotExpiresAt: g.APIAuthzSnapshotExpiresAt,
			PreviousValid:     g.apiAuthzPreviousValid,
			// NG-AZ-02 v2 快照消费输入（D4-2/D5/D7/D8；零值即 v1 语义零介入——
			// 租约应用时刻取注册表（Provision 写入），漂移上限用解析夹紧后配置值）
			Schema:              g.APIAuthzSchema,
			RevocationWatermark: authzWatermarkToDetectors(g.APIAuthzRevocationWatermark),
			LeaseSeconds:        g.APIAuthzLeaseSeconds,
			AppliedAt:           g.authzSnapshotAppliedAt(),
			ConflictedObjects:   authzConflictsToDetectors(g.APIAuthzConflictedObjects),
			ConflictedIndex:     detectors.BuildConflictedObjectIndex(authzConflictsToDetectors(g.APIAuthzConflictedObjects)),
			ProducedAt:          g.APIAuthzProducedAt,
			ClockSkewMaxSeconds: g.APIAuthzClockSkewMaxSeconds,
		},
		JWTVerification:          jwtVerification,
		BodyPreserveSkipped:      bodyPreserveSkipped,
		BodyPreserveSkipReason:   skipReason,
		BodyInspectionFailClosed: g.responseFailClosed(),
	}
	DefaultCovCounters.Inc(StageAPIPipelineReached)
	res, err := pipeline.Process(pipeReq, cfg, nil)
	if err != nil {
		g.logger.Warn("api protection pipeline error (fail-open)", zap.Error(err))
		return nil, false, nil
	}
	if res == nil || res.Skipped {
		return res, false, nil
	}

	// P0-04：例外命中的 Finding（决策侧已打标 Excepted）写 disposition.matched_exceptions
	// 与 EXCEPTED 步骤——例外命中可审计是契约要求（证据保留于事件 matches 不变）
	if len(apiExcRefs) > 0 {
		matches := res.Context.CopyMatches()
		excepted := 0
		for _, m := range matches {
			if !m.Excepted {
				continue
			}
			excepted++
			exc := findAPIExceptionByID(apiExcList, m.ExceptionID)
			dispo.RecordMatchedException(m.ExceptionID, m.ExceptionVersion, "API",
				[]string{m.Detector + ":" + m.RuleID}, apiExceptionScopeSummary(exc),
				apiExceptionTimeFrom(exc), apiExceptionTimeUntil(exc))
		}
		if excepted > 0 {
			dispo.RecordStep(ExecutorAPI, StepExcepted, fmt.Sprintf("excepted_findings=%d", excepted))
		}
	}

	// APM 阶段1（D6）：桥接请求级关联字段进统一 RequestContext（原死字段填充）
	g.bridgeRequestContext(r, res.Context)
	// 任务书 §7：设备指纹与对象标识哈希进统一上下文（parser 纯函数，零网络 IO）
	g.enrichContextIdentifiers(r, res.Context, res.Parsed)

	// 统一上下文随请求传递，供下游复用
	*r = *r.WithContext(context.WithValue(r.Context(), requestContextKey{}, res.Context))

	// 阻断类动作：事件在阻断时输出（状态码按决策映射；放行请求的事件在响应完成后输出，见 serveAPIProtected）
	// P0-04：RecordTerminal 先于 emitBlocked——事件 final_decision 挂载需终止事实已记录
	// （emitAPIEvent 经 Settled 门禁取 dispo.JSON()）；committed=false——caddyhttp.Error
	// 路径响应由 Caddy 错误链写出，此处未提交（准入分支直接写出，committed=true）；
	// ruleRefs 取执法贡献明细（未被例外豁免）
	emitBlocked := func(status int) {
		if res.API.IsAPI || len(res.Context.CopyMatches()) > 0 || len(flowguard.ActionsFromContext(res.Context)) > 0 {
			g.emitAPIEvent(r, res, &apiEventTail{status: status, latencyMS: time.Since(start).Milliseconds()})
		}
	}
	switch res.FinalAction {
	case dsctx.ActionBlock:
		matches := res.Context.CopyMatches()
		// API 准入拒绝（WDSP P1）：统一 403 JSON（unknown/unconfirmed 不区分，防资产探测，
		// 设计 §4.1/§7），本函数直接写出，不经 Caddy 错误链阻断页（API 调用方按协议消费
		// JSON）；committed=true——响应已提交。其余 BLOCK 来源维持既有 caddyhttp.Error
		// 路径与既有响应格式（阻断页）不变。
		if admissionBlockMatched(matches) {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
				[]string{"API_ADMISSION_DENIED"}, apiEnforcementRuleRefs(matches))
			emitBlocked(http.StatusForbidden)
			g.writeAPIAdmissionDeniedResponse(w, res.Context.RequestID)
			return res, true, nil
		}
		// GraphQL 成本/准入拒绝（NG-GQL-03）：403 + GraphQL 协议错误语义 JSON
		// （{"errors":[...extensions.code=<reason>]}，API 调用方按 GraphQL 协议消费，
		// 非 WAF HTML 阻断页）；committed=true。reason 取首条 BLOCK 明细的
		// evidence.reason（GQL_ADMISSION_REJECTED/GQL_COST_EXCEEDED/GQL_WINDOW_EXCEEDED）。
		if reason, ok := graphqlBlockReason(matches); ok {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
				[]string{reason}, apiEnforcementRuleRefs(matches))
			emitBlocked(http.StatusForbidden)
			g.writeGraphQLDeniedResponse(w, res.Context.RequestID, reason)
			return res, true, nil
		}
		// API 授权实断（NG-AZ-03 VERIFIED_VIOLATION）：403 + 规范 JSON
		// （{"code":"AUTHZ_VIOLATION_DENIED",...}，不泄露对象/主体细节——防探测；
		// 本函数直接写出 committed=true，不经 Caddy 错误链阻断页）。authz_enforcement
		// 证据（§1.4）先于 emitBlocked 挂 disposition——随 final_decision 落库，
		// 「为什么被实断」可答（八因子/版本/水位/租约读数/enforcement_owner）。
		if authzBlockMatched(matches) {
			if ev := detectors.AuthzEnforcementEvidenceFromContext(res.Context); ev != nil {
				dispo.SetAuthzEnforcement(ev)
			}
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
				[]string{"AUTHZ_VIOLATION_DENIED"}, apiEnforcementRuleRefs(matches))
			emitBlocked(http.StatusForbidden)
			g.writeAPIAuthzDeniedResponse(w, res.Context.RequestID)
			return res, true, nil
		}
		// 强流程违规实断（NG-FLOW-02 D6）：403 统一 JSON（{"code":"FLOW_VIOLATION_DENIED",…}
		// 不泄露实例/步骤细节——防探测；本函数直接写出 committed=true，不经 Caddy 错误链
		// 阻断页）。UNKNOWN 恒不阻断（红线）：flowguard 的 BLOCK 明细仅可能来自
		// REJECTED/CONFLICT 违规（flowguard.violation）；真实原因（FLOW-RESERVE-001/
		// FENCE-001/IDEMPOTENT-CONFLICT-001）只落事件 details 与 strong_flow 条目。
		if flowguardBlockMatched(matches) {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
				[]string{"FLOW_VIOLATION_DENIED"}, apiEnforcementRuleRefs(matches))
			emitBlocked(http.StatusForbidden)
			g.writeAPIStrongFlowDeniedResponse(w, res.Context.RequestID)
			return res, true, nil
		}
		// gRPC G1 深检实断（NG-GRPC D6）：gRPC 请求按 api.protocol=GRPC 分流——
		// trailers-only 响应（HTTP 200 + content-type: application/grpc +
		// grpc-status/grpc-message + 无体 END_STREAM 语义），grpc-message 固定短语
		// 不泄露策略/字段细节（防探测——AZ-03 统一体同纪律）；真实原因只落事件
		// details 与 grpc.coverage_v1。本函数直接写出 committed=true，不经 Caddy
		// 错误链阻断页（gRPC 调用方按协议消费 grpc-status，非 WAF HTML 阻断页）。
		if grpcStatus, ok := grpcguardBlockStatus(matches); ok {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusOK, true,
				[]string{"GRPC_STATUS_" + strconv.Itoa(grpcStatus)}, apiEnforcementRuleRefs(matches))
			emitBlocked(http.StatusOK)
			g.writeAPIGRPCErrorResponse(w, res.Context.RequestID, grpcStatus)
			return res, true, nil
		}
		// MCP G1 检查链实断（NG-MCP D11）：JSON-RPC 错误对象分流——错误码取首条
		// BLOCK 明细的 mcp_error_code/mcp_http_status 证据（-32010~-32014 冻结表，
		// HTTP 403/413/429 分明）；id 回显请求 id（mcp.call 上下文 Message.ID，
		// 未携 id 回显 null）；message 固定短语不泄露策略/工具细节（防探测），
		// 真实原因只落事件 details 与 mcp.coverage_v1。本函数直接写出
		// committed=true，不经 Caddy 错误链阻断页（MCP 调用方按 JSON-RPC 协议消费）。
		if mcpCode, mcpHTTP, ok := mcpguardBlockInfo(matches); ok {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, mcpHTTP, true,
				[]string{"MCP_ERROR_" + strconv.Itoa(mcpCode)}, apiEnforcementRuleRefs(matches))
			emitBlocked(mcpHTTP)
			g.writeMCPErrorResponse(w, res.Context.RequestID, mcpCode, mcpHTTP, mcpRequestIDRaw(res.Context))
			return res, true, nil
		}
		if bodyTooLargeFailClosedMatched(matches) {
			dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusRequestEntityTooLarge, true,
				[]string{"BODY_TOO_LARGE_FAIL_CLOSED"}, apiEnforcementRuleRefs(matches))
			accessLogAnnotate(r.Context(), wafActionBlock)
			emitBlocked(http.StatusRequestEntityTooLarge)
			g.writeAPIBodyTooLargeResponse(w, res.Context.RequestID)
			return res, true, nil
		}
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, false,
			[]string{"API_POLICY_BLOCK"}, apiEnforcementRuleRefs(matches))
		emitBlocked(http.StatusForbidden)
		return res, true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("request blocked by api protection"))
	case dsctx.ActionRateLimit:
		// MCP 调用预算实断（NG-MCP §1.4-5/-32013=429 语义）：mcpguard RATE_LIMIT
		// 类明细分流 JSON-RPC 错误对象（committed 直写；其余限速来源维持
		// 既有 caddyhttp.Error 429 平面）
		if mcpCode, mcpHTTP, ok := mcpguardBlockInfo(res.Context.CopyMatches()); ok {
			dispo.RecordTerminal(ExecutorAPI, DisActionRateLimit, mcpHTTP, true,
				[]string{"MCP_ERROR_" + strconv.Itoa(mcpCode)}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
			emitBlocked(mcpHTTP)
			g.writeMCPErrorResponse(w, res.Context.RequestID, mcpCode, mcpHTTP, mcpRequestIDRaw(res.Context))
			return res, true, nil
		}
		dispo.RecordTerminal(ExecutorAPI, DisActionRateLimit, http.StatusTooManyRequests, false,
			[]string{"API_RATE_LIMIT"}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
		emitBlocked(http.StatusTooManyRequests)
		return res, true, caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("api request rate limited"))
	case dsctx.ActionTempBlock:
		dispo.RecordTerminal(ExecutorAPI, DisActionTempBlock, http.StatusForbidden, false,
			[]string{"API_TEMP_BLOCK"}, apiEnforcementRuleRefs(res.Context.CopyMatches()))
		g.createAPIRateLimitTempBlock(r, res.Context.RequestID, dispo.JSON())
		emitBlocked(http.StatusForbidden)
		return res, true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("api client temporarily blocked"))
	default:
		// OBSERVE 定案：观察命中进 steps（不进 security_action）
		if res.FinalAction == dsctx.ActionObserve && len(res.Context.CopyMatches()) > 0 {
			dispo.RecordStep(ExecutorAPI, StepObserved, "final_action=OBSERVE")
		}
		return res, false, nil
	}
}

// maxBodyPreserveBytes API 管线读体上限（必须大于 parser 的 MaxBodyParseBytes，否则
// parser 的截断+采样路径永远不会触发而成为死代码——code-review HIGH-7）。
// parser 自身按 dsctx.DefaultParseLimits（MaxBodyParseBytes=1MiB）限流读取，超限截断为
// MaxBodySampleBytes（64KiB）样本并置 BodyTruncated；guard 上限取 4MiB：
//   - ≤1MiB：完整解析，行为不变；
//   - 1MiB~4MiB：不再整体跳过，走 parser 截断采样路径——文件上传合规、gRPC 帧校验、
//     Prompt 注入、参数约束等请求侧检测对样本前缀仍生效；
//   - >4MiB：不整包入内存（防 OOM），跳过管线 fail-open，原请求体完整交给下游，
//     同时落 OBSERVE 明细事件 + 节流 Warn（不静默）。
const maxBodyPreserveBytes = 4 << 20 // 4 MiB

// preserveRequestBody 在上限内读出请求体并还原；返回的 restore 用于管线结束后再次还原给下游，
// bodySample 为读出的完整请求体（webshell C2 请求相位观测的体统计样本由此供给，仅请求内存活；
// GET/HEAD 无体为 nil）。restore 返回 nil 表示读取失败或报文超限（Body 已完整还原给下游，
// 调用方应跳过管线），skipReason 说明跳过原因（供事件明细与告警留痕）。
func preserveRequestBody(r *http.Request) (restore func(), bodySample []byte, skipReason string) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return func() {}, nil, ""
	}
	// Content-Length 已知且超限：不读入内存，Body 原样留给下游，跳过管线
	if r.ContentLength > maxBodyPreserveBytes {
		return nil, nil, "content_length_exceeds_preserve_limit"
	}
	// 限流读：多读 1 字节探测是否超限
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodyPreserveBytes)+1))
	if err != nil {
		// 已读部分 + 剩余流拼回，跳过管线
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil, nil, "body_read_error"
	}
	if len(b) > maxBodyPreserveBytes {
		// 超限：已读字节 + 剩余 Body 拼回完整流，不截断下游，跳过管线
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil, nil, "body_exceeds_preserve_limit"
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return func() { r.Body = io.NopCloser(bytes.NewReader(b)) }, b, ""
}

// bodySkipWarnInterval 大体跳过告警的节流窗口（进程级；OBSERVE 事件本身逐条落盘不节流）。
const bodySkipWarnInterval = time.Minute

// bodySkipWarnLast 上次跳过告警时刻（UnixNano；CAS 节流，防大报文洪泛刷日志）。
var bodySkipWarnLast atomic.Int64

func bodyTooLargeFailClosedMatched(matches []dsctx.DetectorMatch) bool {
	for _, m := range matches {
		if m.Excepted {
			continue
		}
		if m.RuleID == "request.body_too_large_fail_closed" && strings.EqualFold(m.Category, "BLOCK") {
			return true
		}
	}
	return false
}

func (g *Guard) writeAPIBodyTooLargeResponse(w http.ResponseWriter, requestID string) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "payload_too_large",
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusRequestEntityTooLarge)
	if _, err := w.Write(body); err != nil {
		g.logger.Warn("api body too large response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

func (g *Guard) warnAPIBodyPreserveSkipped(r *http.Request, reason string) {
	now := time.Now()
	if last := bodySkipWarnLast.Load(); now.UnixNano()-last >= int64(bodySkipWarnInterval) &&
		bodySkipWarnLast.CompareAndSwap(last, now.UnixNano()) {
		g.logger.Warn("api request body not preserved: running metadata-only pipeline (body-dependent PROTECT/FAIL_CLOSED policies enforce fail-closed)",
			zap.String("reason", reason),
			zap.String("endpoint_key", normalizer.EndpointKey(r.Method, r.URL.Path)),
			zap.Int64("content_length", r.ContentLength),
			zap.Int("preserve_limit_bytes", maxBodyPreserveBytes))
	}
}

// noteAPIBodyPreserveSkipped 请求体无法保全（读取失败/超 maxBodyPreserveBytes）导致 API
// 动态防护请求相位被跳过时的可见性留痕（code-review HIGH-7）：节流 Warn + OBSERVE 明细事件
// （rule_id=request.body_preserve_skipped，final_action=OBSERVE，response_status=0 未采集；
// 不产阻断语义、不冒充已检测）。定性限定：仅 API 动态防护请求相位被跳过，
// 下游 Coraza/CRS 检测不受影响（请求体已完整还原交给下游）。
func (g *Guard) noteAPIBodyPreserveSkipped(r *http.Request, start time.Time, reason string) {
	now := time.Now()
	if last := bodySkipWarnLast.Load(); now.UnixNano()-last >= int64(bodySkipWarnInterval) &&
		bodySkipWarnLast.CompareAndSwap(last, now.UnixNano()) {
		g.logger.Warn("api request phase skipped: request body not preserved (fail-open, request-side detections degraded for this request)",
			zap.String("reason", reason),
			zap.String("endpoint_key", normalizer.EndpointKey(r.Method, r.URL.Path)),
			zap.Int64("content_length", r.ContentLength),
			zap.Int("preserve_limit_bytes", maxBodyPreserveBytes))
	}
	if g.apiEvents == nil {
		return
	}
	// 合成最小管线结果复用 emitAPIEvent（保持事件字段口径一致：域名/指纹/身份/版本戳）；
	// 体未保全无法分类，IsAPI 如实置 false
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = r.Header.Get("X-Jiuzhang-Request-ID")
	}
	rc := dsctx.New(reqID, g.apiParseLimits())
	rc.PolicyVersion = g.APIPolicyVersion
	rc.SetFinalAction(dsctx.ActionObserve)
	g.bridgeRequestContext(r, rc)
	evidence := map[string]string{"reason": reason}
	if r.ContentLength >= 0 {
		evidence["content_length"] = strconv.FormatInt(r.ContentLength, 10)
	}
	rc.AddMatch(dsctx.DetectorMatch{
		Detector:   "api_request",
		RuleID:     "request.body_preserve_skipped",
		Category:   "OBSERVE",
		Severity:   "HIGH",
		Message:    "api request phase skipped: request body exceeds preserve limit or read failed (fail-open)",
		Confidence: 1.0,
		Evidence:   evidence,
	})
	res := &pipeline.Result{
		Context: rc,
		Parsed: &parser.Parsed{
			Method:         strings.ToUpper(r.Method),
			RawPath:        r.URL.Path,
			NormalizedPath: normalizer.NormalizePath(r.URL.Path),
		},
		EndpointKey: normalizer.EndpointKey(r.Method, r.URL.Path),
		FinalAction: dsctx.ActionObserve,
	}
	// §7 字段：体未保全不影响头部设备指纹与路径侧对象标识产出
	g.enrichContextIdentifiers(r, rc, res.Parsed)
	g.emitAPIEvent(r, res, &apiEventTail{latencyMS: time.Since(start).Milliseconds()})
}

// apiEventTail 事件响应侧尾注（状态码/耗时）；nil 表示响应前输出（状态码置 0）。
type apiEventTail struct {
	status    int
	latencyMS int64
}

// emitAPIEvent 构建并输出统一运行时主事件（含端点发现信息）；输出失败仅告警，不影响请求。
func (g *Guard) emitAPIEvent(r *http.Request, res *pipeline.Result, tail *apiEventTail) {
	// 阶段3 Risk Engine：统一管线 DetectorMatch（ScoreDelta>0）汇入身份风险累加器——
	// emitAPIEvent 为每请求唯一事件出口，此时明细已完整（含响应相位与 Coraza 归因补记的
	// waf SQLi +50）；identitybehavior 信号非 DetectorMatch，不经此路径（无双计）
	if g.risk != nil && res != nil && res.Context != nil {
		g.feedRiskSignals(r, res.Context.CopyMatches())
	}
	if g.apiEvents == nil || res == nil || res.Context == nil {
		return
	}
	pe := dsevents.BuildPrimary("", res.Context, res.EndpointKey)
	rec := apievents.Record{
		RequestID:     pe.RequestID,
		OccurredAt:    pe.OccurredAt,
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		// APM 阶段1（D6）：trace 关联键取自桥接后的统一上下文（入口生成，不回传不注入）
		TraceID:       res.Context.TraceID,
		EndpointKey:   pe.EndpointKey,
		RiskScore:     pe.RiskScore,
		RiskLevel:     pe.RiskLevel,
		FinalAction:   pe.FinalAction,
		Details:       pe.Details,
		AuthzDecision: pe.AuthzDecision,
		// 强流程步骤动作条目（NG-FLOW-02；无强流程活动为 nil，事件零变化）
		StrongFlow:    pe.StrongFlow,
		IsAPI:         res.API.IsAPI,
		APIConfidence: res.API.Confidence,
		// 策略版本戳原样透传；FORMAL 模型版本按端点命中（未下发则省略）
		PolicyVersion: g.APIPolicyVersion,
		ModelVersion:  g.APIFormalModelVersions[res.EndpointKey],
		// 任务书 §7：被动设备指纹与对象标识哈希（统一上下文快照；空值经 omitempty 省略）
		DeviceFingerprint: pe.DeviceFingerprint,
		ObjectIdentifiers: pe.ObjectIdentifiers,
	}
	if res.Parsed != nil {
		rec.Method = res.Parsed.Method
		rec.PathTemplate = res.Parsed.NormalizedPath
		rec.RawPath = res.Parsed.RawPath // 归一化前路径、不含 query（Emit 时封顶 512 字符）
	}
	// 协议可见性（W14-GW）：proto 记录 HTTP 协议版本（r.Proto 原样：HTTP/1.1/2.0/3，
	// 空 = 不可得省略）；protocol 记录应用层协议族（§9 词表：GRPC/GRAPHQL/SOAP/JSON_RPC/
	// SSE/FILE_UPLOAD/FILE_DOWNLOAD/WEBHOOK/REST_JSON 等；非 API 普通流量省略保持事件
	// 零变化，采集端按缺省 REST 口径消费）。
	rec.Proto = r.Proto
	if v, ok := res.Context.GetExtension("api.protocol"); ok {
		if s, ok := v.(string); ok {
			rec.Protocol = s
			// gRPC 路径模板全保留：服务/方法名即端点稳定身份，归一化会破坏方法名语义
			if s == "GRPC" && res.Parsed != nil {
				rec.PathTemplate = res.Parsed.RawPath
			}
		}
	}
	// §8.2 四级识别标签：取管线写入的 ctx 扩展 api.classification（与 is_api/api_confidence
	// 同源同分）；未写（fail-open 旁路等）则保持空值经 omitempty 省略，不编造。
	if v, ok := res.Context.GetExtension("api.classification"); ok {
		if s, ok := v.(string); ok {
			rec.APILevel = s
		}
	}
	rec.Domain = requestHost(r)
	// 响应状态码与耗时：响应完成后输出的事件携带真实状态码（tail 非空）；
	// 阻断类按决策映射 403/429；响应前输出（非 API 命中）置 0（未采集）。
	if tail != nil {
		rec.ResponseStatus = tail.status
		rec.LatencyMS = tail.latencyMS
	}
	if rec.ResponseStatus == 0 {
		switch res.FinalAction {
		case dsctx.ActionBlock, dsctx.ActionTempBlock:
			rec.ResponseStatus = http.StatusForbidden
		case dsctx.ActionRateLimit:
			rec.ResponseStatus = http.StatusTooManyRequests
		}
	}
	// 来源/身份指纹：r.RemoteAddr 已被入口中间件改写为真实客户端 IP（module.go），
	// 统一 HMAC-SHA256 截断指纹（detectors.Fingerprint，盐来自 identity_salt），不可逆不落明文。
	if ip, err := clientip.ConnectionIP(r); err == nil && ip.IsValid() {
		rec.ClientIP = ip.String()
		rec.SourceFingerprint = detectors.Fingerprint(g.IdentitySalt, ip.String())
	}
	// 身份指纹仅凭据派生（auth:/key:/sess:）；无凭据为匿名置空——IP 属环境维度，不得冒充身份
	rec.IdentityFingerprint = detectors.CredentialKey(r, g.IdentitySalt)
	// 认证方式由身份信号检测器写入上下文（匿名为空串）
	rec.AuthType = res.Context.AuthenticationType
	// 参数值脱敏观测：仅 API 流量上报，供管理面 statistics 回填（无明文）
	if res.API.IsAPI && res.Parsed != nil {
		// 隐私增强接线：值指纹 HMAC 加盐（identity_salt，缺盐走固定域分隔前缀）；
		// 敏感词表命中（键名/值级规则）的参数不上报原值与值指纹。编译走并发安全
		// 缓存（Provision 已预检），理论上的编译失败保守回退兼容入口
		patterns, perr := detectors.CompileSensitivePatterns(nil)
		valueRules, verr := detectors.CompileSensitiveValueRules(g.APISensitiveValueRules)
		if perr == nil && verr == nil {
			rec.ParamObservations = apievents.ExtendParamObservations(
				detectors.CollectParamObservationsSecure(res.Parsed, g.IdentitySalt, patterns, valueRules),
				res.Parsed, g.IdentitySalt)
		} else {
			rec.ParamObservations = apievents.ExtendParamObservations(
				detectors.CollectParamObservations(res.Parsed), res.Parsed, g.IdentitySalt)
		}
	}
	// 响应结构观测（P0-06）：仅 API 流量且响应相位已产出（捕获到合法 JSON）时挂事件；
	// 非 JSON/截断/流式/非 API 均为 nil，事件保持零变化
	if res.API.IsAPI {
		if rc := res.Context.GetResponse(); rc != nil && rc.Observation != nil {
			rec.ResponseObservations = []dsctx.ResponseObservation{*rc.Observation}
		}
	}
	// 文件传输观测（P1-04 文件资产）：仅 API 流量；上传来自 multipart 文件 part 元数据
	// （阻断类事件同样带观测——被拦的上传尝试仍属资产盘点原料），下载来自响应相位
	// Content-Disposition 观测；均无文件时保持 nil，事件零变化
	if res.API.IsAPI {
		if res.Parsed != nil && len(res.Parsed.MultipartParts) > 0 {
			rec.FileObservations = append(rec.FileObservations, parser.BuildUploadFileObservations(res.Parsed.MultipartParts)...)
		}
		if rc := res.Context.GetResponse(); rc != nil && rc.FileObservation != nil {
			rec.FileObservations = append(rec.FileObservations, *rc.FileObservation)
		}
	}
	// LLM API 观测（P2-04）：识别为 LLM 端点的流量携带（请求相位产出，响应相位
	// 已补全 token 用量与 stream 标记；阻断类事件带请求侧观测——被拦的注入尝试
	// 仍属观测原料）；非 LLM 流量为 nil，事件零变化
	if obs := res.Context.GetLLMObservation(); obs != nil {
		rec.LLMObservation = obs
	}
	// JWT 信任链验证摘要（WDSP P0-03）：请求经 jwt_trust 范围内评估时携带
	// jwt_verification 可选对象（OFF/范围外 UNVERIFIED 不携带，事件零变化；
	// 不落原始 Token/payload/明文 sub/tenant——tenant 为加盐指纹）
	if jwtRes, ok := jwtResultFrom(r.Context()); ok && jwtRes.Status != jwtverify.StatusUnverified {
		rec.JWTVerification = g.jwtEventDetail(jwtRes)
		// 候选关系只接受“可信 JWT 主体 + HUMAN 观测身份”。identity_behavior 是
		// 可选能力，关闭时统一 RequestContext 没有身份类型，因此这里按同一解析器
		// 补算请求类型；该类型只用于候选防投毒筛选，不提升 JWT 信任等级。
		if id := identitybehavior.IdentityFrom(r.Context()); id != nil {
			rec.JWTVerification.VerifiedIdentityType = id.Type
		} else {
			clientIP := res.Context.ClientIP.String()
			rec.JWTVerification.VerifiedIdentityType = identitybehavior.ResolveIdentity(r, g.IdentitySalt, clientIP).Type
		}
	}
	// 请求最终处置上下文（WDSP P0-04）：仅处置事实已确定（终止/源站完成/错误）时挂载——
	// 响应前输出（非 API 命中、体未保全跳过等）请求仍在途，提前 Finalize 会落 UNKNOWN
	// 并锁死后续记录（Settled 门禁；JSON 内部幂等 Finalize，重复取结果稳定）
	if d := DispositionFrom(r.Context()); d != nil && d.Settled() {
		rec.FinalDecision = d.JSON()
	}
	if err := g.apiEvents.Emit(rec); err != nil {
		g.logger.Warn("api runtime event emit failed", zap.Error(err))
	}
}

// requestHost 取请求 Host（去端口，小写），用于域名归属。
func requestHost(r *http.Request) string {
	h := r.Host
	if i := strings.LastIndex(h, ":"); i > 0 {
		// 仅当冒号后全是数字才按端口处理（避免 IPv6 字面量误截断）
		if _, err := strconv.Atoi(h[i+1:]); err == nil {
			h = h[:i]
		}
	}
	return strings.ToLower(h)
}

// ---------- WDSP P0-04：API 受限例外与处置上下文辅助 ----------

// findAPIExceptionByID 按 exception_id 查适用例外原文（scope 摘要/有效期取数）。
func findAPIExceptionByID(list []APIException, id string) *APIException {
	for i := range list {
		if list[i].ExceptionID == id {
			return &list[i]
		}
	}
	return nil
}

// apiExceptionScopeSummary 例外范围脱敏摘要（契约 §2 scope_summary）：
// 只给维度取值与计数，不落完整 source_ips 清单。
func apiExceptionScopeSummary(exc *APIException) string {
	if exc == nil {
		return ""
	}
	var b strings.Builder
	if exc.Domain != "" {
		fmt.Fprintf(&b, "domain=%s ", exc.Domain)
	}
	if exc.URIExact != "" {
		fmt.Fprintf(&b, "uri_exact=%s ", exc.URIExact)
	}
	if exc.URIPrefix != "" {
		fmt.Fprintf(&b, "uri_prefix=%s ", exc.URIPrefix)
	}
	fmt.Fprintf(&b, "methods=%s", strings.Join(exc.Methods, ","))
	if len(exc.SourceIPs) > 0 {
		fmt.Fprintf(&b, " source_ips=%d条", len(exc.SourceIPs))
	}
	return strings.TrimSpace(b.String())
}

// apiExceptionTimeFrom 例外生效起点（UTC 秒 → time；nil 透传）。
func apiExceptionTimeFrom(exc *APIException) *time.Time {
	if exc == nil || exc.EffectiveFrom == nil {
		return nil
	}
	t := time.Unix(*exc.EffectiveFrom, 0).UTC()
	return &t
}

// apiExceptionTimeUntil 例外生效终点（UTC 秒 → time；nil 透传）。
func apiExceptionTimeUntil(exc *APIException) *time.Time {
	if exc == nil || exc.EffectiveUntil == nil {
		return nil
	}
	t := time.Unix(*exc.EffectiveUntil, 0).UTC()
	return &t
}

// apiEnforcementRuleRefs 执法贡献规则引用（终止事件 rule_refs 取数）：
// 排除被例外豁免（Excepted）与纯信息性（INFO）明细——最终动作的关键规则引用
// 必须真实贡献定案（契约 §2：只记录已执行事实）。格式 detector:rule_id。
func apiEnforcementRuleRefs(matches []dsctx.DetectorMatch) []string {
	var out []string
	for _, m := range matches {
		if m.Excepted {
			continue
		}
		cat := strings.ToUpper(m.Category)
		sev := strings.ToUpper(m.Severity)
		if cat == "INFO" || sev == "INFO" {
			continue
		}
		if m.RuleID == "" {
			continue
		}
		out = append(out, m.Detector+":"+m.RuleID)
	}
	return out
}
