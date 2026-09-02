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
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
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

// apiDecisionMode 解析防护模式；启用但模式未配置时默认 OBSERVE（fail-safe，不放任阻断）。
func apiDecisionMode(s string) decision.Mode {
	switch decision.Mode(s) {
	case decision.ModeOff, decision.ModeObserve, decision.ModeProtect:
		return decision.Mode(s)
	default:
		return decision.ModeObserve
	}
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
		if !g.APIDynamicProtection {
			return next.ServeHTTP(w, r)
		}
		// 同凭据并发记账：入口 +1、出口（检测+下游转发全程结束）-1；匿名不跟踪。
		// pipeline 无请求生命周期钩子，serveNext 放行链路是最接近的真实 in-flight 埋点。
		_, release := detectors.AcquireCredentialInFlight(detectors.CredentialKey(r, g.IdentitySalt))
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
	res, handled, err := g.runAPIProtection(r, start)
	if handled {
		return err
	}
	if res == nil || res.Skipped {
		return next.ServeHTTP(w, r)
	}
	if !res.API.IsAPI {
		// 非 API 流量：无响应捕获，维持响应前输出（状态码 0 语义不变）
		if len(res.Context.CopyMatches()) > 0 {
			g.emitAPIEvent(r, res, nil)
		}
		return next.ServeHTTP(w, r)
	}
	// API 流量：包装捕获响应（脱敏改写的执行前提），响应完成后进入响应相位并输出事件
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
	downloadHold := g.apiFileCompliance.HasDownloadRules()
	cw := newAPIResponseCapture(w, g.responseCaptureMax(), g.responseFailClosed(),
		len(g.apiMaskRules[res.EndpointKey]) > 0, downloadTypes, downloadHold, res.EndpointKey, res.Context.RequestID, g.logger)
	nextErr := next.ServeHTTP(cw, r)
	g.finishAPIResponse(w, cw, r, res, start, nextErr)
	return nextErr
}

// finishAPIResponse 响应收束：响应相位 → MASK_RESPONSE 执行 → 缓冲响应写回 → 事件输出。
// 引擎/转换故障一律按 api_response_fail_policy 处理（FAIL_OPEN 默认放行原响应 + Warn），不 panic、不静默。
// nextErr 非 nil 时跳过响应相位与写回（错误页由 Caddy 错误处理流程写），事件按已捕获状态尽力输出；
// 其中 Coraza 阻断中断（coraza-caddy 哨兵错误）经 attributeWAFIntercept 归因补记（见 apicoraza.go）。
func (g *Guard) finishAPIResponse(w http.ResponseWriter, cw *apiResponseCapture, r *http.Request, res *pipeline.Result, start time.Time, nextErr error) {
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
		}
		g.emitAPIEvent(r, res, tail)
		return
	}

	// 连接劫持：响应已脱离捕获，尽力输出事件（状态码可能为 0 = 未采集到）
	if kind == outcomeHijacked {
		g.emitAPIEvent(r, res, tail)
		return
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
		g.emitAPIEvent(r, res, tail)
		return
	}

	// 响应相位（统一引擎）：JSON 解析/敏感字段/错误签名/transform plan + 响应相位决策
	respIn := pipeline.ResponseInput{
		Status:      status,
		Headers:     redactResponseHeaders(cw.base.Header()),
		BodySize:    int64(cw.body.Len()) + cw.bytesStreamed,
		Truncated:   cw.spilled,
		Streamed:    kind == outcomeStreamed,
		ContentType: cw.base.Header().Get("Content-Type"),
	}
	if kind == outcomeBuffered {
		respIn.Body = cw.body.Bytes()
	} else if cw.spilled && cw.body.Len() > 0 {
		respIn.Body = cw.body.Bytes() // 溢出前缀（Truncated=true，不参与解析/计划）
	}
	act, err := pipeline.ProcessResponse(res.Context, respIn, pipeline.ResponseConfig{
		Mode:      apiDecisionMode(g.APIProtectionMode),
		Limits:    dsctx.DefaultParseLimits(),
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
	})
	if err != nil {
		// 响应相位故障 fail-open：记录并放行原响应（不脱敏）
		g.logger.Warn("api response phase error (fail-open)", zap.Error(err),
			zap.String("endpoint_key", res.EndpointKey), zap.String("request_id", res.Context.RequestID))
	} else {
		res.FinalAction = act
	}

	// 文件合规下载阻断（W13-GW / P2-03）：响应相位 BLOCK 类定案仅可能来自下载方向合规规则
	// （请求侧阻断请求不会到达本相位；OBSERVE 模式不产 BLOCK 类）——按响应失败策略语义
	// 选 OBSERVE 优先的设计：仅完整缓冲（未外发一字节）的响应在 PROTECT 抑制为 403；
	// 已直通/溢出的响应无法撤回，诚实降级：补记 file.download_block_unavailable 明细 + Warn
	// （不静默），final_action 按实回落 OBSERVE（未能执行的阻断不得冒充已阻断，
	// 与 attributeWAFIntercept 按实修正同一纪律）。
	if err == nil && act == dsctx.ActionBlock {
		if kind == outcomeBuffered {
			g.writeFileComplianceBlockedResponse(w, res.Context.RequestID)
			tail.status = http.StatusForbidden
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
			out, terr := response.ApplyJSON(cw.body.Bytes(), rc.TransformPlan)
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
		body := cw.body.Bytes()
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
		g.writeBufferedResponse(w, cw, body, modified)
	}
	g.emitAPIEvent(r, res, tail)
}

// maybeApplyFileWatermark 文件下载水印 v1 执行（W12-GW / P2-01 最小可行子集）：
// 命中条件：发布通道下发且启用 + 响应相位已产 DOWNLOAD 文件观测（Content-Disposition
// 携带 filename）+ 完整缓冲（identity 编码；非 identity/流式/溢出在捕获层已直通或抑制，
// 到不了这里）+ 2xx 状态 + 非 Range 分段（206/Content-Range 分段体加水印会破坏断点续传重组）
// + Content-Type 白名单。命中时产 file.watermark_applied INFO 明细（证据不含水印内容）；
// 失败 FAIL_OPEN 直通原响应并 Warn（不静默）。
func (g *Guard) maybeApplyFileWatermark(res *pipeline.Result, r *http.Request, cw *apiResponseCapture, body []byte, status int, start time.Time) ([]byte, bool) {
	cfg := g.apiFileWatermark
	if cfg == nil || res == nil || res.Context == nil {
		return body, false
	}
	rc := res.Context.GetResponse()
	if rc == nil || rc.FileObservation == nil || rc.FileObservation.Direction != dsctx.FileDirectionDownload {
		return body, false
	}
	if status < 200 || status > 299 {
		return body, false // 仅 2xx 成功下载加水印（204 无体、错误页/重定向不属文件交付）
	}
	if status == http.StatusPartialContent || cw.base.Header().Get("Content-Range") != "" {
		return body, false // Range 分段体：加水印会破坏断点续传重组
	}
	ct := cw.base.Header().Get("Content-Type")
	if !cfg.AllowsContentType(ct) {
		return body, false
	}
	// OOXML 族（W14-GW）：Content-Type 白名单之外加 filename 扩展名双重一致门禁
	// （防伪造扩展名绕过/误标；MIME 取观测内已归一化主类型）
	if ext := response.OOXMLWatermarkExtension(rc.FileObservation.MIME); ext != "" && rc.FileObservation.Extension != ext {
		return body, false
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
	res.Context.AddMatch(dsctx.DetectorMatch{
		Detector: "file",
		RuleID:   "file.watermark_applied",
		Category: "INFO",
		Severity: "INFO",
		Message:  "download file watermark applied",
		Evidence: map[string]string{
			"endpoint_key": res.EndpointKey,
			"filename":     rc.FileObservation.FileName,
			"mime":         rc.FileObservation.MIME,
		},
	})
	return out, true
}

// maybeApplyFileSignature 文件签名 v1 执行（W13-GW / P2-02，任务书 §110 子集）：
// 命中条件与水印同一口径：发布通道下发且启用 + 响应相位已产 DOWNLOAD 文件观测 +
// 完整缓冲（identity 编码）+ 2xx 状态 + 非 Range 分段 + v1 文本族能力（text/* 与
// application/json，契约无白名单段）。在水印之后调用——签名覆盖脱敏/水印后的最终交付内容。
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

// writeFileComplianceBlockedResponse 文件合规下载阻断抑制响应：403 + 空明细 JSON 体
// （不含上游任何内容）。仅在不曾外发字节（缓冲模式扣留状态行）时调用。
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

// runAPIProtection 执行统一管线请求相位；handled=true 表示已按决策拦截（阻断事件在此输出），err 为 caddyhttp.Error。
func (g *Guard) runAPIProtection(r *http.Request, start time.Time) (*pipeline.Result, bool, error) {
	restore, bodySample := preserveRequestBody(r)
	if restore == nil {
		// 请求体读取失败：已尽力还原，跳过管线（fail-open）
		return nil, false, nil
	}
	defer restore()

	// 端点键与管线内部同一算法，用于按端点选取冻结模型与参数约束
	ek := normalizer.EndpointKey(r.Method, r.URL.Path)
	// webshell C2 会话行为观测（BAS 覆盖基线，请求相位）：体统计样本只能由读体处供给
	// （parser 之后 r.Body 已消费；样本仅请求内存活，不落证据）；不挂 api.IsAPI 分类门槛——
	// WebShell 端点通常非 API 分类，分类漏判不应关掉观测；只记账不产明细，
	// 评估在响应收束处（见 pipeline webshellc2 挂点）
	pipeline.ObserveWebShellC2Request(r, g.IdentitySalt, bodySample)
	cfg := pipeline.Config{
		Enabled:               true,
		Mode:                  apiDecisionMode(g.APIProtectionMode),
		Limits:                dsctx.DefaultParseLimits(),
		FormalSchema:          g.APIFormalSchemas[ek],
		ParamConstraints:      g.APIParameterConstraints[ek],
		KnownEndpoints:        g.APIKnownEndpoints,
		APIWriteRatePerMinute: g.APIWriteRatePerMinute,
		IdentitySalt:          g.IdentitySalt,
		// 值级敏感检测规则（发布通道下发；空 = 关闭值级检测，零行为变化）
		SensitiveValueRules: g.APISensitiveValueRules,
		// 授权基线（发布通道下发；按端点选取，nil = 无端点基线，BFLA/字段权限检测零行为）
		RoleBaselines:    g.apiRoleBaselines[ek],
		FieldPermissions: g.apiFieldPerms[ek],
		// 已确认参数条件关系（发布通道下发；按端点选取，nil = 无端点关系，关系检测零行为）
		ParamRelations: g.apiParamRelations[ek],
		// 同凭据环境异常阈值（≤0 由引擎默认值兜底）
		CredentialIPSpreadLimit:    g.CredentialIPSpreadLimit,
		CredentialConcurrencyLimit: g.CredentialConcurrencyLimit,
		// 行为计数存储（nil = 进程内默认内存；valkey 时跨节点共享，故障自动 Fail-open 回内存）
		Stores: g.behaviorStores,
		// 版本快照（Finding 逐条盖章 model_version/policy_version，溯源"当时生效哪版"）
		PolicyVersion: g.APIPolicyVersion,
		ModelVersion:  g.APIFormalModelVersions[ek],
		// 扫描流量识别密钥（nil = 未下发，仅按 X-JiuZhang-Scan 头存在性识别）
		ScanVerificationKey: g.apiScanKey,
		// LLM 授权模型名单（nil/空 = 不下发不判定未授权模型；识别与观测不依赖名单）
		LLMAllowedModels: g.APILLMAllowedModels,
		// 文件合规规则（发布通道下发 api_file_compliance_rules，上传方向；nil = 上传侧检测零行为）
		FileComplianceRules: g.apiFileCompliance,
		// gRPC 帧校验配置（W14-GW / P2-05：发布通道下发 api_grpc_*；零值 = 引擎默认 4MiB/不允许压缩）
		GRPCMaxFrameBytes:    g.APIGRPCMaxFrameBytes,
		GRPCAllowCompression: g.APIGRPCAllowCompression,
		// gRPC 描述符注册表（W14-DESC / P2-05 深化：Provision 装配产物；
		// nil = 无描述符下发或全部编译失败，gRPC 处理与 v1 完全一致）
		GRPCDescriptors: g.apiGRPCRegistry,
	}
	res, err := pipeline.Process(r, cfg, nil)
	if err != nil {
		g.logger.Warn("api protection pipeline error (fail-open)", zap.Error(err))
		return nil, false, nil
	}
	if res == nil || res.Skipped {
		return res, false, nil
	}

	// APM 阶段1（D6）：桥接请求级关联字段进统一 RequestContext（原死字段填充）
	g.bridgeRequestContext(r, res.Context)

	// 统一上下文随请求传递，供下游复用
	*r = *r.WithContext(context.WithValue(r.Context(), requestContextKey{}, res.Context))

	// 阻断类动作：事件在阻断时输出（状态码按决策映射；放行请求的事件在响应完成后输出，见 serveAPIProtected）
	emitBlocked := func(status int) {
		if res.API.IsAPI || len(res.Context.CopyMatches()) > 0 {
			g.emitAPIEvent(r, res, &apiEventTail{status: status, latencyMS: time.Since(start).Milliseconds()})
		}
	}
	switch res.FinalAction {
	case dsctx.ActionBlock:
		emitBlocked(http.StatusForbidden)
		return res, true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("request blocked by api protection"))
	case dsctx.ActionRateLimit:
		emitBlocked(http.StatusTooManyRequests)
		return res, true, caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("api request rate limited"))
	case dsctx.ActionTempBlock:
		emitBlocked(http.StatusForbidden)
		return res, true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("api client temporarily blocked"))
	default:
		return res, false, nil
	}
}

// maxBodyPreserveBytes API 管线读体上限（与 dsctx.DefaultParseLimits.MaxBodyParseBytes 对齐）。
// 超限不整包入内存，避免大报文 OOM；跳过管线 fail-open，原请求体完整交给下游。
const maxBodyPreserveBytes = 1 << 20 // 1 MiB

// preserveRequestBody 在上限内读出请求体并还原；返回的 restore 用于管线结束后再次还原给下游，
// bodySample 为读出的完整请求体（webshell C2 请求相位观测的体统计样本由此供给，仅请求内存活；
// GET/HEAD 无体为 nil）。restore 返回 nil 表示读取失败或报文超限（Body 已完整还原给下游，
// 调用方应跳过管线）。
func preserveRequestBody(r *http.Request) (restore func(), bodySample []byte) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return func() {}, nil
	}
	// Content-Length 已知且超限：不读入内存，Body 原样留给下游，跳过管线
	if r.ContentLength > maxBodyPreserveBytes {
		return nil, nil
	}
	// 限流读：多读 1 字节探测是否超限
	b, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBodyPreserveBytes)+1))
	if err != nil {
		// 已读部分 + 剩余流拼回，跳过管线
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil, nil
	}
	if len(b) > maxBodyPreserveBytes {
		// 超限：已读字节 + 剩余 Body 拼回完整流，不截断下游，跳过管线
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
		return nil, nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return func() { r.Body = io.NopCloser(bytes.NewReader(b)) }, b
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
		IsAPI:         res.API.IsAPI,
		APIConfidence: res.API.Confidence,
		// 策略版本戳原样透传；FORMAL 模型版本按端点命中（未下发则省略）
		PolicyVersion: g.APIPolicyVersion,
		ModelVersion:  g.APIFormalModelVersions[res.EndpointKey],
	}
	if res.Parsed != nil {
		rec.Method = res.Parsed.Method
		rec.PathTemplate = res.Parsed.NormalizedPath
		rec.RawPath = res.Parsed.RawPath // 归一化前路径、不含 query（Emit 时封顶 512 字符）
	}
	// 协议可见性（W14-GW）：proto 记录 HTTP 协议版本（r.Proto 原样：HTTP/1.1/2.0/3，
	// 空 = 不可得省略）；protocol 记录应用层协议族（gRPC 识别命中 = GRPC，其余省略
	// 保持事件零变化，采集端按缺省 REST 口径消费）。
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
			rec.ParamObservations = detectors.CollectParamObservationsSecure(res.Parsed, g.IdentitySalt, patterns, valueRules)
		} else {
			rec.ParamObservations = detectors.CollectParamObservations(res.Parsed)
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
