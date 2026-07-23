// API 动态防护（WDSP / 阶段8）：统一引擎在 jiuzhang_guard 请求链上的挂点。
//
// 设计约束：
//   - 关闭（api_dynamic_protection 缺省/false）时零开销、零行为变化，纯 WAF 路径不受影响；
//   - 所有放行出口（保护地址旁路、白名单、常规链路）统一经 serveNext，保证引擎唯一挂点；
//   - parser 会读取并关闭 Body，必须先完整读出并在管线结束后还原，下游（Coraza/反向代理）才能拿到完整请求体；
//   - 引擎/事件输出故障一律 fail-open（记录告警，不阻断业务），与 guard 既有故障策略一致。
package jiuzhang_guard

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/decision"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
	"github.com/jiuzhang-waf/gateway/dynamic_security/pipeline"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

// requestContextKey 请求上下文中的统一 RequestContext 键（供下游处理器复用一次解析结果）。
type requestContextKey struct{}

// RequestContextFrom 从请求上下文取统一 RequestContext（未启用 API 动态防护或未执行管线时为 nil）。
func RequestContextFrom(r *http.Request) *dsctx.RequestContext {
	v, _ := r.Context().Value(requestContextKey{}).(*dsctx.RequestContext)
	return v
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

// serveNext 统一放行出口：先执行 API 动态防护管线，再进入下游（WAF/反向代理）。
func (g *Guard) serveNext(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if !g.APIDynamicProtection {
		return next.ServeHTTP(w, r)
	}
	handled, err := g.runAPIProtection(r)
	if handled {
		return err
	}
	return next.ServeHTTP(w, r)
}

// runAPIProtection 执行统一管线；handled=true 表示已按决策拦截，err 为 caddyhttp.Error。
func (g *Guard) runAPIProtection(r *http.Request) (bool, error) {
	restore := preserveRequestBody(r)
	if restore == nil {
		// 请求体读取失败：已尽力还原，跳过管线（fail-open）
		return false, nil
	}
	defer restore()

	// 端点键与管线内部同一算法，用于按端点选取冻结模型
	ek := normalizer.EndpointKey(r.Method, r.URL.Path)
	cfg := pipeline.Config{
		Enabled:               true,
		Mode:                  apiDecisionMode(g.APIProtectionMode),
		Limits:                dsctx.DefaultParseLimits(),
		FormalSchema:          g.APIFormalSchemas[ek],
		KnownEndpoints:        g.APIKnownEndpoints,
		APIWriteRatePerMinute: g.APIWriteRatePerMinute,
	}
	res, err := pipeline.Process(r, cfg, nil)
	if err != nil {
		g.logger.Warn("api protection pipeline error (fail-open)", zap.Error(err))
		return false, nil
	}
	if res == nil || res.Skipped {
		return false, nil
	}

	// 统一上下文随请求传递，供下游复用
	*r = *r.WithContext(context.WithValue(r.Context(), requestContextKey{}, res.Context))

	// 主事件：API 流量或存在检测命中时输出（其余请求由访问日志/WAF 事件覆盖）
	if res.API.IsAPI || len(res.Context.CopyMatches()) > 0 {
		g.emitAPIEvent(res)
	}

	switch res.FinalAction {
	case dsctx.ActionBlock:
		return true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("request blocked by api protection"))
	case dsctx.ActionRateLimit:
		return true, caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("api request rate limited"))
	case dsctx.ActionTempBlock:
		return true, caddyhttp.Error(http.StatusForbidden, fmt.Errorf("api client temporarily blocked"))
	default:
		return false, nil
	}
}

// preserveRequestBody 完整读出请求体并还原；返回的 restore 用于管线结束后再次还原给下游。
// 返回 nil 表示读取失败（Body 已按已读部分还原，调用方应跳过管线）。
func preserveRequestBody(r *http.Request) (restore func()) {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return func() {}
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		r.Body = io.NopCloser(bytes.NewReader(b))
		return nil
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(b))
	return func() { r.Body = io.NopCloser(bytes.NewReader(b)) }
}

// emitAPIEvent 构建并输出统一运行时主事件（含端点发现信息）；输出失败仅告警，不影响请求。
func (g *Guard) emitAPIEvent(res *pipeline.Result) {
	if g.apiEvents == nil || res == nil || res.Context == nil {
		return
	}
	pe := dsevents.BuildPrimary("", res.Context, res.EndpointKey)
	rec := apievents.Record{
		RequestID:     pe.RequestID,
		OccurredAt:    pe.OccurredAt,
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		EndpointKey:   pe.EndpointKey,
		RiskScore:     pe.RiskScore,
		RiskLevel:     pe.RiskLevel,
		FinalAction:   pe.FinalAction,
		Details:       pe.Details,
		IsAPI:         res.API.IsAPI,
		APIConfidence: res.API.Confidence,
	}
	if res.Parsed != nil {
		rec.Method = res.Parsed.Method
		rec.PathTemplate = res.Parsed.NormalizedPath
	}
	if err := g.apiEvents.Emit(rec); err != nil {
		g.logger.Warn("api runtime event emit failed", zap.Error(err))
	}
}
