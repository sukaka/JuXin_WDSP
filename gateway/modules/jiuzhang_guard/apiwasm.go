// apiwasm.go Phase 9D-1 网关 Wasm（wazero）热插拔自定义检测插件沙箱在 jiuzhang_guard 的挂点实现：
//   - 配置段 wasm_plugins 严格解码（DisallowUnknownFields）+ 常量时间 SHA-256 校验 + 预编译检查，
//     任何配置或摘要错误 fail-closed 拒绝加载；
//   - 未配置或全部插件均为 OFF 时 g.wasmPlugins == nil，请求链路零开销直通；
//   - 请求阶段在 serveNext（enforceJWTTrust 与 enforceMachineIdentity 之后、serveAPIProtected 与
//     Coraza WAF 之前）执行；白名单/L7 allow 不绕过；
//   - ALLOW 绝不绕过下游 A2A、API 动态防护或 Coraza WAF；
//   - BLOCK → 403、RATE_LIMIT → 429（带 Retry-After）、PROTECT+FAIL_CLOSED 执行异常/超时 → 503，
//     均记录 Disposition 终态事实并输出 WASM_PLUGIN_* 访问控制事件；
//   - Guard.Cleanup 幂等关闭全部 wazero 运行时，无资源泄漏。
package jiuzhang_guard

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/wasmplugin"
	"go.uber.org/zap"
)

func (g *Guard) validateWasmPlugins() error {
	if len(g.WasmPlugins) == 0 {
		return nil
	}
	cfg, err := wasmplugin.ParseAndValidateConfig(g.WasmPlugins)
	if err != nil {
		return err
	}
	return wasmplugin.ValidateCompiled(cfg)
}

func (g *Guard) assembleWasmPlugins() error {
	if len(g.WasmPlugins) == 0 {
		g.wasmPlugins = nil
		return nil
	}
	cfg, err := wasmplugin.ParseAndValidateConfig(g.WasmPlugins)
	if err != nil {
		return err
	}
	eng, err := wasmplugin.NewEngine(cfg)
	if err != nil {
		return err
	}
	if eng.ActiveCount() == 0 {
		_ = eng.Close()
		g.wasmPlugins = nil
		return nil
	}
	g.wasmPlugins = eng
	if g.logger != nil {
		g.logger.Info("wasm detection plugins loaded",
			zap.String("app_id", cfg.ApplicationID),
			zap.Int("total_plugins", len(cfg.Plugins)),
			zap.Int("active_plugins", eng.ActiveCount()))
	}
	return nil
}

// restoredReadCloser 在有界预览请求体前缀后将前缀与原始未读流无损拼回，确保下游完整消费请求体。
type restoredReadCloser struct {
	io.Reader
	io.Closer
}

// peekWasmRequestBody 最多读取 limit 字节请求体前缀供 Wasm 沙箱只读访问，并无损还原 r.Body 给下游。
func peekWasmRequestBody(r *http.Request, limit int) []byte {
	if r == nil || r.Body == nil || r.Body == http.NoBody || limit <= 0 {
		return nil
	}
	if limit > wasmplugin.MaxBodyBytes {
		limit = wasmplugin.MaxBodyBytes
	}
	origBody := r.Body
	buf, err := io.ReadAll(io.LimitReader(origBody, int64(limit)))
	r.Body = &restoredReadCloser{
		Reader: io.MultiReader(bytes.NewReader(buf), origBody),
		Closer: origBody,
	}
	if err != nil && len(buf) == 0 {
		return nil
	}
	return buf
}

// enforceWasmPlugins 在 serveNext 中执行匹配当前请求路径的 Wasm 插件链。
// 返回 handled=true 表示已写出 403 / 429 / 503 终态响应；返回 false 时继续下游 A2A / API / Coraza WAF。
func (g *Guard) enforceWasmPlugins(w http.ResponseWriter, r *http.Request) (bool, error) {
	if g.wasmPlugins == nil || r == nil {
		return false, nil
	}
	reqPath := ""
	if r.URL != nil {
		reqPath = r.URL.Path
	}
	bodyLimit := g.wasmPlugins.NeedsBodyForPath(reqPath)
	if bodyLimit < 0 {
		return false, nil
	}
	var body []byte
	if bodyLimit > 0 {
		body = peekWasmRequestBody(r, bodyLimit)
	}

	evalRes := g.wasmPlugins.Evaluate(r.Context(), r, body)
	dispo := DispositionFrom(r.Context())

	for _, sig := range evalRes.Signals {
		detail := "wasm:" + sig.PluginName
		if sig.RuleID != "" {
			detail += ":" + sig.RuleID
		}
		dispo.RecordStep(ExecutorAPI, StepObserved, detail)
		g.emitWasmPluginEvent(r, sig, events.WasmPluginObserved, "OBSERVE", 0, nil)
	}
	for _, errOut := range evalRes.Errors {
		dispo.RecordStep(ExecutorAPI, StepObserved, "wasm_error:"+errOut.PluginName)
		g.emitWasmPluginEvent(r, errOut, events.WasmPluginError, "OBSERVE", 0, nil)
	}

	if evalRes.Blocking == nil {
		return false, nil
	}
	blk := *evalRes.Blocking
	reqID := wasmRequestID(r)
	ruleRef := "wasmplugin:" + blk.PluginName
	if blk.RuleID != "" {
		ruleRef += ":" + blk.RuleID
	}

	switch evalRes.FinalAction {
	case wasmplugin.VerdictBlock:
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusForbidden, true,
			[]string{"WASM_PLUGIN_BLOCK"}, []string{ruleRef})
		g.emitWasmPluginEvent(r, blk, events.WasmPluginBlock, "BLOCK", http.StatusForbidden, dispo.JSON())
		g.writeWasmBlockedResponse(w, reqID, blk)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil

	case wasmplugin.VerdictRateLimit:
		dispo.RecordTerminal(ExecutorAPI, DisActionRateLimit, http.StatusTooManyRequests, true,
			[]string{"WASM_PLUGIN_RATE_LIMIT"}, []string{ruleRef})
		g.emitWasmPluginEvent(r, blk, events.WasmPluginRateLimit, "RATE_LIMIT", http.StatusTooManyRequests, dispo.JSON())
		g.writeWasmRateLimitResponse(w, reqID, blk)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil

	case wasmplugin.VerdictFailClosed:
		dispo.RecordTerminal(ExecutorAPI, DisActionBlock, http.StatusServiceUnavailable, true,
			[]string{"WASM_PLUGIN_FAIL_CLOSED"}, []string{"wasmplugin:" + blk.PluginName + ":error"})
		g.emitWasmPluginEvent(r, blk, events.WasmPluginError, "REJECT", http.StatusServiceUnavailable, dispo.JSON())
		g.writeWasmFailClosedResponse(w, reqID, blk)
		accessLogAnnotate(r.Context(), wafActionBlock)
		return true, nil

	default:
		return false, nil
	}
}

func (g *Guard) emitWasmPluginEvent(
	r *http.Request,
	out wasmplugin.PluginOutcome,
	evType events.Type,
	action string,
	status int,
	finalDecision json.RawMessage,
) {
	if g.events == nil || r == nil {
		return
	}
	path := ""
	if r.URL != nil {
		path = r.URL.RequestURI()
	}
	ev := events.Event{
		RequestID:     wasmRequestID(r),
		OccurredAt:    time.Now().UTC(),
		ApplicationID: g.AppID,
		AppCode:       g.AppCode,
		Domain:        r.Host,
		Method:        r.Method,
		Path:          path,
		Proto:         r.Proto,
		GatewayNode:   g.GatewayNode,
		WasmPlugin: &events.WasmPluginDetail{
			PluginID:      out.PluginID,
			PluginName:    out.PluginName,
			PluginVersion: out.PluginVersion,
			ABIVersion:    out.ABIVersion,
			Mode:          out.Mode,
			SHA256:        out.SHA256,
			RuleID:        out.RuleID,
			Reason:        out.Reason,
			ScoreDelta:    out.ScoreDelta,
			LatencyMS:     out.LatencyMS,
			FailPolicy:    out.FailPolicy,
			ActionTaken:   out.ActionTaken,
			Error:         out.Error,
		},
		FinalDecision: finalDecision,
	}
	if cres, ok := clientIPResultFrom(r.Context()); ok {
		ev.ClientIP = cres.ClientIP.String()
		ev.ConnectionIP = cres.ConnectionIP.String()
		ev.ClientIPSource = string(cres.Source)
		ev.TrustedProxyUsed = cres.TrustedProxyUsed
		ev.ForwardedChainSummary = cres.ChainSummary
	} else if addr, err := clientip.ConnectionIP(r); err == nil && addr.IsValid() {
		ev.ClientIP = addr.String()
		ev.ConnectionIP = addr.String()
	}
	g.emit(ev, evType, action, status)
}

func wasmRequestID(r *http.Request) string {
	if r == nil {
		return ""
	}
	if id := r.Header.Get("X-Request-Id"); id != "" {
		return id
	}
	return r.Header.Get("X-Jiuzhang-Request-ID")
}

func (g *Guard) writeWasmBlockedResponse(w http.ResponseWriter, requestID string, out wasmplugin.PluginOutcome) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "wasm_plugin_blocked",
		"message":    "request blocked by custom detection plugin",
		"plugin":     out.PluginName,
		"rule_id":    out.RuleID,
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusForbidden)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("wasm blocked 403 response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

func (g *Guard) writeWasmRateLimitResponse(w http.ResponseWriter, requestID string, out wasmplugin.PluginOutcome) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Retry-After", "60")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "wasm_plugin_rate_limited",
		"message":    "request rate limited by custom detection plugin",
		"plugin":     out.PluginName,
		"rule_id":    out.RuleID,
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusTooManyRequests)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("wasm rate limit 429 response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}

func (g *Guard) writeWasmFailClosedResponse(w http.ResponseWriter, requestID string, out wasmplugin.PluginOutcome) {
	h := w.Header()
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Jiuzhang-Request-ID", requestID)
	body, _ := json.Marshal(map[string]string{
		"error":      "wasm_plugin_unavailable",
		"message":    "custom detection plugin execution failed under fail-closed policy",
		"plugin":     out.PluginName,
		"request_id": requestID,
	})
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusServiceUnavailable)
	if _, err := w.Write(body); err != nil && g.logger != nil {
		g.logger.Warn("wasm fail-closed 503 response write failed", zap.Error(err), zap.String("request_id", requestID))
	}
}
