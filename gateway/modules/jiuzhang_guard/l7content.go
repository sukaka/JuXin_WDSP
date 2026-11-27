package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientip"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/events"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"go.uber.org/zap"
)

const maxL7BodyInspectionBytes = 1 << 20

var errL7ResponseDiscarded = errors.New("l7 response discarded")

func (g *Guard) readL7RequestBody(r *http.Request) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	original := r.Body
	body, err := io.ReadAll(io.LimitReader(original, maxL7BodyInspectionBytes+1))
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), original))
	if err == nil && len(body) <= maxL7BodyInspectionBytes {
		_ = original.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		return body, true
	}
	if err != nil {
		g.logger.Warn("l7 request body inspection degraded", zap.String("request_id", r.Header.Get("X-Request-Id")), zap.Error(err))
	} else {
		g.logger.Warn("l7 request body inspection skipped: body exceeds 1 MiB", zap.String("request_id", r.Header.Get("X-Request-Id")))
	}
	return nil, false
}

type l7ResponseCapture struct {
	base           http.ResponseWriter
	status         int
	body           bytes.Buffer
	passthrough    bool
	overflow       bool
	hijacked       bool
	committed      bool
	discarded      bool
	headerDecision *l7rules.Decision
	// evalHeadersBeforePassthrough 在切直通（SSE/Upgrade/Flush/>1MiB）前评估纯响应头规则：
	// 若命中阻断/重定向/自定义页，转入 discarded 丢弃上游正文，绝不先提交源站头或正文（N-01）。
	evalHeadersBeforePassthrough func(http.Header) (l7rules.Decision, bool)
	headerEvaluated              bool
}

func newL7ResponseCapture(base http.ResponseWriter, evalHeaders func(http.Header) (l7rules.Decision, bool)) *l7ResponseCapture {
	return &l7ResponseCapture{base: base, evalHeadersBeforePassthrough: evalHeaders}
}

func (w *l7ResponseCapture) Header() http.Header { return w.base.Header() }

func (w *l7ResponseCapture) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if w.status == 0 && !w.discarded {
			w.base.WriteHeader(code)
		}
		return
	}
	if w.status != 0 {
		return
	}
	w.status = code
	if code == http.StatusSwitchingProtocols || w.Header().Get("Upgrade") != "" ||
		strings.EqualFold(strings.TrimSpace(strings.SplitN(w.Header().Get("Content-Type"), ";", 2)[0]), "text/event-stream") {
		w.startPassthrough(false)
	}
}

func (w *l7ResponseCapture) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.discarded {
		return len(p), nil
	}
	if w.passthrough {
		return w.base.Write(p)
	}
	if w.body.Len()+len(p) <= maxL7BodyInspectionBytes {
		return w.body.Write(p)
	}
	w.startPassthrough(true)
	if w.discarded {
		return len(p), nil
	}
	return w.base.Write(p)
}

func (w *l7ResponseCapture) startPassthrough(overflow bool) {
	if w.passthrough || w.discarded {
		return
	}
	if !w.headerEvaluated && w.evalHeadersBeforePassthrough != nil {
		w.headerEvaluated = true
		if dec, matched := w.evalHeadersBeforePassthrough(w.Header()); matched {
			decCopy := dec
			w.headerDecision = &decCopy
			if dec.Action != l7rules.ActionAllow {
				w.discarded = true
				w.overflow = overflow
				w.body.Reset()
				return
			}
		}
	}
	w.passthrough = true
	w.overflow = overflow
	w.commit()
}

func (w *l7ResponseCapture) commit() {
	if w.committed || w.hijacked || w.discarded {
		return
	}
	w.committed = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.base.WriteHeader(w.status)
	if w.body.Len() > 0 {
		_, _ = w.base.Write(w.body.Bytes())
		w.body.Reset()
	}
}

func (w *l7ResponseCapture) Flush() {
	if w.hijacked {
		return
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.startPassthrough(false)
	if w.discarded {
		return
	}
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
		return
	}
	_ = http.NewResponseController(w.base).Flush()
}

func (w *l7ResponseCapture) Unwrap() http.ResponseWriter { return w.base }

func (w *l7ResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if w.discarded {
		return nil, nil, errL7ResponseDiscarded
	}
	var (
		conn net.Conn
		rw   *bufio.ReadWriter
		err  error
	)
	if h, ok := w.base.(http.Hijacker); ok {
		conn, rw, err = h.Hijack()
	} else {
		conn, rw, err = http.NewResponseController(w.base).Hijack()
	}
	if err == nil {
		w.hijacked = true
		w.passthrough = true
	}
	return conn, rw, err
}

func (g *Guard) serveNextWithL7Response(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
	base events.Event, res clientip.Result, clientIP netip.Addr, requestBody []byte, requestBodyReady bool) error {
	if g.l7 == nil || !g.l7.HasResponseRules() {
		return g.serveNextViaBot(w, r, next, base, res)
	}
	dispo := DispositionFrom(r.Context())
	evalHeaders := func(h http.Header) (l7rules.Decision, bool) {
		if dispo != nil && dispo.Terminated() {
			return l7rules.Decision{}, false
		}
		return g.l7.EvalResponseHeaders(r, clientIP, l7rules.ResponseInput{
			Header: h, RequestBody: requestBody, RequestBodyReady: requestBodyReady,
		})
	}
	capture := newL7ResponseCapture(w, evalHeaders)
	if err := g.serveNextViaBot(capture, r, next, base, res); err != nil {
		if capture.discarded && capture.headerDecision != nil && errors.Is(err, errL7ResponseDiscarded) {
			return g.executeL7Response(w, r, base, *capture.headerDecision, capture.status, capture.commit)
		}
		return err
	}
	if capture.hijacked {
		return nil
	}
	// N-01：若响应已由网关本地终止（Bot 403/503、JWT 401/503、MachineID 401/403/413/503、
	// API 403/413/429/500、Coraza WAF、发布探针等），绝不对其执行源站 L7 响应规则，
	// 防止剥离 WWW-Authenticate/Retry-After/X-Jiuzhang-* 或覆写网关拦截响应。
	if dispo != nil && dispo.Terminated() {
		capture.commit()
		return nil
	}
	if capture.discarded && capture.headerDecision != nil {
		return g.executeL7Response(w, r, base, *capture.headerDecision, capture.status, capture.commit)
	}
	if capture.passthrough {
		if capture.headerDecision != nil && capture.headerDecision.Action == l7rules.ActionAllow {
			dispo.RecordStep(ExecutorL7ACL, StepExecuted, "response allow hit rule="+capture.headerDecision.RuleID)
			ev := base
			ev.AccessRuleID = capture.headerDecision.RuleID
			g.emit(ev, events.L7RuleAllow, "ALLOW", capture.status)
		}
		if capture.overflow {
			g.logger.Warn("l7 response inspection skipped: body exceeds 1 MiB", zap.String("request_id", base.RequestID))
		}
		return nil
	}

	body := capture.body.Bytes()
	bodyReady := true
	encoding, supported := apiResponseContentEncoding(capture.Header())
	if !supported {
		bodyReady = false
	} else if compressedAPIResponseEncoding(encoding) {
		decoded, err := decodeAPIResponseBody(encoding, body, maxL7BodyInspectionBytes)
		if err != nil {
			bodyReady = false
			g.logger.Warn("l7 response body decode failed", zap.String("request_id", base.RequestID), zap.Error(err))
		} else {
			body = decoded
		}
	}
	dec, matched := g.l7.EvalResponse(r, clientIP, l7rules.ResponseInput{
		Header: capture.Header(), Body: body, BodyReady: bodyReady,
		RequestBody: requestBody, RequestBodyReady: requestBodyReady,
	})
	if matched {
		return g.executeL7Response(w, r, base, dec, capture.status, capture.commit)
	}
	capture.commit()
	return nil
}

func (g *Guard) executeL7Response(w http.ResponseWriter, r *http.Request, base events.Event,
	dec l7rules.Decision, originalStatus int, commitOriginal func()) error {
	if dec.Action == l7rules.ActionAllow {
		dispo := DispositionFrom(r.Context())
		dispo.RecordStep(ExecutorL7ACL, StepExecuted, "response allow hit rule="+dec.RuleID)
		ev := base
		ev.AccessRuleID = dec.RuleID
		g.emit(ev, events.L7RuleAllow, "ALLOW", originalStatus)
		commitOriginal()
		return nil
	}
	for key := range w.Header() {
		w.Header().Del(key)
	}
	dispo := DispositionFrom(r.Context())
	ev := base
	ev.AccessRuleID = dec.RuleID
	switch dec.Action {
	case l7rules.ActionBlock:
		g.writeL7Block(w, r, base.RequestID, dec.Config.Status, dec.Config.Message)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionBlock, dec.Config.Status, true, []string{"L7_RESPONSE_RULE_BLOCK"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleBlock, "BLOCK", dec.Config.Status)
	case l7rules.ActionRedirect:
		w.Header().Set("Location", dec.Config.RedirectTarget(r.URL))
		w.Header().Set("X-Jiuzhang-Request-ID", base.RequestID)
		w.WriteHeader(dec.Config.RedirectStatus)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionNone, dec.Config.RedirectStatus, true, []string{"L7_RESPONSE_RULE_REDIRECT"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleRedirect, "REDIRECT", dec.Config.RedirectStatus)
	case l7rules.ActionCustomPage:
		w.Header().Set("Content-Type", dec.Config.ContentType)
		w.Header().Set("X-Jiuzhang-Request-ID", base.RequestID)
		w.WriteHeader(dec.Config.Status)
		_, _ = io.WriteString(w, dec.Config.Body)
		dispo.RecordTerminal(ExecutorL7ACL, DisActionNone, dec.Config.Status, true, []string{"L7_RESPONSE_RULE_CUSTOM_PAGE"}, []string{dec.RuleID})
		ev.FinalDecision = dispo.JSON()
		g.emit(ev, events.L7RuleCustom, "CUSTOM_PAGE", dec.Config.Status)
	default:
		return caddyhttp.Error(http.StatusForbidden, fmt.Errorf("l7 response rule action unavailable"))
	}
	accessLogAnnotate(r.Context(), wafActionBlock)
	return nil
}
