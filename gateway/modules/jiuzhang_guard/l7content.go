package jiuzhang_guard

import (
	"bufio"
	"bytes"
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
	base        http.ResponseWriter
	status      int
	body        bytes.Buffer
	passthrough bool
	overflow    bool
	hijacked    bool
	committed   bool
}

func newL7ResponseCapture(base http.ResponseWriter) *l7ResponseCapture {
	return &l7ResponseCapture{base: base}
}

func (w *l7ResponseCapture) Header() http.Header { return w.base.Header() }

func (w *l7ResponseCapture) WriteHeader(code int) {
	if code >= 100 && code < 200 && code != http.StatusSwitchingProtocols {
		if w.status == 0 {
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
	if w.passthrough {
		return w.base.Write(p)
	}
	if w.body.Len()+len(p) <= maxL7BodyInspectionBytes {
		return w.body.Write(p)
	}
	w.startPassthrough(true)
	return w.base.Write(p)
}

func (w *l7ResponseCapture) startPassthrough(overflow bool) {
	if w.passthrough {
		return
	}
	w.passthrough = true
	w.overflow = overflow
	w.commit()
}

func (w *l7ResponseCapture) commit() {
	if w.committed || w.hijacked {
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
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.startPassthrough(false)
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *l7ResponseCapture) Unwrap() http.ResponseWriter { return w.base }

func (w *l7ResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	w.passthrough = true
	h, ok := w.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}

func (g *Guard) serveNextWithL7Response(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler,
	base events.Event, res clientip.Result, clientIP netip.Addr, requestBody []byte, requestBodyReady bool) error {
	if g.l7 == nil || !g.l7.HasResponseRules() {
		return g.serveNextViaBot(w, r, next, base, res)
	}
	capture := newL7ResponseCapture(w)
	if err := g.serveNextViaBot(capture, r, next, base, res); err != nil {
		return err
	}
	if capture.hijacked {
		return nil
	}
	if capture.overflow {
		g.logger.Warn("l7 response inspection skipped: body exceeds 1 MiB", zap.String("request_id", base.RequestID))
		return nil
	}
	if capture.passthrough {
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
		w.Header().Set("Location", dec.Config.RedirectURL)
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
