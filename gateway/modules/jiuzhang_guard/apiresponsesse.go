package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors/mcpguard"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
	"github.com/jiuzhang-waf/gateway/dynamic_security/response"
)

type apiResponseSSEWriter struct {
	base        http.ResponseWriter
	rc          *dsctx.RequestContext
	scanner     *detectors.ResponseBodyValueScanner
	decided     bool
	active      bool
	degraded    bool
	status      int
	pending     []byte
	events      int
	streamBytes int64
}

func (g *Guard) wrapResponseBodySSEResponse(w http.ResponseWriter, rc *dsctx.RequestContext, mcpActive bool) (http.ResponseWriter, *apiResponseSSEWriter) {
	if mcpActive || rc == nil || !detectors.HasResponseBodySensitiveLocation(g.APISensitiveValueRules) {
		return w, nil
	}
	rules, err := detectors.CompileResponseSensitiveValueRules(g.APISensitiveValueRules)
	if err != nil || len(rules) == 0 {
		return w, nil
	}
	if rc.Response == nil {
		rc.Response = &dsctx.ResponseContext{Streamed: true}
	}
	writer := &apiResponseSSEWriter{
		base: w, rc: rc, scanner: detectors.NewResponseBodyValueScanner(rc, rules, g.apiParseLimits()),
	}
	return writer, writer
}

func (w *apiResponseSSEWriter) Header() http.Header { return w.base.Header() }

func (w *apiResponseSSEWriter) WriteHeader(code int) {
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
	encoding, supported := apiResponseContentEncoding(w.base.Header())
	if supported && encoding == apiResponseEncodingIdentity && mcpguard.IsSSEContentType(w.base.Header().Get("Content-Type")) {
		w.active = true
	}
	w.decided = true
	w.base.WriteHeader(code)
}

func (w *apiResponseSSEWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if !w.active {
		return w.base.Write(p)
	}
	w.streamBytes += int64(len(p))
	w.pending = append(w.pending, p...)
	if w.streamBytes > mcpSSEMaxStreamBytes {
		return w.degradeAndFlush("SSE_STREAM_BYTES_EXCEEDED", len(p))
	}
	for {
		block, rest := splitMCPSSEEvent(w.pending)
		if block == nil {
			if len(w.pending) > mcpSSEMaxEventBytes {
				return w.degradeAndFlush("SSE_EVENT_BYTES_EXCEEDED", len(p))
			}
			return len(p), nil
		}
		if len(block) > mcpSSEMaxEventBytes {
			return w.degradeAndFlush("SSE_EVENT_BYTES_EXCEEDED", len(p))
		}
		if w.events >= mcpSSEMaxEvents {
			return w.degradeAndFlush("SSE_EVENT_COUNT_EXCEEDED", len(p))
		}
		w.pending = rest
		w.events++
		if err := w.processEvent(block, w.events); err != nil {
			return 0, err
		}
		if !w.active {
			if err := w.flushPending(); err != nil {
				return 0, err
			}
			return len(p), nil
		}
	}
}

func (w *apiResponseSSEWriter) processEvent(block []byte, eventIndex int) error {
	event, err := mcprpc.NewSSEReader(bytes.NewReader(block), mcpSSEMaxEventBytes).Next()
	if err != nil {
		detectors.NoteResponseBodyValueUnchecked(w.rc, "SSE", w.eventField(eventIndex), "SSE_PARSE_ERROR")
		return w.forward(block)
	}
	if len(event.Data) == 0 {
		return w.forward(block)
	}
	field := w.eventField(eventIndex)
	if response.IsJSONContentType("", event.Data) {
		w.noteEventReason("SSE_JSON", field, w.scanner.ScanJSON(event.Data, field))
	} else {
		w.noteEventReason("SSE_TEXT", field, w.scanner.ScanText(event.Data, field+"."))
	}
	return w.forward(block)
}

func (w *apiResponseSSEWriter) noteEventReason(format, field, reason string) {
	switch reason {
	case "SCAN_BUDGET_EXCEEDED", "MATCH_BUDGET_EXCEEDED", "FIELD_BUDGET_EXCEEDED":
		if !w.degraded {
			w.degraded = true
			detectors.NoteResponseBodyValueUnchecked(w.rc, format, field, reason)
		}
		w.active = false
	default:
		detectors.NoteResponseBodyValueUnchecked(w.rc, format, field, reason)
	}
}

func (w *apiResponseSSEWriter) eventField(eventIndex int) string {
	return fmt.Sprintf("sse.event[%d].data", eventIndex)
}

func (w *apiResponseSSEWriter) forward(block []byte) error {
	if _, err := w.base.Write(block); err != nil {
		return err
	}
	_ = http.NewResponseController(w.base).Flush()
	return nil
}

func (w *apiResponseSSEWriter) degradeAndFlush(reason string, inputLen int) (int, error) {
	w.degrade(reason)
	if err := w.flushPending(); err != nil {
		return 0, err
	}
	return inputLen, nil
}

func (w *apiResponseSSEWriter) degrade(reason string) {
	if w.degraded {
		return
	}
	w.degraded = true
	w.active = false
	detectors.NoteResponseBodyValueUnchecked(w.rc, "SSE", w.eventField(w.events+1), reason)
}

func (w *apiResponseSSEWriter) flushPending() error {
	if len(w.pending) == 0 {
		return nil
	}
	pending := w.pending
	w.pending = nil
	if _, err := w.base.Write(pending); err != nil {
		return err
	}
	_ = http.NewResponseController(w.base).Flush()
	return nil
}

func (w *apiResponseSSEWriter) Finish() {
	if !w.decided {
		return
	}
	if len(w.pending) > 0 && w.active {
		w.degrade("SSE_INCOMPLETE_EVENT")
	}
	_ = w.flushPending()
}

func (w *apiResponseSSEWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.base.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *apiResponseSSEWriter) Unwrap() http.ResponseWriter { return w.base }

func (w *apiResponseSSEWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.active = false
	h, ok := w.base.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("underlying writer does not support hijacking")
	}
	return h.Hijack()
}
