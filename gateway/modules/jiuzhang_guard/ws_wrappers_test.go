package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/aicrawl"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/clientside"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/l7rules"
	"go.uber.org/zap"
)

// Compile-time assertions: every ResponseWriter wrapper in jiuzhang_guard must
// implement http.ResponseWriter, http.Flusher, http.Hijacker, and Unwrap() directly
// (coraza-caddy and similar middlewares perform direct type assertions on w).
type unwrapper interface {
	Unwrap() http.ResponseWriter
}

var (
	_ http.ResponseWriter = (*captureResponseWriter)(nil)
	_ http.Flusher        = (*captureResponseWriter)(nil)
	_ http.Hijacker       = (*captureResponseWriter)(nil)
	_ unwrapper           = (*captureResponseWriter)(nil)

	_ http.ResponseWriter = (*mcpOAuthChallengeWriter)(nil)
	_ http.Flusher        = (*mcpOAuthChallengeWriter)(nil)
	_ http.Hijacker       = (*mcpOAuthChallengeWriter)(nil)
	_ unwrapper           = (*mcpOAuthChallengeWriter)(nil)

	_ http.ResponseWriter = (*apiResponseHeaderPeek)(nil)
	_ http.Flusher        = (*apiResponseHeaderPeek)(nil)
	_ http.Hijacker       = (*apiResponseHeaderPeek)(nil)
	_ unwrapper           = (*apiResponseHeaderPeek)(nil)

	_ http.ResponseWriter = (*botStatusCapture)(nil)
	_ http.Flusher        = (*botStatusCapture)(nil)
	_ http.Hijacker       = (*botStatusCapture)(nil)
	_ unwrapper           = (*botStatusCapture)(nil)

	_ http.ResponseWriter = (*redirectLocationWriter)(nil)
	_ http.Flusher        = (*redirectLocationWriter)(nil)
	_ http.Hijacker       = (*redirectLocationWriter)(nil)
	_ unwrapper           = (*redirectLocationWriter)(nil)

	_ http.ResponseWriter = (*apiResponseCapture)(nil)
	_ http.Flusher        = (*apiResponseCapture)(nil)
	_ http.Hijacker       = (*apiResponseCapture)(nil)
	_ unwrapper           = (*apiResponseCapture)(nil)

	_ http.ResponseWriter = (*apiResponseSSEWriter)(nil)
	_ http.Flusher        = (*apiResponseSSEWriter)(nil)
	_ http.Hijacker       = (*apiResponseSSEWriter)(nil)
	_ unwrapper           = (*apiResponseSSEWriter)(nil)

	_ http.ResponseWriter = (*mcpSSEWriter)(nil)
	_ http.Flusher        = (*mcpSSEWriter)(nil)
	_ http.Hijacker       = (*mcpSSEWriter)(nil)
	_ unwrapper           = (*mcpSSEWriter)(nil)

	_ http.ResponseWriter = (*strongFlowResponseRecorder)(nil)
	_ http.Flusher        = (*strongFlowResponseRecorder)(nil)
	_ http.Hijacker       = (*strongFlowResponseRecorder)(nil)
	_ unwrapper           = (*strongFlowResponseRecorder)(nil)

	_ http.ResponseWriter = (*a2aAgentCardSniffer)(nil)
	_ http.Flusher        = (*a2aAgentCardSniffer)(nil)
	_ http.Hijacker       = (*a2aAgentCardSniffer)(nil)
	_ unwrapper           = (*a2aAgentCardSniffer)(nil)

	_ http.ResponseWriter = (*l7ResponseCapture)(nil)
	_ http.Flusher        = (*l7ResponseCapture)(nil)
	_ http.Hijacker       = (*l7ResponseCapture)(nil)
	_ unwrapper           = (*l7ResponseCapture)(nil)

	_ http.ResponseWriter = (*statusCountingResponseWriter)(nil)
	_ http.Flusher        = (*statusCountingResponseWriter)(nil)
	_ http.Hijacker       = (*statusCountingResponseWriter)(nil)
	_ unwrapper           = (*statusCountingResponseWriter)(nil)
)

type wsMockWriter struct {
	header   http.Header
	codes    []int
	body     bytes.Buffer
	flushed  int
	hijacked bool
	writes   int
}

func newWSMockWriter() *wsMockWriter {
	return &wsMockWriter{header: make(http.Header)}
}

func (m *wsMockWriter) Header() http.Header { return m.header }

func (m *wsMockWriter) WriteHeader(code int) { m.codes = append(m.codes, code) }

func (m *wsMockWriter) Write(p []byte) (int, error) {
	m.writes++
	return m.body.Write(p)
}

func (m *wsMockWriter) Flush() { m.flushed++ }

func (m *wsMockWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	m.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestMCPOAuthChallengeWriter_WS101HijackFlushUnwrap(t *testing.T) {
	for _, viaUnwrapOnly := range []bool{false, true} {
		name := "direct"
		if viaUnwrapOnly {
			name = "via_caddy_ResponseWriterWrapper"
		}
		t.Run(name, func(t *testing.T) {
			root := newWSMockWriter()
			var base http.ResponseWriter = root
			if viaUnwrapOnly {
				base = &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
			}
			w := &mcpOAuthChallengeWriter{
				ResponseWriter: base,
				challenge:      `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			}
			if w.Unwrap() != base {
				t.Fatal("Unwrap mismatch")
			}

			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusSwitchingProtocols)
			if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusSwitchingProtocols {
				t.Fatalf("codes = %v, want [103 101]", root.codes)
			}
			if got := root.Header().Get("WWW-Authenticate"); got != "" {
				t.Fatalf("101 must not receive WWW-Authenticate, got %q", got)
			}

			w.Flush()
			if root.flushed != 1 {
				t.Fatalf("flushed = %d, want 1", root.flushed)
			}

			conn, rw, err := w.Hijack()
			if err != nil || conn == nil || rw == nil {
				t.Fatalf("Hijack failed: conn=%v rw=%v err=%v", conn, rw, err)
			}
			_ = conn.Close()
			if !root.hijacked {
				t.Fatal("root writer was not hijacked")
			}
		})
	}

	t.Run("non-hijackable returns ErrNotSupported", func(t *testing.T) {
		w := &mcpOAuthChallengeWriter{ResponseWriter: httptest.NewRecorder(), challenge: "Bearer test"}
		if _, _, err := w.Hijack(); !errors.Is(err, http.ErrNotSupported) {
			t.Fatalf("err = %v, want http.ErrNotSupported", err)
		}
	})
}

func TestBotStatusCapture_WS101Provisional1xxHijackFlush(t *testing.T) {
	root := newWSMockWriter()
	outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
	w := &botStatusCapture{ResponseWriter: outer}

	if w.Unwrap() != outer {
		t.Fatal("Unwrap mismatch")
	}
	w.WriteHeader(http.StatusContinue)
	w.WriteHeader(http.StatusEarlyHints)
	if w.status != 0 {
		t.Fatalf("provisional 1xx must not set status, got %d", w.status)
	}
	w.WriteHeader(http.StatusSwitchingProtocols)
	if w.status != http.StatusSwitchingProtocols {
		t.Fatalf("101 must set final status, got %d", w.status)
	}
	w.Flush()
	if root.flushed != 1 {
		t.Fatalf("flushed = %d, want 1", root.flushed)
	}
	conn, _, err := w.Hijack()
	if err != nil {
		t.Fatalf("Hijack failed: %v", err)
	}
	_ = conn.Close()
	if !root.hijacked || !w.hijacked {
		t.Fatalf("expected hijacked state: root=%v w=%v", root.hijacked, w.hijacked)
	}
	// Flush after hijack must be a no-op.
	w.Flush()
	if root.flushed != 1 {
		t.Fatalf("Flush after Hijack must be a no-op, flushed=%d", root.flushed)
	}
}

func TestRedirectLocationWriter_WS101Provisional1xxHijackFlush(t *testing.T) {
	t.Run("101 locks header without rewriting Location and allows Hijack via Unwrap wrapper", func(t *testing.T) {
		root := newWSMockWriter()
		outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
		w := newRedirectLocationWriter(outer, 8443)

		w.Header().Set("Location", "http://internal:9000/ws")
		w.WriteHeader(http.StatusEarlyHints)
		if w.wroteHeader {
			t.Fatal("103 must not lock wroteHeader")
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
		if !w.wroteHeader {
			t.Fatal("101 must lock wroteHeader")
		}
		if got := root.Header().Get("Location"); got != "http://internal:9000/ws" {
			t.Fatalf("101 must not rewrite Location, got %q", got)
		}
		w.Flush()
		if root.flushed != 1 {
			t.Fatalf("flushed = %d, want 1", root.flushed)
		}
		// Flush must not rewrite Location after 101 locked wroteHeader.
		if got := root.Header().Get("Location"); got != "http://internal:9000/ws" {
			t.Fatalf("Location rewritten after 101: %q", got)
		}
		conn, _, err := w.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		if !root.hijacked {
			t.Fatal("root not hijacked")
		}
		w.Flush()
		if root.flushed != 1 {
			t.Fatalf("Flush after hijack should not flush, got %d", root.flushed)
		}
	})

	t.Run("provisional 103 then 302 still rewrites Location", func(t *testing.T) {
		root := newWSMockWriter()
		w := newRedirectLocationWriter(root, 8443)
		w.WriteHeader(http.StatusEarlyHints)
		w.Header().Set("Location", "http://example.com:9000/next")
		w.WriteHeader(http.StatusFound)
		if got := root.Header().Get("Location"); got != "http://example.com:8443/next" {
			t.Fatalf("Location = %q, want rewritten port 8443", got)
		}
	})
}

func TestAPIResponseSSEWriter_WS101AndPostHijackFinishSafety(t *testing.T) {
	t.Run("101 never activates SSE even with text/event-stream", func(t *testing.T) {
		root := newWSMockWriter()
		outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
		w := &apiResponseSSEWriter{base: outer, rc: &dsctx.RequestContext{}}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusEarlyHints)
		if w.status != 0 || w.decided {
			t.Fatalf("103 must be provisional: status=%d decided=%v", w.status, w.decided)
		}
		w.WriteHeader(http.StatusSwitchingProtocols)
		if w.status != http.StatusSwitchingProtocols || w.active {
			t.Fatalf("101 must not activate SSE: status=%d active=%v", w.status, w.active)
		}
		if len(root.codes) != 2 || root.codes[1] != http.StatusSwitchingProtocols {
			t.Fatalf("codes = %v, want [103 101]", root.codes)
		}
		conn, _, err := w.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		w.Finish()
		if root.writes != 0 {
			t.Fatalf("Finish after Hijack must not write, writes=%d", root.writes)
		}
	})

	t.Run("pending SSE buffer is discarded on Hijack so Finish never writes to hijacked conn", func(t *testing.T) {
		root := newWSMockWriter()
		w := &apiResponseSSEWriter{base: root, rc: &dsctx.RequestContext{}}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if !w.active {
			t.Fatal("expected SSE active for 200 text/event-stream")
		}
		_, _ = w.Write([]byte("data: partial-unterminated"))
		if len(w.pending) == 0 {
			t.Fatal("expected buffered pending event")
		}
		conn, _, err := w.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		writesBefore := root.writes
		flushedBefore := root.flushed
		w.Finish()
		w.Flush()
		if root.writes != writesBefore || root.flushed != flushedBefore {
			t.Fatalf("Finish/Flush after Hijack must not touch hijacked conn: writes %d->%d flushed %d->%d",
				writesBefore, root.writes, flushedBefore, root.flushed)
		}
	})
}

func TestMCPSSEWriter_WS101AndPostHijackFinishSafety(t *testing.T) {
	t.Run("101 never activates SSE and Hijack works via Unwrap wrapper", func(t *testing.T) {
		root := newWSMockWriter()
		outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
		m := &mcpSSEWriter{base: outer, rc: &dsctx.RequestContext{}}
		m.Header().Set("Content-Type", "text/event-stream")
		m.WriteHeader(http.StatusSwitchingProtocols)
		if m.status != http.StatusSwitchingProtocols || m.active {
			t.Fatalf("101 must not activate MCP SSE: status=%d active=%v", m.status, m.active)
		}
		conn, _, err := m.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		m.Finish()
		m.Flush()
		if root.writes != 0 || root.flushed != 0 {
			t.Fatalf("Finish/Flush after Hijack must not touch conn: writes=%d flushed=%d", root.writes, root.flushed)
		}
	})

	t.Run("pending SSE buffer cleared on Hijack", func(t *testing.T) {
		root := newWSMockWriter()
		m := &mcpSSEWriter{base: root, rc: &dsctx.RequestContext{}}
		m.Header().Set("Content-Type", "text/event-stream")
		m.WriteHeader(http.StatusOK)
		_, _ = m.Write([]byte("data: partial"))
		conn, _, err := m.Hijack()
		if err != nil {
			t.Fatalf("Hijack failed: %v", err)
		}
		_ = conn.Close()
		writesBefore := root.writes
		m.Finish()
		if root.writes != writesBefore {
			t.Fatalf("Finish after Hijack wrote to conn: %d -> %d", writesBefore, root.writes)
		}
	})
}

func TestL7ResponseCapture_WS101AndHeaderBlockNoBypass(t *testing.T) {
	t.Run("normal 101 forwards immediately and Hijack prevents commit", func(t *testing.T) {
		g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
			ID: "response-body", Priority: 1, Enabled: true,
			Conditions: []l7rules.ConditionJSON{{Type: "response_body", Op: "contains", Value: "secret"}},
			Action:     "block",
		})})
		root := newWSMockWriter()
		outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}
		err := g.ServeHTTP(outer, l7Req("GET", "/ws", "203.0.113.60:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
			w.WriteHeader(http.StatusEarlyHints)
			w.Header().Set("Upgrade", "websocket")
			w.Header().Set("Connection", "Upgrade")
			w.WriteHeader(http.StatusSwitchingProtocols)
			if len(root.codes) != 2 || root.codes[1] != http.StatusSwitchingProtocols {
				t.Fatalf("101 must be forwarded immediately before Hijack, got codes=%v", root.codes)
			}
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatalf("Hijack failed: %v", err)
			}
			_ = conn.Close()
			return nil
		}))
		if err != nil {
			t.Fatalf("ServeHTTP err = %v", err)
		}
		if !root.hijacked {
			t.Fatal("expected hijack")
		}
		if root.writes != 0 {
			t.Fatalf("post-hijack must not write body, writes=%d", root.writes)
		}
	})

	t.Run("L7 response_header block refuses Hijack and serves 403", func(t *testing.T) {
		for _, propagateErr := range []bool{false, true} {
			name := "downstream_returns_nil_like_caddy_reverse_proxy"
			if propagateErr {
				name = "downstream_propagates_hijack_err"
			}
			t.Run(name, func(t *testing.T) {
				g := newTestGuard(t, Guard{AppID: "app1", L7Rules: l7Config(l7rules.RuleJSON{
					ID: "ws-hdr-block", Priority: 1, Enabled: true,
					Conditions: []l7rules.ConditionJSON{{Type: "response_header", Name: "X-Deny-WS", Op: "eq", Value: "1"}},
					Action:     "block", ActionConfig: l7rules.ActionConfigJSON{Status: 403, Message: "ws blocked"},
				})})
				root := newWSMockWriter()
				err := g.ServeHTTP(root, l7Req("GET", "/ws", "203.0.113.61:1"), nextFunc(func(w http.ResponseWriter, r *http.Request) error {
					w.Header().Set("Upgrade", "websocket")
					w.Header().Set("X-Deny-WS", "1")
					w.WriteHeader(http.StatusSwitchingProtocols)
					_, _, herr := w.(http.Hijacker).Hijack()
					if !errors.Is(herr, errL7ResponseDiscarded) {
						t.Fatalf("Hijack must be rejected with errL7ResponseDiscarded, got %v", herr)
					}
					if propagateErr {
						return herr
					}
					return nil
				}))
				if err != nil {
					t.Fatalf("ServeHTTP err = %v", err)
				}
				if root.hijacked {
					t.Fatal("blocked 101 response must NOT hijack connection")
				}
				if len(root.codes) != 1 || root.codes[0] != http.StatusForbidden {
					t.Fatalf("codes = %v, want [403]", root.codes)
				}
			})
		}
	})
}

func TestAllGuardWrappers_NestedWebSocket101AndHijackThroughUnwrapWrapper(t *testing.T) {
	// Exercise the full nested wrapper chain mirroring a real Caddy request with
	// every optional wrapper active at once, sitting inside Caddy's Unwrap-only
	// ResponseWriterWrapper.
	root := newWSMockWriter()
	outer := &caddyhttp.ResponseWriterWrapper{ResponseWriter: root}

	bypassW := &statusCountingResponseWriter{ResponseWriter: outer}
	accessW := &captureResponseWriter{ResponseWriter: bypassW, cfg: &accessLogJSON{CaptureResponseBody: true}, bodyLimit: 64}
	l7W := newL7ResponseCapture(accessW, nil)
	csSigW := aicrawl.NewContentSignalWriter(l7W, "ai-train=no")
	lab := aicrawl.NewLabyrinth(aicrawl.LabyrinthConfig{Key: []byte("0123456789abcdef0123456789abcdef")})
	trapW := lab.NewTrapLinkInjectorWriter(csSigW, "example.com", "/ws")
	csEng, err := clientside.NewEngine(&clientside.Policy{
		SchemaVersion: clientside.SchemaVersion,
		ApplicationID: "app-1",
		Mode:          clientside.ModeObserve,
		Version:       1,
		CSPMode:       clientside.CSPModeReportOnly,
	}, clientside.EngineOptions{})
	if err != nil {
		t.Fatalf("clientside.NewEngine: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/ws", nil)
	htmlW := csEng.NewHTMLResponseWrapper(trapW, req, "/ws", nil)
	redirW := newRedirectLocationWriter(htmlW, 8443)
	a2aW := &a2aAgentCardSniffer{ResponseWriter: redirW, req: req}
	peekW := &apiResponseHeaderPeek{base: a2aW}
	mcpSSEW := &mcpSSEWriter{base: peekW, rc: &dsctx.RequestContext{}}
	respSSEW := &apiResponseSSEWriter{base: mcpSSEW, rc: &dsctx.RequestContext{}}
	apiCapW := newAPIResponseCapture(respSSEW, 1024, false, false, nil, false, "GET /ws", "req-nested-ws", zap.NewNop())
	sfW := &strongFlowResponseRecorder{base: apiCapW, captureBody: true}

	// Innermost writer must satisfy direct http.Hijacker (as required by coraza-caddy).
	var inner http.ResponseWriter = sfW
	hijacker, ok := inner.(http.Hijacker)
	if !ok {
		t.Fatal("innermost wrapper must implement http.Hijacker directly")
	}

	// Provisional 103 must pass through without locking any wrapper's final status.
	inner.WriteHeader(http.StatusEarlyHints)
	if accessW.status != 0 || bypassW.status != 0 || l7W.status != 0 || apiCapW.status != 0 || sfW.status != 0 || peekW.status != 0 {
		t.Fatalf("provisional 103 locked status: access=%d bypass=%d l7=%d apiCap=%d sf=%d peek=%d",
			accessW.status, bypassW.status, l7W.status, apiCapW.status, sfW.status, peekW.status)
	}

	// Final 101 Switching Protocols must be forwarded immediately (unbuffered) and recorded.
	inner.Header().Set("Upgrade", "websocket")
	inner.Header().Set("Connection", "Upgrade")
	inner.Header().Set("Sec-WebSocket-Accept", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
	inner.WriteHeader(http.StatusSwitchingProtocols)

	if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusSwitchingProtocols {
		t.Fatalf("root codes = %v, want [103 101]", root.codes)
	}
	for label, got := range map[string]int{
		"bypass": bypassW.status, "access": accessW.status, "l7": l7W.status,
		"a2a": a2aW.status, "peek": peekW.status, "mcpSSE": mcpSSEW.status,
		"respSSE": respSSEW.status, "apiCap": apiCapW.status, "strongFlow": sfW.status,
	} {
		if got != http.StatusSwitchingProtocols {
			t.Errorf("%s status = %d, want 101", label, got)
		}
	}

	// Hijack must traverse every wrapper AND Caddy's Unwrap-only ResponseWriterWrapper.
	conn, rw, err := hijacker.Hijack()
	if err != nil || conn == nil || rw == nil {
		t.Fatalf("nested Hijack failed: conn=%v rw=%v err=%v", conn, rw, err)
	}
	_ = conn.Close()
	if !root.hijacked {
		t.Fatal("root writer was not hijacked")
	}

	// Post-handler Finish/commit calls must NOT write to the hijacked connection.
	respSSEW.Finish()
	mcpSSEW.Finish()
	a2aW.Finish()
	htmlW.Finish(false)
	trapW.Finish(false)
	l7W.commit()
	if status, kind := apiCapW.outcome(); status != http.StatusSwitchingProtocols || kind != outcomeHijacked {
		t.Fatalf("apiCapW.outcome() = (%d, %d), want (101, %d)", status, kind, outcomeHijacked)
	}
	if root.writes != 0 {
		t.Fatalf("post-hijack Finish/commit must not write, root.writes=%d", root.writes)
	}
}
