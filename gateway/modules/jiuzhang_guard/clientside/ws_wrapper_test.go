package clientside

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

type wsTestWriter struct {
	header   http.Header
	codes    []int
	flushed  int
	hijacked bool
	writes   int
}

func (w *wsTestWriter) Header() http.Header         { return w.header }
func (w *wsTestWriter) WriteHeader(code int)        { w.codes = append(w.codes, code) }
func (w *wsTestWriter) Write(p []byte) (int, error) { w.writes++; return len(p), nil }
func (w *wsTestWriter) Flush()                      { w.flushed++ }
func (w *wsTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

type unwrapOnlyWriter struct{ http.ResponseWriter }

func (u *unwrapOnlyWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func TestHTMLResponseWrapper_101AndHijackViaUnwrap(t *testing.T) {
	eng, err := NewEngine(&Policy{
		SchemaVersion:  SchemaVersion,
		ApplicationID:  "app-1",
		Mode:           ModeProtect,
		Version:        1,
		CSPMode:        CSPModeEnforce,
		SensitivePaths: []string{"/ws"},
		ProbeEnabled:   true,
	}, EngineOptions{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	root := &wsTestWriter{header: make(http.Header)}
	outer := &unwrapOnlyWriter{ResponseWriter: root}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/ws", nil)
	hw := eng.NewHTMLResponseWrapper(outer, req, "/ws", nil)

	if hw.Unwrap() != outer {
		t.Fatal("Unwrap mismatch")
	}

	hw.WriteHeader(http.StatusEarlyHints)
	if hw.status != 0 {
		t.Fatalf("103 must be provisional, got status=%d", hw.status)
	}
	hw.Header().Set("Upgrade", "websocket")
	hw.Header().Set("Connection", "Upgrade")
	hw.WriteHeader(http.StatusSwitchingProtocols)
	if len(root.codes) != 2 || root.codes[0] != http.StatusEarlyHints || root.codes[1] != http.StatusSwitchingProtocols {
		t.Fatalf("101 must forward immediately: codes=%v", root.codes)
	}
	if root.Header().Get("Content-Security-Policy") != "" || root.Header().Get("Content-Security-Policy-Report-Only") != "" {
		t.Fatalf("101 must not receive CSP header: %v", root.Header())
	}

	hw.Flush()
	if root.flushed != 1 {
		t.Fatalf("flushed = %d, want 1", root.flushed)
	}
	conn, _, err := hw.Hijack()
	if err != nil {
		t.Fatalf("Hijack failed: %v", err)
	}
	_ = conn.Close()
	if !root.hijacked {
		t.Fatal("root not hijacked")
	}

	// Post-hijack Finish and Flush must not touch the hijacked connection.
	hw.Finish(false)
	hw.Flush()
	if root.writes != 0 || root.flushed != 1 {
		t.Fatalf("Finish/Flush after Hijack must not touch conn: writes=%d flushed=%d", root.writes, root.flushed)
	}
}
