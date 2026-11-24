package jiuzhang_guard

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

type softwareBypassHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f softwareBypassHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

type fixedResourceSampler struct{ sample resourceSample }

func (s fixedResourceSampler) Sample() resourceSample { return s.sample }

func testBypassConfig() bypassRuntimeConfig {
	cfg, err := (&SoftwareBypass{
		Enabled: true, CPUThresholdPercent: 80, MemoryThresholdPercent: 80,
		MinHoldSeconds: 10, SessionCookieNames: []string{"JSESSIONID"},
	}).runtimeConfig()
	if err != nil {
		panic(err)
	}
	return cfg
}

func registerTestBypassState(runtime *softwareRuntime, appID string, cfg bypassRuntimeConfig) *softwareBypassState {
	state := newSoftwareBypassState(appID, "test-node", cfg)
	runtime.register(state)
	return state
}

func TestEvaluateSoftwareBypassThresholdHoldAndRecovery(t *testing.T) {
	cfg := testBypassConfig()
	now := time.Now().UTC()
	atThreshold := resourceSample{cpuAvailable: true, cpuPercent: 80, memoryAvailable: true, memoryPercent: 20}
	if active, _ := evaluateSoftwareBypass(cfg, atThreshold, false, time.Time{}, now); active {
		t.Fatal("exactly 80% must not trigger; threshold semantics are strictly greater than")
	}
	high := resourceSample{cpuAvailable: true, cpuPercent: 81, memoryAvailable: true, memoryPercent: 20}
	if active, reason := evaluateSoftwareBypass(cfg, high, false, time.Time{}, now); !active || reason != "CPU_THRESHOLD" {
		t.Fatalf("high CPU decision = %v, %q", active, reason)
	}
	low := resourceSample{cpuAvailable: true, cpuPercent: 20, memoryAvailable: true, memoryPercent: 20}
	if active, _ := evaluateSoftwareBypass(cfg, low, true, now, now.Add(9*time.Second)); !active {
		t.Fatal("bypass must remain active during minimum hold")
	}
	if active, _ := evaluateSoftwareBypass(cfg, low, true, now, now.Add(11*time.Second)); active {
		t.Fatal("bypass must recover below both recovery thresholds after hold")
	}
	borderlineRecovery := resourceSample{cpuAvailable: true, cpuPercent: 75, memoryAvailable: true, memoryPercent: 20}
	if active, _ := evaluateSoftwareBypass(cfg, borderlineRecovery, true, now, now.Add(11*time.Second)); !active {
		t.Fatal("exactly 75% must remain active; recovery is strictly below 75%")
	}
}

func TestEvaluateSoftwareBypassMemoryAndUnavailableSamples(t *testing.T) {
	cfg := testBypassConfig()
	now := time.Now().UTC()
	memoryHigh := resourceSample{cpuAvailable: true, cpuPercent: 10, memoryAvailable: true, memoryPercent: 81}
	if active, reason := evaluateSoftwareBypass(cfg, memoryHigh, false, time.Time{}, now); !active || reason != "MEMORY_THRESHOLD" {
		t.Fatalf("high memory decision = %v, %q", active, reason)
	}
	unavailable := resourceSample{}
	if active, _ := evaluateSoftwareBypass(cfg, unavailable, true, now, now.Add(time.Minute)); !active {
		t.Fatal("active bypass must not flap off when resource sampling is unavailable")
	}
	cfg.enabled = false
	if active, _ := evaluateSoftwareBypass(cfg, memoryHigh, true, now, now); active {
		t.Fatal("disabled configuration must not bypass")
	}
}

func TestSoftwareBypassRoutesAndRecordsMetrics(t *testing.T) {
	now := time.Now().UTC()
	runtime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{
		takenAt: now, cpuAvailable: true, cpuPercent: 90, memoryAvailable: true, memoryPercent: 20,
	}}, &connectionMetrics{})
	state := registerTestBypassState(runtime, "app-1", testBypassConfig())
	runtime.sampleOnce()

	var normalCalls, bypassCalls int
	handler := &SoftwareBypass{
		AppID: "app-1", runtime: runtime, state: state,
		normalHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error {
			normalCalls++
			return nil
		}),
		bypassHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error {
			bypassCalls++
			return nil
		}),
	}
	request := httptest.NewRequest("GET", "http://example.com/", nil)
	request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "raw-session-id"})
	if err := handler.ServeHTTP(httptest.NewRecorder(), request, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		t.Fatal("route handler must consume the request")
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if normalCalls != 0 || bypassCalls != 1 {
		t.Fatalf("normal=%d bypass=%d, want 0/1", normalCalls, bypassCalls)
	}
	snapshot := runtime.snapshot(now)
	if snapshot.HTTP.RequestsTotal != 1 || snapshot.HTTP.SessionsActive != 1 || snapshot.HTTP.SessionsNewTotal != 1 {
		t.Fatalf("HTTP metrics = %+v", snapshot.HTTP)
	}
	if snapshot.SoftwareBypass.BypassedRequestsTotal != 1 || !snapshot.SoftwareBypass.Active {
		t.Fatalf("bypass metrics = %+v", snapshot.SoftwareBypass)
	}
}

// Lightweight session tracking runs continuously whenever session cookie names
// are configured, even when automatic software bypass is disabled.
func TestSoftwareBypassDisabledTracksSessionsWithoutBypassing(t *testing.T) {
	now := time.Now().UTC()
	runtime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{
		takenAt: now, cpuAvailable: true, cpuPercent: 100, memoryAvailable: true, memoryPercent: 100,
	}}, &connectionMetrics{})
	cfg := testBypassConfig()
	cfg.enabled = false
	state := registerTestBypassState(runtime, "disabled-app", cfg)
	runtime.sampleOnce()
	normalCalls := 0
	handler := &SoftwareBypass{
		AppID: "disabled-app", runtime: runtime, state: state,
		normalHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error {
			normalCalls++
			return nil
		}),
	}
	for i := 0; i < 100; i++ {
		request := httptest.NewRequest("GET", "http://example.com/", nil)
		request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: fmt.Sprintf("session-%d", i)})
		if err := handler.ServeHTTP(httptest.NewRecorder(), request, nil); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := runtime.snapshot(now)
	if normalCalls != 100 || snapshot.HTTP.RequestsTotal != 100 {
		t.Fatalf("normal calls=%d requests=%d, want 100/100", normalCalls, snapshot.HTTP.RequestsTotal)
	}
	if snapshot.HTTP.SessionsActive != 100 || snapshot.HTTP.SessionsNewTotal != 100 || snapshot.HTTP.SessionsOverflowTotal != 0 {
		t.Fatalf("always-on session tracking metrics = %+v, want active=100 new=100 overflow=0", snapshot.HTTP)
	}
	if snapshot.SoftwareBypass.Enabled || snapshot.SoftwareBypass.Active || snapshot.SoftwareBypass.BypassedRequestsTotal != 0 {
		t.Fatalf("disabled bypass changed routing state: %+v", snapshot.SoftwareBypass)
	}

	// Empty session cookie set must not track any sessions.
	emptyRuntime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{takenAt: now}}, &connectionMetrics{})
	emptyCfg, err := (&SoftwareBypass{Enabled: false, SessionCookieNames: []string{}}).runtimeConfig()
	if err != nil {
		t.Fatal(err)
	}
	emptyState := registerTestBypassState(emptyRuntime, "no-cookie-app", emptyCfg)
	emptyHandler := &SoftwareBypass{
		AppID: "no-cookie-app", runtime: emptyRuntime, state: emptyState,
		normalHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
	}
	req := httptest.NewRequest("GET", "http://example.com/", nil)
	req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "ignored"})
	if err := emptyHandler.ServeHTTP(httptest.NewRecorder(), req, nil); err != nil {
		t.Fatal(err)
	}
	emptySnap := emptyRuntime.snapshot(now)
	if emptySnap.HTTP.SessionsActive != 0 || emptySnap.HTTP.SessionsNewTotal != 0 {
		t.Fatalf("empty session cookie config tracked sessions: %+v", emptySnap.HTTP)
	}
}

func TestSoftwareRuntimeIsolatesConfigurationsAndLifecycle(t *testing.T) {
	now := time.Now().UTC()
	runtime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{
		takenAt: now, cpuAvailable: true, cpuPercent: 70, memoryAvailable: true, memoryPercent: 20,
	}}, &connectionMetrics{})
	strictConfig := testBypassConfig()
	strictConfig.cpuThreshold = 90
	strictConfig.sessionCookieSet = map[string]struct{}{"JSESSIONID": {}}
	relaxedConfig := testBypassConfig()
	relaxedConfig.cpuThreshold = 60
	relaxedConfig.sessionCookieSet = map[string]struct{}{"PHPSESSID": {}}
	strictState := registerTestBypassState(runtime, "strict-app", strictConfig)
	relaxedState := registerTestBypassState(runtime, "relaxed-app", relaxedConfig)
	runtime.sampleOnce()
	if strictState.active.Load() || !relaxedState.active.Load() {
		t.Fatalf("cross-configuration decision overwrite: strict=%v relaxed=%v", strictState.active.Load(), relaxedState.active.Load())
	}

	newHandler := func(appID string, state *softwareBypassState) *SoftwareBypass {
		return &SoftwareBypass{
			AppID: appID, runtime: runtime, state: state,
			normalHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
			bypassHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
		}
	}
	strictHandler := newHandler("strict-app", strictState)
	relaxedHandler := newHandler("relaxed-app", relaxedState)
	strictRequest := httptest.NewRequest("GET", "http://strict.example.com/", nil)
	strictRequest.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: "strict-session"})
	if err := strictHandler.ServeHTTP(httptest.NewRecorder(), strictRequest, nil); err != nil {
		t.Fatal(err)
	}
	relaxedRequest := httptest.NewRequest("GET", "http://relaxed.example.com/", nil)
	relaxedRequest.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: "relaxed-session"})
	if err := relaxedHandler.ServeHTTP(httptest.NewRecorder(), relaxedRequest, nil); err != nil {
		t.Fatal(err)
	}

	snapshot := runtime.snapshot(now)
	if snapshot.HTTP.RequestsTotal != 2 || snapshot.HTTP.SessionsNewTotal != 2 || snapshot.HTTP.SessionsActive != 2 {
		t.Fatalf("isolated HTTP metrics = %+v", snapshot.HTTP)
	}
	if !snapshot.SoftwareBypass.Active || snapshot.SoftwareBypass.BypassedRequestsTotal != 1 || snapshot.SoftwareBypass.CPUThresholdPercent != 60 {
		t.Fatalf("aggregate bypass metrics = %+v", snapshot.SoftwareBypass)
	}
	if err := strictHandler.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if err := strictHandler.Cleanup(); err != nil {
		t.Fatal(err)
	}
	snapshot = runtime.snapshot(now)
	if snapshot.HTTP.RequestsTotal != 1 || snapshot.SoftwareBypass.BypassedRequestsTotal != 1 || !snapshot.SoftwareBypass.Active {
		t.Fatalf("cleanup removed or retained the wrong state: %+v", snapshot)
	}
	if snapshot.SoftwareBypass.CPUThresholdPercent != 60 || snapshot.Node != "test-node" {
		t.Fatalf("remaining configuration changed after peer cleanup: %+v", snapshot.SoftwareBypass)
	}
}

func TestSoftwareRuntimeConcurrentSamplingRequestsAndSnapshots(t *testing.T) {
	now := time.Now().UTC()
	runtime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{
		takenAt: now, cpuAvailable: true, cpuPercent: 85, memoryAvailable: true, memoryPercent: 30,
	}}, &connectionMetrics{})
	const (
		stateCount        = 4
		workersPerState   = 4
		requestsPerWorker = 40
	)
	handlers := make([]*SoftwareBypass, 0, stateCount)
	for i := 0; i < stateCount; i++ {
		appID := fmt.Sprintf("app-%d", i)
		state := registerTestBypassState(runtime, appID, testBypassConfig())
		handlers = append(handlers, &SoftwareBypass{
			AppID: appID, runtime: runtime, state: state,
			normalHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
			bypassHandler: softwareBypassHandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil }),
		})
	}

	var wg sync.WaitGroup
	for i, handler := range handlers {
		for worker := 0; worker < workersPerState; worker++ {
			wg.Add(1)
			go func(handler *SoftwareBypass, worker int) {
				defer wg.Done()
				for requestNumber := 0; requestNumber < requestsPerWorker; requestNumber++ {
					request := httptest.NewRequest("GET", "http://example.com/", nil)
					request.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: fmt.Sprintf("session-%d-%d", worker, requestNumber)})
					if err := handler.ServeHTTP(httptest.NewRecorder(), request, nil); err != nil {
						t.Error(err)
						return
					}
				}
			}(handler, worker+i*workersPerState)
		}
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			runtime.sampleOnce()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = runtime.snapshot(time.Now().UTC())
		}
	}()
	wg.Wait()

	snapshot := runtime.snapshot(time.Now().UTC())
	wantRequests := uint64(stateCount * workersPerState * requestsPerWorker)
	if snapshot.HTTP.RequestsTotal != wantRequests || snapshot.HTTP.RequestsInFlight != 0 {
		t.Fatalf("concurrent HTTP metrics = %+v, want requests=%d", snapshot.HTTP, wantRequests)
	}
	if snapshot.HTTP.SessionsActive > defaultMaxTrackedSessions {
		t.Fatalf("session bound exceeded: %+v", snapshot.HTTP)
	}
}

func TestSoftwareBypassValidation(t *testing.T) {
	for _, cfg := range []*SoftwareBypass{
		{CPUThresholdPercent: 101},
		{MemoryThresholdPercent: -1},
		{MinHoldSeconds: 301},
		{SessionCookieNames: []string{"bad name"}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", cfg)
		}
	}
}

type hijackableTestWriter struct {
	*httptest.ResponseRecorder
	hijacked bool
	flushed  bool
}

func (w *hijackableTestWriter) Flush() {
	w.flushed = true
	w.ResponseRecorder.Flush()
}

func (w *hijackableTestWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, bufio.NewReadWriter(bufio.NewReader(c1), bufio.NewWriter(c1)), nil
}

func TestSoftwareBypassCapturesStatusCodesBytesAndStreaming(t *testing.T) {
	now := time.Now().UTC()
	runtime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{takenAt: now}}, &connectionMetrics{})
	cfg := testBypassConfig()
	cfg.enabled = false
	state := registerTestBypassState(runtime, "status-app", cfg)

	run := func(req *http.Request, w http.ResponseWriter, fn func(http.ResponseWriter, *http.Request) error) error {
		h := &SoftwareBypass{
			AppID: "status-app", runtime: runtime, state: state,
			normalHandler: softwareBypassHandlerFunc(fn),
		}
		return h.ServeHTTP(w, req, nil)
	}

	// 1. Implicit 200 (no WriteHeader, no Write, nil err) + ContentLength fallback for unread body.
	reqUnread := httptest.NewRequest(http.MethodPost, "http://example.com/unread", strings.NewReader("1234567890"))
	if err := run(reqUnread, httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) error { return nil }); err != nil {
		t.Fatal(err)
	}

	// 2. Chunked body read (ContentLength = -1) + 103 Early Hints followed by 204.
	reqChunked := httptest.NewRequest(http.MethodPost, "http://example.com/chunked", io.NopCloser(bytes.NewBufferString("abcdef")))
	reqChunked.ContentLength = -1
	if err := run(reqChunked, httptest.NewRecorder(), func(w http.ResponseWriter, r *http.Request) error {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusEarlyHints)
		w.WriteHeader(http.StatusNoContent)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 3. 302 redirect + response bytes.
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/redir", nil), httptest.NewRecorder(), func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusFound)
		_, _ = w.Write([]byte("moved"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 4. Explicit 403 + response bytes.
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/deny", nil), httptest.NewRecorder(), func(w http.ResponseWriter, _ *http.Request) error {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("forbidden"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// 5. caddyhttp.HandlerError 429 without WriteHeader.
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/rl", nil), httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) error {
		return caddyhttp.Error(http.StatusTooManyRequests, errors.New("rate limited"))
	}); err == nil {
		t.Fatal("expected 429 HandlerError")
	}

	// 6. caddyhttp.HandlerError 502 without WriteHeader.
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/bg", nil), httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) error {
		return caddyhttp.Error(http.StatusBadGateway, errors.New("upstream down"))
	}); err == nil {
		t.Fatal("expected 502 HandlerError")
	}

	// 7. Generic error without WriteHeader -> falls back to 500 (5xx).
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/err", nil), httptest.NewRecorder(), func(http.ResponseWriter, *http.Request) error {
		return errors.New("boom")
	}); err == nil {
		t.Fatal("expected generic error")
	}

	// 8. Streaming Flush + Unwrap + Hijack passthrough.
	hw := &hijackableTestWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/sse", nil), hw, func(w http.ResponseWriter, _ *http.Request) error {
		unwrapper, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok || unwrapper.Unwrap() != hw {
			t.Fatal("statusCountingResponseWriter must unwrap to underlying ResponseWriter")
		}
		w.(http.Flusher).Flush()
		_, _ = w.Write([]byte("event: ping\n\n"))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !hw.flushed {
		t.Fatal("Flush must be forwarded to underlying writer")
	}

	wsWriter := &hijackableTestWriter{ResponseRecorder: httptest.NewRecorder()}
	if err := run(httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil), wsWriter, func(w http.ResponseWriter, _ *http.Request) error {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return err
		}
		_ = conn.Close()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !wsWriter.hijacked {
		t.Fatal("Hijack must be forwarded to underlying writer")
	}

	// Hijack on non-hijackable ResponseRecorder returns an error cleanly.
	cw := &statusCountingResponseWriter{ResponseWriter: httptest.NewRecorder()}
	if _, _, err := cw.Hijack(); err == nil {
		t.Fatal("Hijack on non-hijackable writer must return error")
	}

	snap := runtime.snapshot(now)
	// 2xx: unread(200), chunked(204), sse(200) = 3 (ws hijacked without WriteHeader is not counted as 2xx)
	// 3xx: redir(302) = 1
	// 4xx: deny(403), rl(429) = 2
	// 5xx: bg(502), err(500) = 2
	if snap.HTTP.Status2xxTotal != 3 || snap.HTTP.Status3xxTotal != 1 || snap.HTTP.Status4xxTotal != 2 || snap.HTTP.Status5xxTotal != 2 {
		t.Fatalf("status totals = 2xx:%d 3xx:%d 4xx:%d 5xx:%d, want 3/1/2/2",
			snap.HTTP.Status2xxTotal, snap.HTTP.Status3xxTotal, snap.HTTP.Status4xxTotal, snap.HTTP.Status5xxTotal)
	}
	if len(snap.Applications) != 1 {
		t.Fatalf("applications len = %d, want 1", len(snap.Applications))
	}
	app := snap.Applications[0]
	wantBytesIn := uint64(len("1234567890") + len("abcdef"))
	wantBytesOut := uint64(len("moved") + len("forbidden") + len("event: ping\n\n"))
	if app.BytesInTotal != wantBytesIn || app.BytesOutTotal != wantBytesOut {
		t.Fatalf("app bytes = in:%d out:%d, want %d/%d", app.BytesInTotal, app.BytesOutTotal, wantBytesIn, wantBytesOut)
	}
	if app.Status4xxTotal != 2 || app.Status5xxTotal != 2 {
		t.Fatalf("app 4xx/5xx = %d/%d, want 2/2", app.Status4xxTotal, app.Status5xxTotal)
	}
}

type sequenceResourceSampler struct {
	mu      sync.Mutex
	samples []resourceSample
	index   int
}

func (s *sequenceResourceSampler) Sample() resourceSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) == 0 {
		return resourceSample{takenAt: time.Now().UTC()}
	}
	if s.index >= len(s.samples) {
		return s.samples[len(s.samples)-1]
	}
	out := s.samples[s.index]
	s.index++
	return out
}

func TestSoftwareRuntimeRatesAndApplicationAggregation(t *testing.T) {
	t0 := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Second)
	t2 := t1 // elapsed == 0 guard
	t3 := t1.Add(2 * time.Second)

	sampler := &sequenceResourceSampler{
		samples: []resourceSample{
			{takenAt: t0, cpuAvailable: true, cpuPercent: 20, memoryAvailable: true, memoryPercent: 40, loadAvailable: true, load1: 0.5, fdUsageAvailable: true, fdUsagePercent: 10},
			{takenAt: t1, cpuAvailable: true, cpuPercent: 25, memoryAvailable: true, memoryPercent: 45, loadAvailable: true, load1: 0.8, fdUsageAvailable: true, fdUsagePercent: 12},
			{takenAt: t2, cpuAvailable: true, cpuPercent: 25, memoryAvailable: true, memoryPercent: 45},
			{takenAt: t3, cpuAvailable: true, cpuPercent: 30, memoryAvailable: true, memoryPercent: 50},
		},
	}
	connMetrics := &connectionMetrics{}
	runtime := newSoftwareRuntime(sampler, connMetrics)

	cfg := testBypassConfig()
	cfg.enabled = false
	// Two states sharing app-a must be aggregated into one application entry.
	stateA1 := registerTestBypassState(runtime, "app-a", cfg)
	stateA2 := registerTestBypassState(runtime, "app-a", cfg)
	stateB := registerTestBypassState(runtime, "app-b", cfg)

	// Baseline sample at t0.
	runtime.sampleOnce()

	// Traffic between t0 and t1 (2s elapsed):
	connMetrics.acceptedTotal.Add(10) // 5/s
	connMetrics.active.Store(4)
	connMetrics.bytesInTotal.Add(2000)  // 1000 B/s
	connMetrics.bytesOutTotal.Add(4000) // 2000 B/s

	stateA1.requestsTotal.Add(6)
	stateA1.bytesInTotal.Add(600)
	stateA1.bytesOutTotal.Add(1200)
	stateA1.status2xxTotal.Add(4)
	stateA1.status4xxTotal.Add(2)

	stateA2.requestsTotal.Add(4)
	stateA2.bytesInTotal.Add(400)
	stateA2.bytesOutTotal.Add(800)
	stateA2.status3xxTotal.Add(2)
	stateA2.status5xxTotal.Add(2)

	stateB.requestsTotal.Add(20)
	stateB.bytesInTotal.Add(1000)
	stateB.bytesOutTotal.Add(2000)
	stateB.status2xxTotal.Add(20)

	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.AddCookie(&http.Cookie{Name: "JSESSIONID", Value: fmt.Sprintf("s-%d", i)})
		runtime.sessions.observe(req, "app-b", cfg.sessionCookieSet, t1)
	}

	// Second sample at t1 (+2s).
	runtime.sampleOnce()

	snap := runtime.snapshot(t1)
	if snap.Connections.AcceptedPerSecond != 5 || snap.Connections.BytesInPerSecond != 1000 || snap.Connections.BytesOutPerSecond != 2000 {
		t.Fatalf("connection rates = %+v", snap.Connections)
	}
	if snap.HTTP.RequestsPerSecond != 15 || snap.HTTP.SessionsNewPerSecond != 3 {
		t.Fatalf("http rates = req/s:%v sess/s:%v, want 15/3", snap.HTTP.RequestsPerSecond, snap.HTTP.SessionsNewPerSecond)
	}
	if snap.HTTP.Status2xxPerSecond != 12 || snap.HTTP.Status3xxPerSecond != 1 || snap.HTTP.Status4xxPerSecond != 1 || snap.HTTP.Status5xxPerSecond != 1 {
		t.Fatalf("status rates = 2xx:%v 3xx:%v 4xx:%v 5xx:%v, want 12/1/1/1",
			snap.HTTP.Status2xxPerSecond, snap.HTTP.Status3xxPerSecond, snap.HTTP.Status4xxPerSecond, snap.HTTP.Status5xxPerSecond)
	}
	if len(snap.Applications) != 2 {
		t.Fatalf("applications = %+v, want 2 aggregated entries", snap.Applications)
	}
	// app-b has 10 req/s > app-a 5 req/s
	if snap.Applications[0].AppID != "app-b" || snap.Applications[0].RequestsPerSecond != 10 {
		t.Fatalf("top app = %+v, want app-b @ 10 req/s", snap.Applications[0])
	}
	appA := snap.Applications[1]
	if appA.AppID != "app-a" || appA.RequestsTotal != 10 || appA.RequestsPerSecond != 5 ||
		appA.BytesInTotal != 1000 || appA.BytesOutTotal != 2000 ||
		appA.BytesInPerSecond != 500 || appA.BytesOutPerSecond != 1000 ||
		appA.Status4xxTotal != 2 || appA.Status5xxTotal != 2 {
		t.Fatalf("aggregated app-a = %+v", appA)
	}

	// Third sample at t2 (elapsed == 0): must not divide by zero or produce NaN/Inf.
	runtime.sampleOnce()
	snapZeroElapsed := runtime.snapshot(t2)
	if math.IsNaN(snapZeroElapsed.HTTP.RequestsPerSecond) || math.IsInf(snapZeroElapsed.HTTP.RequestsPerSecond, 0) {
		t.Fatalf("elapsed=0 produced non-finite rate: %v", snapZeroElapsed.HTTP.RequestsPerSecond)
	}

	// Unregister stateB so global requestsTotal drops (counter decrease); fourth sample at t3 must clamp rate to 0.
	runtime.unregister(stateB)
	runtime.sampleOnce()
	snapDrop := runtime.snapshot(t3)
	if snapDrop.HTTP.RequestsPerSecond != 0 {
		t.Fatalf("counter decrease must yield 0 rate, got %v", snapDrop.HTTP.RequestsPerSecond)
	}

	// Verify Top-20 cap & tie-breaking by requests_total desc.
	topRuntime := newSoftwareRuntime(fixedResourceSampler{sample: resourceSample{takenAt: t0}}, &connectionMetrics{})
	for i := 0; i < 25; i++ {
		st := registerTestBypassState(topRuntime, fmt.Sprintf("app-%02d", i), cfg)
		st.requestsTotal.Store(uint64(i + 1))
	}
	topSnap := topRuntime.snapshot(t0)
	if len(topSnap.Applications) != 20 {
		t.Fatalf("applications len = %d, want max 20", len(topSnap.Applications))
	}
	if topSnap.Applications[0].AppID != "app-24" || topSnap.Applications[19].AppID != "app-05" {
		t.Fatalf("top-20 order = first:%s last:%s, want app-24..app-05", topSnap.Applications[0].AppID, topSnap.Applications[19].AppID)
	}
}

func TestRuntimeHistoryRingAndAdminEndpoints(t *testing.T) {
	// 1. Small ring buffer eviction & chronological order.
	ring := newRuntimeHistoryRing(3)
	if pts := ring.snapshot(); pts == nil || len(pts) != 0 {
		t.Fatalf("empty ring snapshot = %#v, want non-nil empty slice", pts)
	}
	base := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		ring.push(RuntimeHistoryPoint{
			TakenAt:              base.Add(time.Duration(i*2) * time.Second),
			TCPConnectionsActive: int64(i + 1),
		})
	}
	pts := ring.snapshot()
	if len(pts) != 3 || pts[0].TCPConnectionsActive != 3 || pts[1].TCPConnectionsActive != 4 || pts[2].TCPConnectionsActive != 5 {
		t.Fatalf("ring points = %+v, want [3, 4, 5]", pts)
	}

	// 2. Empty RuntimeAdmin history endpoint encodes [] (never null) and rejects non-GET with 405.
	var seqSamples []resourceSample
	for i := 0; i < 350; i++ {
		seqSamples = append(seqSamples, resourceSample{
			takenAt:          base.Add(time.Duration(i*2) * time.Second),
			cpuAvailable:     true,
			cpuPercent:       float64(i % 100),
			memoryAvailable:  true,
			memoryPercent:    50,
			loadAvailable:    true,
			load1:            1.5,
			fdUsageAvailable: true,
			fdUsagePercent:   3.2,
		})
	}
	runtime := newSoftwareRuntime(&sequenceResourceSampler{samples: seqSamples}, &connectionMetrics{})
	registerTestBypassState(runtime, "hist-app", testBypassConfig())
	admin := &RuntimeAdmin{runtime: runtime}

	// Check registered routes.
	routes := admin.Routes()
	if len(routes) != 2 || routes[0].Pattern != "/jiuzhang/runtime" || routes[1].Pattern != "/jiuzhang/runtime/history" {
		t.Fatalf("admin routes = %+v", routes)
	}

	// Empty history returns JSON with "points":[].
	rec := httptest.NewRecorder()
	if err := admin.serveHistoryHTTP(rec, httptest.NewRequest(http.MethodGet, "/jiuzhang/runtime/history", nil)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("empty history status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"points":[]`) {
		t.Fatalf("empty history must encode points as [], got %s", rec.Body.String())
	}

	// Non-GET must return 405 on both endpoints.
	for _, fn := range []func(http.ResponseWriter, *http.Request) error{admin.serveHTTP, admin.serveHistoryHTTP} {
		postRec := httptest.NewRecorder()
		if err := fn(postRec, httptest.NewRequest(http.MethodPost, "/jiuzhang/runtime", nil)); err != nil {
			t.Fatal(err)
		}
		if postRec.Code != http.StatusMethodNotAllowed || postRec.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("POST status=%d Allow=%q, want 405/GET", postRec.Code, postRec.Header().Get("Allow"))
		}
	}

	// 3. 350 samples saturate capacity 300 and retain newest 300 in chronological order.
	for i := 0; i < 350; i++ {
		runtime.sampleOnce()
	}
	recFull := httptest.NewRecorder()
	if err := admin.serveHistoryHTTP(recFull, httptest.NewRequest(http.MethodGet, "/jiuzhang/runtime/history", nil)); err != nil {
		t.Fatal(err)
	}
	var history RuntimeHistory
	if err := json.Unmarshal(recFull.Body.Bytes(), &history); err != nil {
		t.Fatal(err)
	}
	if history.Node != "test-node" || history.IntervalSeconds != 2 {
		t.Fatalf("history header = node:%q interval:%d", history.Node, history.IntervalSeconds)
	}
	if len(history.Points) != defaultRuntimeHistoryCapacity {
		t.Fatalf("history len = %d, want %d", len(history.Points), defaultRuntimeHistoryCapacity)
	}
	wantFirst := base.Add(50 * 2 * time.Second)
	wantLast := base.Add(349 * 2 * time.Second)
	if !history.Points[0].TakenAt.Equal(wantFirst) || !history.Points[299].TakenAt.Equal(wantLast) {
		t.Fatalf("history time range = [%v .. %v], want [%v .. %v]",
			history.Points[0].TakenAt, history.Points[299].TakenAt, wantFirst, wantLast)
	}
	for i := 1; i < len(history.Points); i++ {
		if !history.Points[i].TakenAt.After(history.Points[i-1].TakenAt) {
			t.Fatalf("history points not strictly chronological at index %d", i)
		}
	}
	if history.Points[0].Load1 == nil || *history.Points[0].Load1 != 1.5 || history.Points[0].FDUsagePercent == nil || *history.Points[0].FDUsagePercent != 3.2 {
		t.Fatalf("history extended point fields missing: %+v", history.Points[0])
	}
}
