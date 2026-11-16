package jiuzhang_guard

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestSoftwareBypassDisabledSkipsSessionTracking(t *testing.T) {
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
	if snapshot.HTTP.SessionsActive != 0 || snapshot.HTTP.SessionsNewTotal != 0 || snapshot.HTTP.SessionsOverflowTotal != 0 {
		t.Fatalf("disabled bypass tracked sessions: %+v", snapshot.HTTP)
	}
	if snapshot.SoftwareBypass.Enabled || snapshot.SoftwareBypass.Active || snapshot.SoftwareBypass.BypassedRequestsTotal != 0 {
		t.Fatalf("disabled bypass changed routing state: %+v", snapshot.SoftwareBypass)
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
