package jiuzhang_guard

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	defaultSoftwareBypassThreshold = 80
	softwareBypassRecoveryDelta    = 5
	defaultSoftwareBypassHold      = 10 * time.Second
	softwareBypassSampleInterval   = 2 * time.Second
)

var (
	defaultSessionCookieNames = []string{"JSESSIONID", "PHPSESSID", "SESSION", "SESSIONID", "connect.sid"}
	sessionCookieNamePattern  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
)

func init() {
	caddy.RegisterModule(&SoftwareBypass{})
	caddy.RegisterModule(&RuntimeAdmin{})
}

// SoftwareBypass selects the detection chain or the pure reverse-proxy chain.
type SoftwareBypass struct {
	AppID                  string             `json:"app_id"`
	Node                   string             `json:"node,omitempty"`
	Enabled                bool               `json:"enabled"`
	CPUThresholdPercent    int                `json:"cpu_threshold_percent"`
	MemoryThresholdPercent int                `json:"memory_threshold_percent"`
	MinHoldSeconds         int                `json:"min_hold_seconds"`
	SessionCookieNames     []string           `json:"session_cookie_names"`
	Normal                 caddyhttp.Subroute `json:"normal"`
	Bypass                 caddyhttp.Subroute `json:"bypass"`

	runtime       *softwareRuntime
	state         *softwareBypassState
	normalHandler caddyhttp.Handler
	bypassHandler caddyhttp.Handler
}

func (SoftwareBypass) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jiuzhang_software_bypass",
		New: func() caddy.Module { return new(SoftwareBypass) },
	}
}

func (s *SoftwareBypass) Validate() error {
	_, err := s.runtimeConfig()
	return err
}

func (s *SoftwareBypass) Provision(ctx caddy.Context) error {
	cfg, err := s.runtimeConfig()
	if err != nil {
		return err
	}
	if err := s.Normal.Provision(ctx); err != nil {
		return fmt.Errorf("software bypass normal chain: %w", err)
	}
	if err := s.Bypass.Provision(ctx); err != nil {
		return fmt.Errorf("software bypass pure proxy chain: %w", err)
	}
	runtime := s.runtime
	if runtime == nil {
		runtime = globalSoftwareRuntime
	}
	s.runtime = runtime
	s.state = newSoftwareBypassState(s.AppID, runtimeNode(s.Node), cfg)
	runtime.register(s.state)
	runtime.start()
	return nil
}

func (s *SoftwareBypass) Cleanup() error {
	if s.runtime != nil && s.state != nil {
		s.runtime.unregister(s.state)
	}
	return nil
}

func (s *SoftwareBypass) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	runtime := s.runtime
	if runtime == nil {
		runtime = globalSoftwareRuntime
	}
	state := s.state
	if state == nil {
		// Direct handler users outside Caddy still get a functional, isolated
		// decision state; Provision registers the state for process-level metrics.
		cfg, cfgErr := s.runtimeConfig()
		if cfgErr != nil {
			return caddyhttp.Error(http.StatusInternalServerError, cfgErr)
		}
		state = newSoftwareBypassState(s.AppID, runtimeNode(s.Node), cfg)
	}
	state.requestsTotal.Add(1)
	state.requestsInFlight.Add(1)

	origContentLength := r.ContentLength
	var origBody io.ReadCloser
	var bodyCounter *countingReadCloser
	if r.Body != nil && r.Body != http.NoBody {
		origBody = r.Body
		bodyCounter = &countingReadCloser{ReadCloser: origBody}
		r.Body = bodyCounter
	}
	cw := &statusCountingResponseWriter{ResponseWriter: w}
	completed := false
	defer func() {
		state.requestsInFlight.Add(-1)
		if bodyCounter != nil && r.Body == bodyCounter {
			r.Body = origBody
		}
		var bytesIn uint64
		if bodyCounter != nil {
			bytesIn = bodyCounter.bytesRead.Load()
		}
		if bytesIn == 0 && origContentLength > 0 {
			bytesIn = uint64(origContentLength)
		}
		if bytesIn > 0 {
			state.bytesInTotal.Add(bytesIn)
		}
		if cw.bytesOut > 0 {
			state.bytesOutTotal.Add(cw.bytesOut)
		}
		recordHTTPStatus(state, resolveHTTPStatus(cw.status, cw.hijacked, completed, err))
	}()

	// Lightweight session tracking runs continuously whenever session cookies are
	// configured (still strictly bounded by defaultMaxTrackedSessions and 5m idle expiry).
	if len(state.config.sessionCookieSet) > 0 {
		runtime.sessions.observe(r, s.AppID, state.config.sessionCookieSet, time.Now().UTC())
	}
	if state.active.Load() {
		state.bypassedRequestsTotal.Add(1)
		if s.bypassHandler != nil {
			err = s.bypassHandler.ServeHTTP(cw, r)
		} else {
			err = s.Bypass.ServeHTTP(cw, r, next)
		}
		completed = true
		return err
	}
	if s.normalHandler != nil {
		err = s.normalHandler.ServeHTTP(cw, r)
	} else {
		err = s.Normal.ServeHTTP(cw, r, next)
	}
	completed = true
	return err
}

type countingReadCloser struct {
	io.ReadCloser
	bytesRead atomic.Uint64
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	n, err := c.ReadCloser.Read(p)
	if n > 0 {
		c.bytesRead.Add(uint64(n))
	}
	return n, err
}

// statusCountingResponseWriter captures HTTP status code and response byte count
// without disrupting streaming (Flush), WebSocket upgrades (Hijack), or
// http.ResponseController unwrapping (Unwrap).
type statusCountingResponseWriter struct {
	http.ResponseWriter
	status   int
	bytesOut uint64
	hijacked bool
}

func (w *statusCountingResponseWriter) WriteHeader(code int) {
	if w.status == 0 && (code == http.StatusSwitchingProtocols || code < 100 || code >= 200) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusCountingResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(p)
	if n > 0 {
		w.bytesOut += uint64(n)
	}
	return n, err
}

func (w *statusCountingResponseWriter) Flush() {
	if w.hijacked {
		return
	}
	if w.status == 0 {
		w.status = http.StatusOK
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
		return
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

func (w *statusCountingResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	var (
		conn net.Conn
		rw   *bufio.ReadWriter
		err  error
	)
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err = h.Hijack()
	} else {
		conn, rw, err = http.NewResponseController(w.ResponseWriter).Hijack()
	}
	if err == nil {
		w.hijacked = true
	}
	return conn, rw, err
}

func (w *statusCountingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func resolveHTTPStatus(writtenStatus int, hijacked, completed bool, err error) int {
	if writtenStatus != 0 {
		return writtenStatus
	}
	if err != nil {
		var he caddyhttp.HandlerError
		if errors.As(err, &he) && he.StatusCode > 0 {
			return he.StatusCode
		}
		return http.StatusInternalServerError
	}
	if !completed {
		return http.StatusInternalServerError
	}
	if hijacked {
		return 0
	}
	return http.StatusOK
}

func recordHTTPStatus(state *softwareBypassState, status int) {
	switch {
	case status >= 200 && status < 300:
		state.status2xxTotal.Add(1)
	case status >= 300 && status < 400:
		state.status3xxTotal.Add(1)
	case status >= 400 && status < 500:
		state.status4xxTotal.Add(1)
	case status >= 500 && status < 600:
		state.status5xxTotal.Add(1)
	}
}

func runtimeNode(configured string) string {
	if configured != "" {
		return configured
	}
	return strings.TrimSpace(os.Getenv("GATEWAY_NODE_NAME"))
}

type bypassRuntimeConfig struct {
	enabled            bool
	cpuThreshold       int
	memoryThreshold    int
	minHold            time.Duration
	sessionCookieNames []string
	sessionCookieSet   map[string]struct{}
}

func (s *SoftwareBypass) runtimeConfig() (bypassRuntimeConfig, error) {
	cfg := bypassRuntimeConfig{
		enabled:            s.Enabled,
		cpuThreshold:       s.CPUThresholdPercent,
		memoryThreshold:    s.MemoryThresholdPercent,
		minHold:            time.Duration(s.MinHoldSeconds) * time.Second,
		sessionCookieNames: s.SessionCookieNames,
		sessionCookieSet:   make(map[string]struct{}),
	}
	if cfg.cpuThreshold == 0 {
		cfg.cpuThreshold = defaultSoftwareBypassThreshold
	}
	if cfg.memoryThreshold == 0 {
		cfg.memoryThreshold = defaultSoftwareBypassThreshold
	}
	if cfg.minHold == 0 {
		cfg.minHold = defaultSoftwareBypassHold
	}
	if cfg.cpuThreshold < 1 || cfg.cpuThreshold > 100 || cfg.memoryThreshold < 1 || cfg.memoryThreshold > 100 {
		return bypassRuntimeConfig{}, fmt.Errorf("software bypass CPU and memory thresholds must be in range [1,100]")
	}
	if cfg.minHold < time.Second || cfg.minHold > 5*time.Minute {
		return bypassRuntimeConfig{}, fmt.Errorf("software bypass min_hold_seconds must be in range [1,300]")
	}
	if cfg.sessionCookieNames == nil {
		cfg.sessionCookieNames = slices.Clone(defaultSessionCookieNames)
	}
	if len(cfg.sessionCookieNames) > 16 {
		return bypassRuntimeConfig{}, fmt.Errorf("software bypass supports at most 16 session cookie names")
	}
	seen := make(map[string]struct{}, len(cfg.sessionCookieNames))
	for _, name := range cfg.sessionCookieNames {
		name = strings.TrimSpace(name)
		if len(name) == 0 || len(name) > 64 || !sessionCookieNamePattern.MatchString(name) {
			return bypassRuntimeConfig{}, fmt.Errorf("invalid session cookie name %q", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		cfg.sessionCookieSet[name] = struct{}{}
	}
	cfg.sessionCookieNames = make([]string, 0, len(seen))
	for name := range seen {
		cfg.sessionCookieNames = append(cfg.sessionCookieNames, name)
	}
	slices.Sort(cfg.sessionCookieNames)
	return cfg, nil
}

func (s *SoftwareBypass) mustRuntimeConfig() bypassRuntimeConfig {
	cfg, err := s.runtimeConfig()
	if err != nil {
		panic(err)
	}
	return cfg
}

// RuntimeAdmin exposes read-only runtime metrics on Caddy's admin listener.
type RuntimeAdmin struct {
	runtime *softwareRuntime
}

func (RuntimeAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.jiuzhang_runtime",
		New: func() caddy.Module { return new(RuntimeAdmin) },
	}
}

func (a *RuntimeAdmin) Provision(caddy.Context) error {
	if a.runtime == nil {
		a.runtime = globalSoftwareRuntime
	}
	a.runtime.start()
	return nil
}

func (a *RuntimeAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{Pattern: "/jiuzhang/runtime", Handler: caddy.AdminHandlerFunc(a.serveHTTP)},
		{Pattern: "/jiuzhang/runtime/history", Handler: caddy.AdminHandlerFunc(a.serveHistoryHTTP)},
	}
}

func (a *RuntimeAdmin) serveHTTP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	runtime := a.runtime
	if runtime == nil {
		runtime = globalSoftwareRuntime
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(runtime.snapshot(time.Now().UTC()))
}

func (a *RuntimeAdmin) serveHistoryHTTP(w http.ResponseWriter, r *http.Request) error {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil
	}
	runtime := a.runtime
	if runtime == nil {
		runtime = globalSoftwareRuntime
	}
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(runtime.historySnapshot())
}

// RuntimeSnapshot is the management-plane runtime metrics contract.
type RuntimeSnapshot struct {
	Node           string                       `json:"node"`
	TakenAt        time.Time                    `json:"taken_at"`
	Resources      ResourceSnapshot             `json:"resources"`
	Connections    ConnectionSnapshot           `json:"connections"`
	HTTP           HTTPSnapshot                 `json:"http"`
	SoftwareBypass SoftwareBypassSnapshot       `json:"software_bypass"`
	Applications   []ApplicationRuntimeSnapshot `json:"applications"`
}

type ResourceSnapshot struct {
	CPUPercent       *float64  `json:"cpu_percent"`
	MemoryPercent    *float64  `json:"memory_percent"`
	MemoryUsedBytes  *uint64   `json:"memory_used_bytes,omitempty"`
	MemoryTotalBytes *uint64   `json:"memory_total_bytes,omitempty"`
	Load1            *float64  `json:"load1,omitempty"`
	Load5            *float64  `json:"load5,omitempty"`
	Load15           *float64  `json:"load15,omitempty"`
	FDOpen           *int      `json:"fd_open,omitempty"`
	FDMax            *uint64   `json:"fd_max,omitempty"`
	FDUsagePercent   *float64  `json:"fd_usage_percent,omitempty"`
	SampledAt        time.Time `json:"sampled_at"`
	Error            string    `json:"error,omitempty"`
}

type TCPStateSnapshot struct {
	Established int `json:"established"`
	TimeWait    int `json:"time_wait"`
	CloseWait   int `json:"close_wait"`
	SynRecv     int `json:"syn_recv"`
	FinWait     int `json:"fin_wait"`
	Listen      int `json:"listen"`
	Other       int `json:"other"`
}

type ConnectionSnapshot struct {
	Active            int64             `json:"active"`
	AcceptedTotal     uint64            `json:"accepted_total"`
	AcceptedPerSecond float64           `json:"accepted_per_second"`
	BytesInTotal      uint64            `json:"bytes_in_total"`
	BytesOutTotal     uint64            `json:"bytes_out_total"`
	BytesInPerSecond  float64           `json:"bytes_in_per_second"`
	BytesOutPerSecond float64           `json:"bytes_out_per_second"`
	TCPStates         *TCPStateSnapshot `json:"tcp_states,omitempty"`
}

// HTTPSnapshot aggregates all registered handlers. Session active/new counts include
// only sessions admitted to the bounded tracker; overflow counts rejected new-session
// observations, so it deliberately is not a distinct-session estimate.
type HTTPSnapshot struct {
	RequestsInFlight      int64   `json:"requests_in_flight"`
	RequestsTotal         uint64  `json:"requests_total"`
	RequestsPerSecond     float64 `json:"requests_per_second"`
	SessionsActive        int     `json:"sessions_active"`
	SessionsNewTotal      uint64  `json:"sessions_new_total"`
	SessionsNewPerSecond  float64 `json:"sessions_new_per_second"`
	SessionsOverflowTotal uint64  `json:"sessions_overflow_total"`
	Status2xxTotal        uint64  `json:"status_2xx_total"`
	Status3xxTotal        uint64  `json:"status_3xx_total"`
	Status4xxTotal        uint64  `json:"status_4xx_total"`
	Status5xxTotal        uint64  `json:"status_5xx_total"`
	Status2xxPerSecond    float64 `json:"status_2xx_per_second"`
	Status3xxPerSecond    float64 `json:"status_3xx_per_second"`
	Status4xxPerSecond    float64 `json:"status_4xx_per_second"`
	Status5xxPerSecond    float64 `json:"status_5xx_per_second"`
}

type ApplicationRuntimeSnapshot struct {
	AppID                 string  `json:"app_id"`
	RequestsInFlight      int64   `json:"requests_in_flight"`
	RequestsTotal         uint64  `json:"requests_total"`
	RequestsPerSecond     float64 `json:"requests_per_second"`
	BypassedRequestsTotal uint64  `json:"bypassed_requests_total"`
	BytesInTotal          uint64  `json:"bytes_in_total"`
	BytesOutTotal         uint64  `json:"bytes_out_total"`
	BytesInPerSecond      float64 `json:"bytes_in_per_second"`
	BytesOutPerSecond     float64 `json:"bytes_out_per_second"`
	Status4xxTotal        uint64  `json:"status_4xx_total"`
	Status5xxTotal        uint64  `json:"status_5xx_total"`
}

type RuntimeHistory struct {
	Node            string                `json:"node"`
	IntervalSeconds int                   `json:"interval_seconds"`
	Points          []RuntimeHistoryPoint `json:"points"`
}

type RuntimeHistoryPoint struct {
	TakenAt                         time.Time `json:"taken_at"`
	CPUPercent                      *float64  `json:"cpu_percent"`
	MemoryPercent                   *float64  `json:"memory_percent"`
	Load1                           *float64  `json:"load1,omitempty"`
	FDUsagePercent                  *float64  `json:"fd_usage_percent,omitempty"`
	TCPConnectionsActive            int64     `json:"tcp_connections_active"`
	TCPConnectionsAcceptedPerSecond float64   `json:"tcp_connections_accepted_per_second"`
	BytesInPerSecond                float64   `json:"bytes_in_per_second"`
	BytesOutPerSecond               float64   `json:"bytes_out_per_second"`
	HTTPRequestsInFlight            int64     `json:"http_requests_in_flight"`
	HTTPRequestsPerSecond           float64   `json:"http_requests_per_second"`
	HTTPSessionsActive              int       `json:"http_sessions_active"`
	HTTPSessionsNewPerSecond        float64   `json:"http_sessions_new_per_second"`
	Status2xxPerSecond              float64   `json:"status_2xx_per_second"`
	Status3xxPerSecond              float64   `json:"status_3xx_per_second"`
	Status4xxPerSecond              float64   `json:"status_4xx_per_second"`
	Status5xxPerSecond              float64   `json:"status_5xx_per_second"`
	SoftwareBypassActive            bool      `json:"software_bypass_active"`
}

// SoftwareBypassSnapshot aggregates independent route policies. Enabled/Active mean
// any registered policy is enabled/active; enabled thresholds and minimum hold use
// their minimum values, counters are summed, and Reason comes from the first active
// registration. The normal node-wide configuration has one policy and is unchanged.
type SoftwareBypassSnapshot struct {
	Enabled                bool       `json:"enabled"`
	Active                 bool       `json:"active"`
	Reason                 string     `json:"reason,omitempty"`
	CPUThresholdPercent    int        `json:"cpu_threshold_percent"`
	MemoryThresholdPercent int        `json:"memory_threshold_percent"`
	RecoveryCPUPercent     int        `json:"recovery_cpu_percent"`
	RecoveryMemoryPercent  int        `json:"recovery_memory_percent"`
	MinHoldSeconds         int        `json:"min_hold_seconds"`
	ActivatedAt            *time.Time `json:"activated_at,omitempty"`
	TransitionsTotal       uint64     `json:"transitions_total"`
	BypassedRequestsTotal  uint64     `json:"bypassed_requests_total"`
}

var (
	_ caddy.Provisioner           = (*SoftwareBypass)(nil)
	_ caddy.Validator             = (*SoftwareBypass)(nil)
	_ caddyhttp.MiddlewareHandler = (*SoftwareBypass)(nil)
	_ caddy.CleanerUpper          = (*SoftwareBypass)(nil)
	_ caddy.Provisioner           = (*RuntimeAdmin)(nil)
	_ caddy.AdminRouter           = (*RuntimeAdmin)(nil)
	_ http.ResponseWriter         = (*statusCountingResponseWriter)(nil)
	_ http.Flusher                = (*statusCountingResponseWriter)(nil)
	_ http.Hijacker               = (*statusCountingResponseWriter)(nil)
)
