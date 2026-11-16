package jiuzhang_guard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
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

func (s *SoftwareBypass) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	runtime := s.runtime
	if runtime == nil {
		runtime = globalSoftwareRuntime
	}
	state := s.state
	if state == nil {
		// Direct handler users outside Caddy still get a functional, isolated
		// decision state; Provision registers the state for process-level metrics.
		cfg, err := s.runtimeConfig()
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		state = newSoftwareBypassState(s.AppID, runtimeNode(s.Node), cfg)
	}
	state.requestsTotal.Add(1)
	state.requestsInFlight.Add(1)
	defer state.requestsInFlight.Add(-1)
	if state.config.enabled {
		runtime.sessions.observe(r, s.AppID, state.config.sessionCookieSet, time.Now().UTC())
	}
	if state.active.Load() {
		state.bypassedRequestsTotal.Add(1)
		if s.bypassHandler != nil {
			return s.bypassHandler.ServeHTTP(w, r)
		}
		return s.Bypass.ServeHTTP(w, r, next)
	}
	if s.normalHandler != nil {
		return s.normalHandler.ServeHTTP(w, r)
	}
	return s.Normal.ServeHTTP(w, r, next)
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
	return []caddy.AdminRoute{{Pattern: "/jiuzhang/runtime", Handler: caddy.AdminHandlerFunc(a.serveHTTP)}}
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

// RuntimeSnapshot is the management-plane runtime metrics contract.
type RuntimeSnapshot struct {
	Node           string                 `json:"node"`
	TakenAt        time.Time              `json:"taken_at"`
	Resources      ResourceSnapshot       `json:"resources"`
	Connections    ConnectionSnapshot     `json:"connections"`
	HTTP           HTTPSnapshot           `json:"http"`
	SoftwareBypass SoftwareBypassSnapshot `json:"software_bypass"`
}

type ResourceSnapshot struct {
	CPUPercent    *float64  `json:"cpu_percent"`
	MemoryPercent *float64  `json:"memory_percent"`
	SampledAt     time.Time `json:"sampled_at"`
	Error         string    `json:"error,omitempty"`
}

type ConnectionSnapshot struct {
	Active            int64   `json:"active"`
	AcceptedTotal     uint64  `json:"accepted_total"`
	AcceptedPerSecond float64 `json:"accepted_per_second"`
}

// HTTPSnapshot aggregates all registered handlers. Session active/new counts include
// only sessions admitted to the bounded tracker; overflow counts rejected new-session
// observations, so it deliberately is not a distinct-session estimate.
type HTTPSnapshot struct {
	RequestsInFlight      int64  `json:"requests_in_flight"`
	RequestsTotal         uint64 `json:"requests_total"`
	SessionsActive        int    `json:"sessions_active"`
	SessionsNewTotal      uint64 `json:"sessions_new_total"`
	SessionsOverflowTotal uint64 `json:"sessions_overflow_total"`
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
)
