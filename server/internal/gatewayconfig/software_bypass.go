package gatewayconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const SoftwareBypassSettingsGroup = "software_bypass"

var softwareBypassCookieNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// GuardSoftwareBypass is the node-wide automatic pure-proxy policy.
type GuardSoftwareBypass struct {
	Enabled                bool     `json:"enabled"`
	CPUThresholdPercent    int      `json:"cpu_threshold_percent"`
	MemoryThresholdPercent int      `json:"memory_threshold_percent"`
	MinHoldSeconds         int      `json:"min_hold_seconds"`
	SessionCookieNames     []string `json:"session_cookie_names"`
}

func defaultSoftwareBypass() *GuardSoftwareBypass {
	return &GuardSoftwareBypass{
		CPUThresholdPercent:    80,
		MemoryThresholdPercent: 80,
		MinHoldSeconds:         10,
		SessionCookieNames:     []string{"JSESSIONID", "PHPSESSID", "SESSION", "SESSIONID", "connect.sid"},
	}
}

func softwareBypassFromSettings(values map[string]json.RawMessage) (*GuardSoftwareBypass, error) {
	cfg := defaultSoftwareBypass()
	for key, raw := range values {
		switch key {
		case "enabled":
			if err := json.Unmarshal(raw, &cfg.Enabled); err != nil {
				return nil, fmt.Errorf("software_bypass.enabled must be boolean: %w", err)
			}
		case "cpu_threshold_percent":
			if err := json.Unmarshal(raw, &cfg.CPUThresholdPercent); err != nil {
				return nil, fmt.Errorf("software_bypass.cpu_threshold_percent must be integer: %w", err)
			}
		case "memory_threshold_percent":
			if err := json.Unmarshal(raw, &cfg.MemoryThresholdPercent); err != nil {
				return nil, fmt.Errorf("software_bypass.memory_threshold_percent must be integer: %w", err)
			}
		case "min_hold_seconds":
			if err := json.Unmarshal(raw, &cfg.MinHoldSeconds); err != nil {
				return nil, fmt.Errorf("software_bypass.min_hold_seconds must be integer: %w", err)
			}
		case "session_cookie_names":
			var rawNames string
			if err := json.Unmarshal(raw, &rawNames); err != nil {
				return nil, fmt.Errorf("software_bypass.session_cookie_names must be string: %w", err)
			}
			names, err := parseSoftwareBypassCookieNames(rawNames)
			if err != nil {
				return nil, err
			}
			cfg.SessionCookieNames = names
		}
	}
	if cfg.CPUThresholdPercent < 1 || cfg.CPUThresholdPercent > 100 || cfg.MemoryThresholdPercent < 1 || cfg.MemoryThresholdPercent > 100 {
		return nil, fmt.Errorf("software_bypass CPU and memory thresholds must be in range [1,100]")
	}
	if cfg.MinHoldSeconds < 1 || cfg.MinHoldSeconds > 300 {
		return nil, fmt.Errorf("software_bypass.min_hold_seconds must be in range [1,300]")
	}
	return cfg, nil
}

func parseSoftwareBypassCookieNames(raw string) ([]string, error) {
	seen := map[string]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		name := strings.TrimSpace(item)
		if name == "" {
			continue
		}
		if len(name) > 64 || !softwareBypassCookieNamePattern.MatchString(name) {
			return nil, fmt.Errorf("software_bypass.session_cookie_names contains invalid cookie name %q", name)
		}
		seen[name] = struct{}{}
	}
	if len(seen) > 16 {
		return nil, fmt.Errorf("software_bypass.session_cookie_names supports at most 16 names")
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

// LoadSoftwareBypass reads the persisted node policy. Missing rows use safe defaults.
func LoadSoftwareBypass(ctx context.Context, db *pgxpool.Pool) (*GuardSoftwareBypass, error) {
	rows, err := db.Query(ctx, `
SELECT setting_key, setting_value FROM system_settings WHERE setting_group = $1`, SoftwareBypassSettingsGroup)
	if err != nil {
		return nil, fmt.Errorf("read software_bypass settings: %w", err)
	}
	defer rows.Close()
	values := map[string]json.RawMessage{}
	for rows.Next() {
		var key string
		var raw json.RawMessage
		if err := rows.Scan(&key, &raw); err != nil {
			return nil, fmt.Errorf("scan software_bypass setting: %w", err)
		}
		values[key] = raw
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read software_bypass settings: %w", err)
	}
	return softwareBypassFromSettings(values)
}

// GatewayTCPStates mirrors /proc/net/tcp(6) state counts reported by the gateway.
type GatewayTCPStates struct {
	Established int `json:"established"`
	TimeWait    int `json:"time_wait"`
	CloseWait   int `json:"close_wait"`
	SynRecv     int `json:"syn_recv"`
	FinWait     int `json:"fin_wait"`
	Listen      int `json:"listen"`
	Other       int `json:"other"`
}

// GatewayRuntimeApplication mirrors per-application live load stats reported by the gateway.
type GatewayRuntimeApplication struct {
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

// GatewayRuntimeSnapshot mirrors the read-only gateway admin runtime contract.
type GatewayRuntimeSnapshot struct {
	Node      string    `json:"node"`
	TakenAt   time.Time `json:"taken_at"`
	Resources struct {
		CPUPercent       *float64  `json:"cpu_percent"`
		MemoryPercent    *float64  `json:"memory_percent"`
		MemoryUsedBytes  *uint64   `json:"memory_used_bytes"`
		MemoryTotalBytes *uint64   `json:"memory_total_bytes"`
		Load1            *float64  `json:"load1"`
		Load5            *float64  `json:"load5"`
		Load15           *float64  `json:"load15"`
		FDOpen           *int      `json:"fd_open"`
		FDMax            *uint64   `json:"fd_max"`
		FDUsagePercent   *float64  `json:"fd_usage_percent"`
		SampledAt        time.Time `json:"sampled_at"`
		Error            string    `json:"error"`
	} `json:"resources"`
	Connections struct {
		Active            int64             `json:"active"`
		AcceptedTotal     uint64            `json:"accepted_total"`
		AcceptedPerSecond float64           `json:"accepted_per_second"`
		BytesInTotal      uint64            `json:"bytes_in_total"`
		BytesOutTotal     uint64            `json:"bytes_out_total"`
		BytesInPerSecond  float64           `json:"bytes_in_per_second"`
		BytesOutPerSecond float64           `json:"bytes_out_per_second"`
		TCPStates         *GatewayTCPStates `json:"tcp_states"`
	} `json:"connections"`
	HTTP struct {
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
	} `json:"http"`
	SoftwareBypass struct {
		Enabled                bool       `json:"enabled"`
		Active                 bool       `json:"active"`
		Reason                 string     `json:"reason"`
		CPUThresholdPercent    int        `json:"cpu_threshold_percent"`
		MemoryThresholdPercent int        `json:"memory_threshold_percent"`
		RecoveryCPUPercent     int        `json:"recovery_cpu_percent"`
		RecoveryMemoryPercent  int        `json:"recovery_memory_percent"`
		MinHoldSeconds         int        `json:"min_hold_seconds"`
		ActivatedAt            *time.Time `json:"activated_at"`
		TransitionsTotal       uint64     `json:"transitions_total"`
		BypassedRequestsTotal  uint64     `json:"bypassed_requests_total"`
	} `json:"software_bypass"`
	Applications []GatewayRuntimeApplication `json:"applications"`
}

// GatewayRuntimeHistoryPoint mirrors a single high-resolution sample from GET /jiuzhang/runtime/history.
type GatewayRuntimeHistoryPoint struct {
	TakenAt                         time.Time `json:"taken_at"`
	CPUPercent                      *float64  `json:"cpu_percent"`
	MemoryPercent                   *float64  `json:"memory_percent"`
	Load1                           *float64  `json:"load1"`
	FDUsagePercent                  *float64  `json:"fd_usage_percent"`
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

// GatewayRuntimeHistory mirrors GET /jiuzhang/runtime/history response.
type GatewayRuntimeHistory struct {
	Node            string                       `json:"node"`
	IntervalSeconds int                          `json:"interval_seconds"`
	Points          []GatewayRuntimeHistoryPoint `json:"points"`
}
