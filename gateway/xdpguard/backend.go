package xdpguard

import (
	"context"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultSocketPath is the default controlled Unix Domain Socket for xdpguard.
	DefaultSocketPath = "/var/run/caddy/sidecars/xdpguard.sock"

	// SyncSchemaVersion is the only supported schema_version for POST /v1/sync.
	SyncSchemaVersion = 1

	// MaxSyncBodyBytes caps POST /v1/sync request bodies at 2 MiB.
	MaxSyncBodyBytes = 2 << 20

	// StatusOK indicates healthy operation (either kernel XDP attached on all NICs or cleanly disabled).
	StatusOK = "ok"
	// StatusDegraded indicates fail-open fallback to userspace or partial NIC attach.
	StatusDegraded = "degraded"
)

// ValidationError represents a client-supplied contract or safety validation failure (HTTP 400).
type ValidationError struct {
	Msg string
}

func (e *ValidationError) Error() string {
	return e.Msg
}

// SyncRequest is the frozen JSON payload accepted by POST /v1/sync.
type SyncRequest struct {
	SchemaVersion  int      `json:"schema_version"`
	Enabled        bool     `json:"enabled"`
	AttachMode     string   `json:"attach_mode"`
	Interfaces     []string `json:"interfaces"`
	BlockedCIDRs   []string `json:"blocked_cidrs"`
	ProtectedCIDRs []string `json:"protected_cidrs"`
}

// SyncResponse is the frozen JSON payload returned by POST /v1/sync.
type SyncResponse struct {
	Synced                 bool     `json:"synced"`
	Mode                   string   `json:"mode"`
	KernelAttached         bool     `json:"kernel_attached"`
	AttachedInterfaces     []string `json:"attached_interfaces"`
	SyncedV4CIDRs          int      `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int      `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int      `json:"excluded_protected_count"`
	InvalidCIDRsSkipped    int      `json:"invalid_cidrs_skipped"`
	LastSyncAt             string   `json:"last_sync_at"`
	Error                  string   `json:"error"`
}

// HealthzResponse is the frozen JSON payload returned by GET /healthz.
type HealthzResponse struct {
	Status                 string   `json:"status"`
	Mode                   string   `json:"mode"`
	KernelAttached         bool     `json:"kernel_attached"`
	AttachedInterfaces     []string `json:"attached_interfaces"`
	DroppedV4Packets       uint64   `json:"dropped_v4_packets"`
	DroppedV6Packets       uint64   `json:"dropped_v6_packets"`
	SyncedV4CIDRs          int      `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int      `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int      `json:"excluded_protected_count"`
	LastSyncAt             string   `json:"last_sync_at"`
	Error                  string   `json:"error"`
}

// InterfaceStatus reports per-interface XDP attachment status in GET /v1/stats.
type InterfaceStatus struct {
	Name     string `json:"name"`
	Attached bool   `json:"attached"`
	Mode     string `json:"mode"`
	Error    string `json:"error"`
}

// StatsResponse is the frozen JSON payload returned by GET /v1/stats.
type StatsResponse struct {
	Status                 string            `json:"status"`
	Mode                   string            `json:"mode"`
	KernelAttached         bool              `json:"kernel_attached"`
	AttachModeRequested    string            `json:"attach_mode_requested"`
	Interfaces             []InterfaceStatus `json:"interfaces"`
	DroppedV4Packets       uint64            `json:"dropped_v4_packets"`
	DroppedV6Packets       uint64            `json:"dropped_v6_packets"`
	PassedPackets          uint64            `json:"passed_packets"`
	SyncedV4CIDRs          int               `json:"synced_v4_cidrs"`
	SyncedV6CIDRs          int               `json:"synced_v6_cidrs"`
	ExcludedProtectedCount int               `json:"excluded_protected_count"`
	LastSyncAt             string            `json:"last_sync_at"`
	Error                  string            `json:"error"`
}

// BackendOptions configures the platform XDP backend.
type BackendOptions struct {
	BPFObjPath         string
	DefaultInterfaces  []string
	ExcludedInterfaces []string
	DefaultAttachMode  string
	HostAddrsProvider  HostAddrsProvider
	Now                func() time.Time
}

// Backend abstracts kernel XDP management (Linux) and honest userspace fallback (non-Linux / tests).
type Backend interface {
	Sync(ctx context.Context, req SyncRequest) (SyncResponse, error)
	Stats(ctx context.Context) StatsResponse
	Healthz(ctx context.Context) HealthzResponse
	Close() error
}

// ValidateSyncRequest enforces schema, attach_mode, and interface safety constraints.
func ValidateSyncRequest(req SyncRequest, defaultIfaces []string, excluded map[string]struct{}) ([]string, string, error) {
	if req.SchemaVersion != SyncSchemaVersion {
		return nil, "", &ValidationError{
			Msg: fmt.Sprintf("unsupported schema_version %d: expected %d", req.SchemaVersion, SyncSchemaVersion),
		}
	}

	attachMode := strings.TrimSpace(req.AttachMode)
	if attachMode == "" {
		return nil, "", &ValidationError{Msg: "attach_mode is required (auto, native, generic)"}
	}
	if err := ValidateAttachMode(attachMode); err != nil {
		return nil, "", &ValidationError{Msg: err.Error()}
	}

	ifaces, err := ValidateInterfaces(req.Interfaces, excluded)
	if err != nil {
		return nil, "", &ValidationError{Msg: err.Error()}
	}

	if req.Enabled {
		if len(ifaces) == 0 && len(defaultIfaces) > 0 {
			ifaces, err = ValidateInterfaces(defaultIfaces, excluded)
			if err != nil {
				return nil, "", &ValidationError{Msg: err.Error()}
			}
		}
		if len(ifaces) == 0 {
			return nil, "", &ValidationError{Msg: "enabled=true requires at least one valid physical interface"}
		}
	}

	return ifaces, attachMode, nil
}

func normalizeBackendOptions(opts BackendOptions) (BackendOptions, map[string]struct{}, error) {
	if opts.DefaultAttachMode == "" {
		opts.DefaultAttachMode = AttachModeAuto
	}
	if err := ValidateAttachMode(opts.DefaultAttachMode); err != nil {
		return BackendOptions{}, nil, err
	}
	excluded := ParseExcludedInterfaces(opts.ExcludedInterfaces)
	if len(opts.DefaultInterfaces) > 0 {
		validIfaces, err := ValidateInterfaces(opts.DefaultInterfaces, excluded)
		if err != nil {
			return BackendOptions{}, nil, fmt.Errorf("default interfaces: %w", err)
		}
		opts.DefaultInterfaces = validIfaces
	} else {
		opts.DefaultInterfaces = []string{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts, excluded, nil
}

func nonNilStrings(in []string) []string {
	if len(in) == 0 {
		return []string{}
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func nonNilInterfaces(in []InterfaceStatus) []InterfaceStatus {
	if len(in) == 0 {
		return []InterfaceStatus{}
	}
	out := make([]InterfaceStatus, len(in))
	copy(out, in)
	return out
}
