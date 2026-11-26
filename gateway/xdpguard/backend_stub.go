//go:build !linux

package xdpguard

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// StubBackend is the non-Linux backend. It runs the full safety filter and validation
// pipeline while honestly reporting fallback_userspace (kernel_attached=false).
type StubBackend struct {
	opts     BackendOptions
	excluded map[string]struct{}

	mu                sync.Mutex
	status            string
	mode              string
	attachModeReq     string
	interfaces        []InterfaceStatus
	excludedProtected int
	invalidSkipped    int
	lastSyncAt        string
	lastErr           string
}

// NewBackend creates the non-Linux honest fallback backend.
func NewBackend(opts BackendOptions) (Backend, error) {
	norm, excluded, err := normalizeBackendOptions(opts)
	if err != nil {
		return nil, err
	}
	return &StubBackend{
		opts:          norm,
		excluded:      excluded,
		status:        StatusOK,
		mode:          ModeFallbackUserspace,
		attachModeReq: norm.DefaultAttachMode,
		interfaces:    []InterfaceStatus{},
	}, nil
}

// Sync validates input, enforces double-guard protected exclusion, and honestly
// reports userspace fallback when XDP kernel attachment is requested on non-Linux.
func (b *StubBackend) Sync(_ context.Context, req SyncRequest) (SyncResponse, error) {
	ifaces, attachMode, err := ValidateSyncRequest(req, b.opts.DefaultInterfaces, b.excluded)
	if err != nil {
		return SyncResponse{}, err
	}

	filtered, err := FilterBlocklist(req.BlockedCIDRs, req.ProtectedCIDRs, b.opts.HostAddrsProvider)
	if err != nil {
		var valErr *ValidationError
		if errors.As(err, &valErr) {
			return SyncResponse{}, valErr
		}
		now := b.opts.Now().UTC().Format(time.RFC3339)
		b.mu.Lock()
		defer b.mu.Unlock()
		b.lastSyncAt = now
		b.attachModeReq = attachMode
		b.status = StatusDegraded
		b.mode = ModeFallbackUserspace
		b.lastErr = err.Error()
		b.interfaces = []InterfaceStatus{}
		return SyncResponse{
			Synced:             false,
			Mode:               ModeFallbackUserspace,
			KernelAttached:     false,
			AttachedInterfaces: []string{},
			LastSyncAt:         now,
			Error:              err.Error(),
		}, nil
	}

	now := b.opts.Now().UTC().Format(time.RFC3339)

	b.mu.Lock()
	defer b.mu.Unlock()

	b.attachModeReq = attachMode
	b.excludedProtected = filtered.ExcludedProtectedCount
	b.invalidSkipped = filtered.InvalidCIDRsSkipped
	b.lastSyncAt = now
	b.mode = ModeFallbackUserspace

	if !req.Enabled {
		b.status = StatusOK
		b.lastErr = ""
		b.interfaces = []InterfaceStatus{}
		return SyncResponse{
			Synced:                 true,
			Mode:                   ModeFallbackUserspace,
			KernelAttached:         false,
			AttachedInterfaces:     []string{},
			SyncedV4CIDRs:          0,
			SyncedV6CIDRs:          0,
			ExcludedProtectedCount: filtered.ExcludedProtectedCount,
			InvalidCIDRsSkipped:    filtered.InvalidCIDRsSkipped,
			LastSyncAt:             now,
			Error:                  "",
		}, nil
	}

	reason := fmt.Sprintf("eBPF/XDP kernel attach unavailable on %s/%s: fallback to userspace", runtime.GOOS, runtime.GOARCH)
	b.status = StatusDegraded
	b.lastErr = reason
	b.interfaces = make([]InterfaceStatus, 0, len(ifaces))
	for _, name := range ifaces {
		b.interfaces = append(b.interfaces, InterfaceStatus{
			Name:     name,
			Attached: false,
			Mode:     ModeFallbackUserspace,
			Error:    reason,
		})
	}

	return SyncResponse{
		Synced:                 false,
		Mode:                   ModeFallbackUserspace,
		KernelAttached:         false,
		AttachedInterfaces:     []string{},
		SyncedV4CIDRs:          0,
		SyncedV6CIDRs:          0,
		ExcludedProtectedCount: filtered.ExcludedProtectedCount,
		InvalidCIDRsSkipped:    filtered.InvalidCIDRsSkipped,
		LastSyncAt:             now,
		Error:                  reason,
	}, nil
}

// Stats returns the current honest userspace fallback telemetry.
func (b *StubBackend) Stats(_ context.Context) StatsResponse {
	b.mu.Lock()
	defer b.mu.Unlock()

	return StatsResponse{
		Status:                 b.status,
		Mode:                   b.mode,
		KernelAttached:         false,
		AttachModeRequested:    b.attachModeReq,
		Interfaces:             nonNilInterfaces(b.interfaces),
		DroppedV4Packets:       0,
		DroppedV6Packets:       0,
		PassedPackets:          0,
		SyncedV4CIDRs:          0,
		SyncedV6CIDRs:          0,
		ExcludedProtectedCount: b.excludedProtected,
		LastSyncAt:             b.lastSyncAt,
		Error:                  b.lastErr,
	}
}

// Healthz returns the current health summary.
func (b *StubBackend) Healthz(_ context.Context) HealthzResponse {
	b.mu.Lock()
	defer b.mu.Unlock()

	return HealthzResponse{
		Status:                 b.status,
		Mode:                   b.mode,
		KernelAttached:         false,
		AttachedInterfaces:     []string{},
		DroppedV4Packets:       0,
		DroppedV6Packets:       0,
		SyncedV4CIDRs:          0,
		SyncedV6CIDRs:          0,
		ExcludedProtectedCount: b.excludedProtected,
		LastSyncAt:             b.lastSyncAt,
		Error:                  b.lastErr,
	}
}

// Close resets stub state cleanly (idempotent).
func (b *StubBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.status = StatusOK
	b.mode = ModeFallbackUserspace
	b.interfaces = []InterfaceStatus{}
	b.lastErr = ""
	return nil
}
