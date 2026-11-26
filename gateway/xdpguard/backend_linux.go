//go:build linux

package xdpguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type attachedLink struct {
	link    link.Link
	mode    string
	ifIndex int
}

// LinuxBackend manages the kernel eBPF/XDP program, LPM Trie maps, per-CPU stats,
// and fail-open XDP interface links on Linux hosts.
type LinuxBackend struct {
	opts     BackendOptions
	excluded map[string]struct{}

	mu                sync.Mutex
	coll              *ebpf.Collection
	prog              *ebpf.Program
	mapV4             *ebpf.Map
	mapV6             *ebpf.Map
	mapStats          *ebpf.Map
	links             map[string]*attachedLink
	currentV4         map[LPMKeyV4]struct{}
	currentV6         map[LPMKeyV6]struct{}
	status            string
	mode              string
	attachModeReq     string
	interfaces        []InterfaceStatus
	excludedProtected int
	invalidSkipped    int
	lastSyncAt        string
	lastErr           string
}

// NewBackend creates the Linux kernel eBPF/XDP backend. It starts cleanly detached
// in userspace fallback mode until Sync(enabled=true) attaches XDP links.
func NewBackend(opts BackendOptions) (Backend, error) {
	norm, excluded, err := normalizeBackendOptions(opts)
	if err != nil {
		return nil, err
	}
	return &LinuxBackend{
		opts:          norm,
		excluded:      excluded,
		links:         make(map[string]*attachedLink),
		currentV4:     make(map[LPMKeyV4]struct{}),
		currentV6:     make(map[LPMKeyV6]struct{}),
		status:        StatusOK,
		mode:          ModeFallbackUserspace,
		attachModeReq: norm.DefaultAttachMode,
		interfaces:    []InterfaceStatus{},
	}, nil
}

// Sync validates input, enforces the double-guard protected-address exclusion filter,
// atomically diff-syncs blocked_v4/blocked_v6 LPM Trie maps, and reconciles XDP links.
// Any eBPF load or attach failure transitions cleanly to fail-open fallback_userspace.
func (b *LinuxBackend) Sync(_ context.Context, req SyncRequest) (SyncResponse, error) {
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
		// Host address discovery failure: fail-open by detaching active XDP links.
		b.mu.Lock()
		defer b.mu.Unlock()
		now := b.opts.Now().UTC().Format(time.RFC3339)
		b.lastSyncAt = now
		b.attachModeReq = attachMode
		b.fallbackLocked(ifaces, err.Error())
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

	b.lastSyncAt = now
	b.attachModeReq = attachMode
	b.excludedProtected = filtered.ExcludedProtectedCount
	b.invalidSkipped = filtered.InvalidCIDRsSkipped

	if !req.Enabled {
		b.detachAndCloseLocked()
		b.status = StatusOK
		b.mode = ModeFallbackUserspace
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

	if err := b.ensureLoadedLocked(); err != nil {
		b.fallbackLocked(ifaces, err.Error())
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
			Error:                  err.Error(),
		}, nil
	}

	// Sync LPM Trie maps before attaching links (add new entries before deleting stale ones).
	var warnings []string
	v4List := filtered.BlockedV4
	if len(v4List) > MaxBlockedV4Entries {
		warnings = append(warnings, fmt.Sprintf("IPv4 blocklist truncated from %d to %d max entries", len(v4List), MaxBlockedV4Entries))
		v4List = v4List[:MaxBlockedV4Entries]
	}
	v6List := filtered.BlockedV6
	if len(v6List) > MaxBlockedV6Entries {
		warnings = append(warnings, fmt.Sprintf("IPv6 blocklist truncated from %d to %d max entries", len(v6List), MaxBlockedV6Entries))
		v6List = v6List[:MaxBlockedV6Entries]
	}

	if err := b.syncMapV4Locked(v4List); err != nil {
		b.fallbackLocked(ifaces, fmt.Sprintf("sync blocked_v4 map failed: %v", err))
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
			Error:                  b.lastErr,
		}, nil
	}
	if err := b.syncMapV6Locked(v6List); err != nil {
		b.fallbackLocked(ifaces, fmt.Sprintf("sync blocked_v6 map failed: %v", err))
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
			Error:                  b.lastErr,
		}, nil
	}

	// Detach interfaces no longer requested.
	desired := make(map[string]struct{}, len(ifaces))
	for _, name := range ifaces {
		desired[name] = struct{}{}
	}
	for name, existing := range b.links {
		if _, keep := desired[name]; !keep {
			_ = existing.link.Close()
			delete(b.links, name)
		}
	}

	ifaceStatuses := make([]InterfaceStatus, 0, len(ifaces))
	attachedNames := make([]string, 0, len(ifaces))
	var attachErrors []string
	allNative := true

	for _, name := range ifaces {
		iface, lookupErr := net.InterfaceByName(name)
		if lookupErr != nil {
			if existing, ok := b.links[name]; ok {
				_ = existing.link.Close()
				delete(b.links, name)
			}
			msg := fmt.Sprintf("interface %s lookup failed: %v", name, lookupErr)
			attachErrors = append(attachErrors, msg)
			ifaceStatuses = append(ifaceStatuses, InterfaceStatus{
				Name:     name,
				Attached: false,
				Mode:     ModeFallbackUserspace,
				Error:    msg,
			})
			continue
		}

		if existing, ok := b.links[name]; ok && existing.ifIndex == iface.Index && modeCompatible(existing.mode, attachMode) {
			attachedNames = append(attachedNames, name)
			if existing.mode != ModeXDPNative {
				allNative = false
			}
			ifaceStatuses = append(ifaceStatuses, InterfaceStatus{
				Name:     name,
				Attached: true,
				Mode:     existing.mode,
				Error:    "",
			})
			continue
		}

		if existing, ok := b.links[name]; ok {
			_ = existing.link.Close()
			delete(b.links, name)
		}

		lnk, actualMode, attachErr := attachInterfaceXDP(b.prog, iface.Index, attachMode)
		if attachErr != nil {
			msg := fmt.Sprintf("interface %s attach failed: %v", name, attachErr)
			attachErrors = append(attachErrors, msg)
			ifaceStatuses = append(ifaceStatuses, InterfaceStatus{
				Name:     name,
				Attached: false,
				Mode:     ModeFallbackUserspace,
				Error:    msg,
			})
			continue
		}

		b.links[name] = &attachedLink{
			link:    lnk,
			mode:    actualMode,
			ifIndex: iface.Index,
		}
		attachedNames = append(attachedNames, name)
		if actualMode != ModeXDPNative {
			allNative = false
		}
		ifaceStatuses = append(ifaceStatuses, InterfaceStatus{
			Name:     name,
			Attached: true,
			Mode:     actualMode,
			Error:    "",
		})
	}

	if len(attachedNames) == 0 {
		// Fail-open guarantee: no interface attached -> close collection cleanly and report fallback.
		errMsg := strings.Join(attachErrors, "; ")
		if errMsg == "" {
			errMsg = "no interfaces attached"
		}
		b.detachAndCloseLocked()
		b.status = StatusDegraded
		b.mode = ModeFallbackUserspace
		b.lastErr = errMsg
		b.interfaces = ifaceStatuses
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
			Error:                  errMsg,
		}, nil
	}

	aggMode := ModeXDPGeneric
	if allNative {
		aggMode = ModeXDPNative
	}
	allIssues := append(warnings, attachErrors...)
	errMsg := strings.Join(allIssues, "; ")
	status := StatusOK
	if errMsg != "" {
		status = StatusDegraded
	}

	b.status = status
	b.mode = aggMode
	b.lastErr = errMsg
	b.interfaces = ifaceStatuses

	return SyncResponse{
		Synced:                 true,
		Mode:                   aggMode,
		KernelAttached:         true,
		AttachedInterfaces:     nonNilStrings(attachedNames),
		SyncedV4CIDRs:          len(b.currentV4),
		SyncedV6CIDRs:          len(b.currentV6),
		ExcludedProtectedCount: filtered.ExcludedProtectedCount,
		InvalidCIDRsSkipped:    filtered.InvalidCIDRsSkipped,
		LastSyncAt:             now,
		Error:                  errMsg,
	}, nil
}

// Stats returns live per-CPU kernel drop/pass counters and per-interface attachment status.
func (b *LinuxBackend) Stats(_ context.Context) StatsResponse {
	b.mu.Lock()
	defer b.mu.Unlock()

	droppedV4, droppedV6, passed := b.readDropStatsLocked()
	kernelAttached := len(b.links) > 0

	return StatsResponse{
		Status:                 b.status,
		Mode:                   b.mode,
		KernelAttached:         kernelAttached,
		AttachModeRequested:    b.attachModeReq,
		Interfaces:             nonNilInterfaces(b.interfaces),
		DroppedV4Packets:       droppedV4,
		DroppedV6Packets:       droppedV6,
		PassedPackets:          passed,
		SyncedV4CIDRs:          len(b.currentV4),
		SyncedV6CIDRs:          len(b.currentV6),
		ExcludedProtectedCount: b.excludedProtected,
		LastSyncAt:             b.lastSyncAt,
		Error:                  b.lastErr,
	}
}

// Healthz returns the compact health and telemetry summary.
func (b *LinuxBackend) Healthz(_ context.Context) HealthzResponse {
	b.mu.Lock()
	defer b.mu.Unlock()

	droppedV4, droppedV6, _ := b.readDropStatsLocked()
	attached := b.attachedInterfaceNamesLocked()

	return HealthzResponse{
		Status:                 b.status,
		Mode:                   b.mode,
		KernelAttached:         len(attached) > 0,
		AttachedInterfaces:     attached,
		DroppedV4Packets:       droppedV4,
		DroppedV6Packets:       droppedV6,
		SyncedV4CIDRs:          len(b.currentV4),
		SyncedV6CIDRs:          len(b.currentV6),
		ExcludedProtectedCount: b.excludedProtected,
		LastSyncAt:             b.lastSyncAt,
		Error:                  b.lastErr,
	}
}

// Close detaches ALL XDP links, clears maps, and closes the eBPF collection (idempotent, fail-open).
func (b *LinuxBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.detachAndCloseLocked()
	b.status = StatusOK
	b.mode = ModeFallbackUserspace
	b.lastErr = ""
	b.interfaces = []InterfaceStatus{}
	return nil
}

func (b *LinuxBackend) ensureLoadedLocked() error {
	if b.coll != nil && b.prog != nil && b.mapV4 != nil && b.mapV6 != nil && b.mapStats != nil {
		return nil
	}
	// Best-effort memlock removal for kernels < 5.11; ignore failure so ebpf.NewCollection
	// reports the true kernel permission/verifier error if unprivileged.
	_ = rlimit.RemoveMemlock()

	spec, err := LoadCollectionSpec(b.opts.BPFObjPath)
	if err != nil {
		return err
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load eBPF XDP collection failed (requires CAP_BPF + CAP_NET_ADMIN and Linux eBPF support): %w", err)
	}

	prog := coll.Programs[ProgramName]
	mapV4 := coll.Maps[MapBlockedV4]
	mapV6 := coll.Maps[MapBlockedV6]
	mapStats := coll.Maps[MapDropStats]
	if prog == nil || mapV4 == nil || mapV6 == nil || mapStats == nil {
		coll.Close()
		return errors.New("loaded eBPF collection missing required program or maps")
	}

	b.coll = coll
	b.prog = prog
	b.mapV4 = mapV4
	b.mapV6 = mapV6
	b.mapStats = mapStats
	b.currentV4 = make(map[LPMKeyV4]struct{})
	b.currentV6 = make(map[LPMKeyV6]struct{})
	return nil
}

func (b *LinuxBackend) syncMapV4Locked(prefixes []netip.Prefix) error {
	desired := make(map[LPMKeyV4]struct{}, len(prefixes))
	for _, p := range prefixes {
		k, err := EncodeLPMKeyV4(p)
		if err != nil {
			return err
		}
		desired[k] = struct{}{}
	}
	// Add new entries FIRST so live XDP lookups never experience a gap.
	for k := range desired {
		if _, exists := b.currentV4[k]; exists {
			continue
		}
		if err := b.mapV4.Put(k, uint32(1)); err != nil {
			return fmt.Errorf("put IPv4 LPM key: %w", err)
		}
	}
	// Delete stale entries SECOND.
	for k := range b.currentV4 {
		if _, keep := desired[k]; keep {
			continue
		}
		if err := b.mapV4.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale IPv4 LPM key: %w", err)
		}
	}
	b.currentV4 = desired
	return nil
}

func (b *LinuxBackend) syncMapV6Locked(prefixes []netip.Prefix) error {
	desired := make(map[LPMKeyV6]struct{}, len(prefixes))
	for _, p := range prefixes {
		k, err := EncodeLPMKeyV6(p)
		if err != nil {
			return err
		}
		desired[k] = struct{}{}
	}
	for k := range desired {
		if _, exists := b.currentV6[k]; exists {
			continue
		}
		if err := b.mapV6.Put(k, uint32(1)); err != nil {
			return fmt.Errorf("put IPv6 LPM key: %w", err)
		}
	}
	for k := range b.currentV6 {
		if _, keep := desired[k]; keep {
			continue
		}
		if err := b.mapV6.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete stale IPv6 LPM key: %w", err)
		}
	}
	b.currentV6 = desired
	return nil
}

func (b *LinuxBackend) readDropStatsLocked() (droppedV4, droppedV6, passed uint64) {
	if b.mapStats == nil {
		return 0, 0, 0
	}
	sumPerCPU := func(idx uint32) uint64 {
		var perCPU []uint64
		if err := b.mapStats.Lookup(idx, &perCPU); err != nil {
			return 0
		}
		var total uint64
		for _, v := range perCPU {
			total += v
		}
		return total
	}
	return sumPerCPU(StatIdxDroppedV4), sumPerCPU(StatIdxDroppedV6), sumPerCPU(StatIdxPassed)
}

func (b *LinuxBackend) attachedInterfaceNamesLocked() []string {
	if len(b.links) == 0 {
		return []string{}
	}
	names := make([]string, 0, len(b.links))
	for name := range b.links {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (b *LinuxBackend) fallbackLocked(ifaces []string, reason string) {
	b.detachAndCloseLocked()
	b.status = StatusDegraded
	b.mode = ModeFallbackUserspace
	b.lastErr = reason
	statuses := make([]InterfaceStatus, 0, len(ifaces))
	for _, name := range ifaces {
		statuses = append(statuses, InterfaceStatus{
			Name:     name,
			Attached: false,
			Mode:     ModeFallbackUserspace,
			Error:    reason,
		})
	}
	b.interfaces = statuses
}

func (b *LinuxBackend) detachAndCloseLocked() {
	for name, lnk := range b.links {
		_ = lnk.link.Close()
		delete(b.links, name)
	}
	if b.mapV4 != nil {
		for k := range b.currentV4 {
			_ = b.mapV4.Delete(k)
		}
	}
	if b.mapV6 != nil {
		for k := range b.currentV6 {
			_ = b.mapV6.Delete(k)
		}
	}
	b.currentV4 = make(map[LPMKeyV4]struct{})
	b.currentV6 = make(map[LPMKeyV6]struct{})
	if b.coll != nil {
		b.coll.Close()
		b.coll = nil
		b.prog = nil
		b.mapV4 = nil
		b.mapV6 = nil
		b.mapStats = nil
	}
}

func modeCompatible(activeMode, requestedAttachMode string) bool {
	switch requestedAttachMode {
	case AttachModeNative:
		return activeMode == ModeXDPNative
	case AttachModeGeneric:
		return activeMode == ModeXDPGeneric
	case AttachModeAuto:
		return activeMode == ModeXDPNative || activeMode == ModeXDPGeneric
	default:
		return false
	}
}

func attachInterfaceXDP(prog *ebpf.Program, ifIndex int, attachMode string) (link.Link, string, error) {
	switch attachMode {
	case AttachModeNative:
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     link.XDPDriverMode,
		})
		if err != nil {
			return nil, ModeFallbackUserspace, fmt.Errorf("native XDP attach failed: %w", err)
		}
		return lnk, ModeXDPNative, nil

	case AttachModeGeneric:
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return nil, ModeFallbackUserspace, fmt.Errorf("generic XDP attach failed: %w", err)
		}
		return lnk, ModeXDPGeneric, nil

	case AttachModeAuto:
		lnk, driverErr := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     link.XDPDriverMode,
		})
		if driverErr == nil {
			return lnk, ModeXDPNative, nil
		}
		lnk, genericErr := link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: ifIndex,
			Flags:     link.XDPGenericMode,
		})
		if genericErr == nil {
			return lnk, ModeXDPGeneric, nil
		}
		return nil, ModeFallbackUserspace, fmt.Errorf("auto XDP attach failed (native: %v; generic: %v)", driverErr, genericErr)

	default:
		return nil, ModeFallbackUserspace, fmt.Errorf("unsupported attach mode %q", attachMode)
	}
}
