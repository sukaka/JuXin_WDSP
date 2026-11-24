package nodesync

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/server/internal/hagroups"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
)

// DefaultTelemetryInterval is the periodic poll interval for remote hasyncd /v1/status telemetry.
const DefaultTelemetryInterval = 15 * time.Second

const (
	defaultNodePollTimeout = 10 * time.Second
	maxConcurrentPolls     = 8
)

// TelemetryRecord is persisted to api_gateway_nodes after a successful GET /v1/status poll.
type TelemetryRecord struct {
	NodeName        string
	CollectedAt     time.Time
	PolicyVersion   string
	ReportedVersion string
	HaVipStatus     json.RawMessage
	HaVipStatusAt   *time.Time
	NetworkStatus   json.RawMessage
	NetworkStatusAt *time.Time
}

// TelemetrySink persists polled node telemetry (adapted from *apinodes.Store in app.go).
type TelemetrySink interface {
	SaveTelemetry(ctx context.Context, rec TelemetryRecord) error
}

// InterfaceApplier merges remote node network interface snapshots (*nodeinterfaces.Store).
type InterfaceApplier interface {
	ApplySnapshot(ctx context.Context, nodeName string, items []nodeinterfaces.SnapshotItem, seenAt time.Time) error
}

// HAEventRecorder persists HA state transition events (*hagroups.Store).
type HAEventRecorder interface {
	RecordEvent(ctx context.Context, ev hagroups.HaEvent) error
}

// GroupIDResolver maps an HA group name to its UUID (optional, best-effort).
type GroupIDResolver func(ctx context.Context, groupName string) string

// TelemetrySweeper periodically polls GET /v1/status from every gateway node that has
// a configured hasyncd sync_agent_addr, persisting converged HA VIP status, network status,
// reported version, and network interfaces while emitting idempotent HA transition events.
type TelemetrySweeper struct {
	manager       *Manager
	sink          TelemetrySink
	ifaces        InterfaceApplier
	events        HAEventRecorder
	groupResolver GroupIDResolver
	interval      time.Duration
	pollTimeout   time.Duration
	now           func() time.Time

	mu             sync.Mutex
	lastVIPState   map[string]string // nodeName -> last observed VIP state (e.g. MASTER/BACKUP/FAULT)
	lastLinkStates map[string]string // nodeName+"/"+bridge -> last observed link_pair state
}

// NewTelemetrySweeper creates a TelemetrySweeper with default 15s polling interval.
func NewTelemetrySweeper(manager *Manager, sink TelemetrySink) *TelemetrySweeper {
	return &TelemetrySweeper{
		manager:        manager,
		sink:           sink,
		interval:       DefaultTelemetryInterval,
		pollTimeout:    defaultNodePollTimeout,
		now:            func() time.Time { return time.Now().UTC() },
		lastVIPState:   make(map[string]string),
		lastLinkStates: make(map[string]string),
	}
}

// SetInterfaceApplier wires *nodeinterfaces.Store to reconcile remote NIC snapshots.
func (s *TelemetrySweeper) SetInterfaceApplier(a InterfaceApplier) *TelemetrySweeper {
	s.ifaces = a
	return s
}

// SetHAEventRecorder wires *hagroups.Store to record VIP_TRANSITION and LINK_PAIR_CHANGE events.
func (s *TelemetrySweeper) SetHAEventRecorder(r HAEventRecorder) *TelemetrySweeper {
	s.events = r
	return s
}

// SetGroupIDResolver wires an optional group_name -> group_id UUID resolver for ha_events.
func (s *TelemetrySweeper) SetGroupIDResolver(fn GroupIDResolver) *TelemetrySweeper {
	s.groupResolver = fn
	return s
}

// SetInterval overrides the poll interval (non-positive uses DefaultTelemetryInterval).
func (s *TelemetrySweeper) SetInterval(d time.Duration) *TelemetrySweeper {
	s.interval = d
	return s
}

// SetClock overrides the wall clock (for deterministic unit tests).
func (s *TelemetrySweeper) SetClock(fn func() time.Time) *TelemetrySweeper {
	if fn != nil {
		s.now = fn
	}
	return s
}

// Run polls remote nodes periodically until ctx is cancelled.
func (s *TelemetrySweeper) Run(ctx context.Context) {
	interval := s.interval
	if interval <= 0 {
		interval = DefaultTelemetryInterval
	}
	slog.Info("nodesync telemetry sweeper started", "interval", interval)
	// Initial sweep on startup so remote statuses converge promptly without waiting a full tick.
	if err := s.SweepOnce(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("nodesync initial telemetry sweep failed", "error", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("nodesync telemetry sweeper stopped")
			return
		case <-t.C:
			if err := s.SweepOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("nodesync telemetry sweep failed", "error", err)
			}
		}
	}
}

// SweepOnce polls all nodes with a configured sync_agent_addr once (bounded concurrency).
func (s *TelemetrySweeper) SweepOnce(ctx context.Context) error {
	if s.manager == nil || s.manager.store == nil {
		return nil
	}
	creds, err := s.manager.store.ListSyncAgentNodes(ctx)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		return nil
	}

	sem := make(chan struct{}, maxConcurrentPolls)
	var wg sync.WaitGroup
	for i := range creds {
		cred := creds[i]
		if strings.TrimSpace(cred.SyncAgentAddr) == "" || strings.TrimSpace(cred.SyncSecretCiphertext) == "" {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(c NodeCredential) {
			defer wg.Done()
			defer func() { <-sem }()
			s.pollOne(ctx, &c)
		}(cred)
	}
	wg.Wait()
	return nil
}

func (s *TelemetrySweeper) pollOne(ctx context.Context, cred *NodeCredential) {
	cli, err := s.manager.ClientForCredential(cred)
	if err != nil {
		slog.Warn("nodesync telemetry client init failed", "node", cred.NodeName, "error", err)
		return
	}
	timeout := s.pollTimeout
	if timeout <= 0 {
		timeout = defaultNodePollTimeout
	}
	pCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	st, err := cli.Status(pCtx)
	if err != nil {
		slog.Warn("nodesync telemetry status poll failed", "node", cred.NodeName, "addr", cred.SyncAgentAddr, "error", err)
		return
	}
	now := s.now().UTC()
	collectedAt := st.CollectedAt.UTC()
	if collectedAt.IsZero() {
		collectedAt = now
	}

	var haVipRaw json.RawMessage
	var haVipAt *time.Time
	if len(st.HaVipStatus) > 0 && json.Valid(st.HaVipStatus) {
		haVipRaw = st.HaVipStatus
		if st.HaVipStatusMtime != nil && !st.HaVipStatusMtime.IsZero() {
			t := st.HaVipStatusMtime.UTC()
			haVipAt = &t
		} else {
			t := collectedAt
			haVipAt = &t
		}
	}

	var netRaw json.RawMessage
	var netAt *time.Time
	if len(st.NetworkStatus) > 0 && json.Valid(st.NetworkStatus) {
		netRaw = st.NetworkStatus
		if st.NetworkStatusMtime != nil && !st.NetworkStatusMtime.IsZero() {
			t := st.NetworkStatusMtime.UTC()
			netAt = &t
		} else {
			t := collectedAt
			netAt = &t
		}
	}

	if s.sink != nil {
		rec := TelemetryRecord{
			NodeName:        cred.NodeName,
			CollectedAt:     collectedAt,
			PolicyVersion:   strings.TrimSpace(st.PolicyVersion),
			ReportedVersion: strings.TrimSpace(st.Version),
			HaVipStatus:     haVipRaw,
			HaVipStatusAt:   haVipAt,
			NetworkStatus:   netRaw,
			NetworkStatusAt: netAt,
		}
		if err := s.sink.SaveTelemetry(ctx, rec); err != nil {
			slog.Warn("nodesync save telemetry failed", "node", cred.NodeName, "error", err)
		}
	}

	if s.ifaces != nil && len(st.Interfaces) > 0 {
		items := make([]nodeinterfaces.SnapshotItem, 0, len(st.Interfaces))
		for _, it := range st.Interfaces {
			if strings.TrimSpace(it.IfName) == "" {
				continue
			}
			itAt := it.CollectedAt.UTC()
			if itAt.IsZero() {
				itAt = collectedAt
			}
			items = append(items, nodeinterfaces.SnapshotItem{
				NodeName:    cred.NodeName,
				Ifname:      it.IfName,
				MAC:         it.MAC,
				IPAddresses: it.IPAddresses,
				PCIPath:     it.PCIPath,
				Driver:      it.Driver,
				MediaType:   it.MediaType,
				LinkSpeed:   int64(it.LinkSpeed),
				Operstate:   it.OperState,
				CollectedAt: itAt,
			})
		}
		if len(items) > 0 {
			if err := s.ifaces.ApplySnapshot(ctx, cred.NodeName, items, collectedAt); err != nil {
				slog.Warn("nodesync apply remote interfaces snapshot failed", "node", cred.NodeName, "error", err)
			}
		}
	}

	if s.events != nil {
		s.detectAndRecordTransitions(ctx, cred.NodeName, haVipRaw, netRaw, now)
	}
}

type polledHaVipStatus struct {
	Group             string   `json:"group"`
	Node              string   `json:"node"`
	State             string   `json:"state"`
	KeepalivedRunning bool     `json:"keepalived_running"`
	VIPsPresent       []string `json:"vips_present"`
	Message           string   `json:"message"`
}

type polledNetworkStatus struct {
	LinkPairs []struct {
		Bridge         string `json:"bridge"`
		State          string `json:"state"`
		DownPort       string `json:"down_port"`
		PropagatedPort string `json:"propagated_port"`
		Message        string `json:"message"`
	} `json:"link_pairs"`
}

func (s *TelemetrySweeper) detectAndRecordTransitions(ctx context.Context, nodeName string, haVipRaw, netRaw json.RawMessage, now time.Time) {
	if len(haVipRaw) > 0 {
		var hv polledHaVipStatus
		if err := json.Unmarshal(haVipRaw, &hv); err == nil {
			curr := strings.ToUpper(strings.TrimSpace(hv.State))
			if curr != "" {
				s.mu.Lock()
				prev := s.lastVIPState[nodeName]
				s.lastVIPState[nodeName] = curr
				s.mu.Unlock()
				if prev != "" && prev != curr {
					groupID := ""
					if s.groupResolver != nil && strings.TrimSpace(hv.Group) != "" {
						groupID = s.groupResolver(ctx, strings.TrimSpace(hv.Group))
					}
					if err := s.events.RecordEvent(ctx, hagroups.HaEvent{
						GroupID:   groupID,
						GroupName: strings.TrimSpace(hv.Group),
						NodeName:  nodeName,
						EventType: hagroups.EventTypeVIPTransition,
						Detail: map[string]any{
							"from_state":         prev,
							"to_state":           curr,
							"keepalived_running": hv.KeepalivedRunning,
							"vips_present":       hv.VIPsPresent,
							"message":            hv.Message,
						},
						OccurredAt: now,
					}); err != nil {
						slog.Warn("nodesync record VIP_TRANSITION event failed", "node", nodeName, "error", err)
					}
				}
			}
		}
	} else {
		// HA VIP file absent (e.g. group removed): clear last observed state so future re-enable seeds cleanly.
		s.mu.Lock()
		delete(s.lastVIPState, nodeName)
		s.mu.Unlock()
	}

	if len(netRaw) > 0 {
		var ns polledNetworkStatus
		if err := json.Unmarshal(netRaw, &ns); err == nil {
			for _, lp := range ns.LinkPairs {
				bridge := strings.TrimSpace(lp.Bridge)
				curr := strings.ToUpper(strings.TrimSpace(lp.State))
				if bridge == "" || curr == "" {
					continue
				}
				key := nodeName + "/" + bridge
				s.mu.Lock()
				prev := s.lastLinkStates[key]
				s.lastLinkStates[key] = curr
				s.mu.Unlock()
				if prev != "" && prev != curr {
					if err := s.events.RecordEvent(ctx, hagroups.HaEvent{
						NodeName:  nodeName,
						EventType: hagroups.EventTypeLinkPairChange,
						Detail: map[string]any{
							"bridge":          bridge,
							"from_state":      prev,
							"to_state":        curr,
							"down_port":       lp.DownPort,
							"propagated_port": lp.PropagatedPort,
							"message":         lp.Message,
						},
						OccurredAt: now,
					}); err != nil {
						slog.Warn("nodesync record LINK_PAIR_CHANGE event failed", "node", nodeName, "bridge", bridge, "error", err)
					}
				}
			}
		}
	}
}
