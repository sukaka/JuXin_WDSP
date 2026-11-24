package jiuzhang_guard

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultRuntimeHistoryCapacity = 300
	maxRuntimeApplications        = 20
)

type softwareBypassState struct {
	id     uint64
	appID  string
	node   string
	config bypassRuntimeConfig

	mu               sync.RWMutex
	active           atomic.Bool
	reason           string
	activatedAt      time.Time
	transitionsTotal uint64

	requestsTotal         atomic.Uint64
	requestsInFlight      atomic.Int64
	bypassedRequestsTotal atomic.Uint64
	bytesInTotal          atomic.Uint64
	bytesOutTotal         atomic.Uint64
	status2xxTotal        atomic.Uint64
	status3xxTotal        atomic.Uint64
	status4xxTotal        atomic.Uint64
	status5xxTotal        atomic.Uint64
}

func newSoftwareBypassState(appID, node string, cfg bypassRuntimeConfig) *softwareBypassState {
	return &softwareBypassState{appID: appID, node: node, config: cfg}
}

func (s *softwareBypassState) evaluate(sample resourceSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	active, reason := evaluateSoftwareBypass(s.config, sample, s.active.Load(), s.activatedAt, sample.takenAt)
	if active != s.active.Load() {
		s.active.Store(active)
		s.transitionsTotal++
		if active {
			s.activatedAt = sample.takenAt
		} else {
			s.activatedAt = time.Time{}
		}
	}
	s.reason = reason
}

type softwareBypassStateSnapshot struct {
	active           bool
	reason           string
	activatedAt      time.Time
	transitionsTotal uint64
}

func (s *softwareBypassState) snapshot() softwareBypassStateSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return softwareBypassStateSnapshot{
		active:           s.active.Load(),
		reason:           s.reason,
		activatedAt:      s.activatedAt,
		transitionsTotal: s.transitionsTotal,
	}
}

type runtimeRateCounters struct {
	acceptedTotal    uint64
	bytesInTotal     uint64
	bytesOutTotal    uint64
	requestsTotal    uint64
	sessionsNewTotal uint64
	status2xxTotal   uint64
	status3xxTotal   uint64
	status4xxTotal   uint64
	status5xxTotal   uint64
}

type runtimeRates struct {
	acceptedPerSecond    float64
	bytesInPerSecond     float64
	bytesOutPerSecond    float64
	requestsPerSecond    float64
	sessionsNewPerSecond float64
	status2xxPerSecond   float64
	status3xxPerSecond   float64
	status4xxPerSecond   float64
	status5xxPerSecond   float64
}

type appRateState struct {
	lastRequestsTotal uint64
	lastBytesInTotal  uint64
	lastBytesOutTotal uint64
	requestsPerSecond float64
	bytesInPerSecond  float64
	bytesOutPerSecond float64
}

type runtimeHistoryRing struct {
	buf   []RuntimeHistoryPoint
	cap   int
	head  int
	count int
}

func newRuntimeHistoryRing(capacity int) *runtimeHistoryRing {
	if capacity <= 0 {
		capacity = defaultRuntimeHistoryCapacity
	}
	return &runtimeHistoryRing{
		buf: make([]RuntimeHistoryPoint, capacity),
		cap: capacity,
	}
}

func (rb *runtimeHistoryRing) push(point RuntimeHistoryPoint) {
	if rb == nil || rb.cap <= 0 {
		return
	}
	rb.buf[rb.head] = point
	rb.head = (rb.head + 1) % rb.cap
	if rb.count < rb.cap {
		rb.count++
	}
}

func (rb *runtimeHistoryRing) snapshot() []RuntimeHistoryPoint {
	if rb == nil || rb.count == 0 {
		return make([]RuntimeHistoryPoint, 0)
	}
	out := make([]RuntimeHistoryPoint, rb.count)
	start := 0
	if rb.count == rb.cap {
		start = rb.head
	}
	for i := 0; i < rb.count; i++ {
		out[i] = rb.buf[(start+i)%rb.cap]
	}
	return out
}

// softwareRuntime owns process-wide resources only. Bypass policy, transition state,
// and request counters belong to softwareBypassState so independent Caddy handler
// instances cannot overwrite one another during provisioning or reloads.
type softwareRuntime struct {
	sampler     resourceSampler
	connections *connectionMetrics
	sessions    *sessionTracker
	startOnce   sync.Once
	stopOnce    sync.Once
	stopCh      chan struct{}
	doneCh      chan struct{}

	sampleMu         sync.Mutex
	mu               sync.RWMutex
	sample           resourceSample
	lastCounters     runtimeRateCounters
	lastRateSampleAt time.Time
	rates            runtimeRates
	appRates         map[string]appRateState
	history          *runtimeHistoryRing
	states           map[*softwareBypassState]struct{}
	nextStateID      uint64
}

var globalSoftwareRuntime = newSoftwareRuntime(newProcResourceSampler(), globalConnectionMetrics)

func newSoftwareRuntime(sampler resourceSampler, connections *connectionMetrics) *softwareRuntime {
	if connections == nil {
		connections = globalConnectionMetrics
	}
	return &softwareRuntime{
		sampler:     sampler,
		connections: connections,
		sessions:    newSessionTracker(defaultSessionIdleTimeout, defaultMaxTrackedSessions),
		appRates:    make(map[string]appRateState),
		history:     newRuntimeHistoryRing(defaultRuntimeHistoryCapacity),
		states:      make(map[*softwareBypassState]struct{}),
	}
}

func (r *softwareRuntime) register(state *softwareBypassState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.states[state]; ok {
		return
	}
	r.nextStateID++
	state.id = r.nextStateID
	r.states[state] = struct{}{}
}

func (r *softwareRuntime) unregister(state *softwareBypassState) {
	r.mu.Lock()
	delete(r.states, state)
	r.mu.Unlock()
}

func (r *softwareRuntime) currentStates() []*softwareBypassState {
	r.mu.RLock()
	states := make([]*softwareBypassState, 0, len(r.states))
	for state := range r.states {
		states = append(states, state)
	}
	r.mu.RUnlock()
	sort.Slice(states, func(i, j int) bool { return states[i].id < states[j].id })
	return states
}

func (r *softwareRuntime) start() {
	r.startOnce.Do(func() {
		r.stopCh = make(chan struct{})
		r.doneCh = make(chan struct{})
		go func() {
			defer close(r.doneCh)
			r.sampleOnce()
			ticker := time.NewTicker(softwareBypassSampleInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					r.sampleOnce()
				case <-r.stopCh:
					return
				}
			}
		}()
	})
}

func (r *softwareRuntime) stop() {
	r.stopOnce.Do(func() {
		if r.stopCh != nil {
			close(r.stopCh)
			<-r.doneCh
		}
	})
}

func computeRate(current, prev uint64, elapsed float64) float64 {
	if elapsed <= 0 || current < prev {
		return 0
	}
	return float64(current-prev) / elapsed
}

func (r *softwareRuntime) sampleOnce() {
	// Manual sampling in diagnostics/tests and the ticker may overlap. The
	// proc sampler contains CPU deltas, so all sampling must be serialized.
	r.sampleMu.Lock()
	defer r.sampleMu.Unlock()
	sample := r.sampler.Sample()
	takenAt := sample.takenAt
	if takenAt.IsZero() {
		takenAt = time.Now().UTC()
		sample.takenAt = takenAt
	}

	states := r.currentStates()
	for _, state := range states {
		state.evaluate(sample)
	}

	sessionsActive, sessionsNewTotal, _ := r.sessions.snapshot(takenAt)
	connActive := r.connections.active.Load()
	current := runtimeRateCounters{
		acceptedTotal:    r.connections.acceptedTotal.Load(),
		bytesInTotal:     r.connections.bytesInTotal.Load(),
		bytesOutTotal:    r.connections.bytesOutTotal.Load(),
		sessionsNewTotal: sessionsNewTotal,
	}

	type appCounters struct {
		requestsTotal uint64
		bytesInTotal  uint64
		bytesOutTotal uint64
	}
	appTotals := make(map[string]appCounters, len(states))
	var reqInFlight int64
	bypassActive := false
	for _, state := range states {
		reqInFlight += state.requestsInFlight.Load()
		reqTotal := state.requestsTotal.Load()
		bytesIn := state.bytesInTotal.Load()
		bytesOut := state.bytesOutTotal.Load()
		current.requestsTotal += reqTotal
		current.status2xxTotal += state.status2xxTotal.Load()
		current.status3xxTotal += state.status3xxTotal.Load()
		current.status4xxTotal += state.status4xxTotal.Load()
		current.status5xxTotal += state.status5xxTotal.Load()
		if state.active.Load() {
			bypassActive = true
		}
		if state.appID != "" {
			agg := appTotals[state.appID]
			agg.requestsTotal += reqTotal
			agg.bytesInTotal += bytesIn
			agg.bytesOutTotal += bytesOut
			appTotals[state.appID] = agg
		}
	}

	r.mu.Lock()
	if r.lastRateSampleAt.IsZero() {
		r.lastCounters = current
		r.lastRateSampleAt = takenAt
		nextAppRates := make(map[string]appRateState, len(appTotals))
		for appID, agg := range appTotals {
			nextAppRates[appID] = appRateState{
				lastRequestsTotal: agg.requestsTotal,
				lastBytesInTotal:  agg.bytesInTotal,
				lastBytesOutTotal: agg.bytesOutTotal,
			}
		}
		r.appRates = nextAppRates
	} else {
		elapsed := takenAt.Sub(r.lastRateSampleAt).Seconds()
		switch {
		case elapsed > 0:
			r.rates = runtimeRates{
				acceptedPerSecond:    computeRate(current.acceptedTotal, r.lastCounters.acceptedTotal, elapsed),
				bytesInPerSecond:     computeRate(current.bytesInTotal, r.lastCounters.bytesInTotal, elapsed),
				bytesOutPerSecond:    computeRate(current.bytesOutTotal, r.lastCounters.bytesOutTotal, elapsed),
				requestsPerSecond:    computeRate(current.requestsTotal, r.lastCounters.requestsTotal, elapsed),
				sessionsNewPerSecond: computeRate(current.sessionsNewTotal, r.lastCounters.sessionsNewTotal, elapsed),
				status2xxPerSecond:   computeRate(current.status2xxTotal, r.lastCounters.status2xxTotal, elapsed),
				status3xxPerSecond:   computeRate(current.status3xxTotal, r.lastCounters.status3xxTotal, elapsed),
				status4xxPerSecond:   computeRate(current.status4xxTotal, r.lastCounters.status4xxTotal, elapsed),
				status5xxPerSecond:   computeRate(current.status5xxTotal, r.lastCounters.status5xxTotal, elapsed),
			}
			nextAppRates := make(map[string]appRateState, len(appTotals))
			for appID, agg := range appTotals {
				prev := r.appRates[appID]
				nextAppRates[appID] = appRateState{
					lastRequestsTotal: agg.requestsTotal,
					lastBytesInTotal:  agg.bytesInTotal,
					lastBytesOutTotal: agg.bytesOutTotal,
					requestsPerSecond: computeRate(agg.requestsTotal, prev.lastRequestsTotal, elapsed),
					bytesInPerSecond:  computeRate(agg.bytesInTotal, prev.lastBytesInTotal, elapsed),
					bytesOutPerSecond: computeRate(agg.bytesOutTotal, prev.lastBytesOutTotal, elapsed),
				}
			}
			r.appRates = nextAppRates
			r.lastCounters = current
			r.lastRateSampleAt = takenAt
		case elapsed < 0:
			r.rates = runtimeRates{}
			nextAppRates := make(map[string]appRateState, len(appTotals))
			for appID, agg := range appTotals {
				nextAppRates[appID] = appRateState{
					lastRequestsTotal: agg.requestsTotal,
					lastBytesInTotal:  agg.bytesInTotal,
					lastBytesOutTotal: agg.bytesOutTotal,
				}
			}
			r.appRates = nextAppRates
			r.lastCounters = current
			r.lastRateSampleAt = takenAt
		default:
			// elapsed == 0: keep existing rates and baselines without dividing by zero.
			if r.appRates == nil {
				r.appRates = make(map[string]appRateState, len(appTotals))
			}
			for appID, agg := range appTotals {
				if _, ok := r.appRates[appID]; !ok {
					r.appRates[appID] = appRateState{
						lastRequestsTotal: agg.requestsTotal,
						lastBytesInTotal:  agg.bytesInTotal,
						lastBytesOutTotal: agg.bytesOutTotal,
					}
				}
			}
		}
	}
	r.sample = sample

	point := RuntimeHistoryPoint{
		TakenAt:                         takenAt,
		TCPConnectionsActive:            connActive,
		TCPConnectionsAcceptedPerSecond: r.rates.acceptedPerSecond,
		BytesInPerSecond:                r.rates.bytesInPerSecond,
		BytesOutPerSecond:               r.rates.bytesOutPerSecond,
		HTTPRequestsInFlight:            reqInFlight,
		HTTPRequestsPerSecond:           r.rates.requestsPerSecond,
		HTTPSessionsActive:              sessionsActive,
		HTTPSessionsNewPerSecond:        r.rates.sessionsNewPerSecond,
		Status2xxPerSecond:              r.rates.status2xxPerSecond,
		Status3xxPerSecond:              r.rates.status3xxPerSecond,
		Status4xxPerSecond:              r.rates.status4xxPerSecond,
		Status5xxPerSecond:              r.rates.status5xxPerSecond,
		SoftwareBypassActive:            bypassActive,
	}
	if sample.cpuAvailable {
		v := sample.cpuPercent
		point.CPUPercent = &v
	}
	if sample.memoryAvailable {
		v := sample.memoryPercent
		point.MemoryPercent = &v
	}
	if sample.loadAvailable {
		v := sample.load1
		point.Load1 = &v
	}
	if sample.fdUsageAvailable {
		v := sample.fdUsagePercent
		point.FDUsagePercent = &v
	}
	if r.history == nil {
		r.history = newRuntimeHistoryRing(defaultRuntimeHistoryCapacity)
	}
	r.history.push(point)
	r.mu.Unlock()
}

func evaluateSoftwareBypass(cfg bypassRuntimeConfig, sample resourceSample, active bool, activatedAt, now time.Time) (bool, string) {
	if !cfg.enabled {
		return false, ""
	}
	cpuHigh := sample.cpuAvailable && sample.cpuPercent > float64(cfg.cpuThreshold)
	memoryHigh := sample.memoryAvailable && sample.memoryPercent > float64(cfg.memoryThreshold)
	if !active {
		switch {
		case cpuHigh && memoryHigh:
			return true, "CPU_AND_MEMORY_THRESHOLD"
		case cpuHigh:
			return true, "CPU_THRESHOLD"
		case memoryHigh:
			return true, "MEMORY_THRESHOLD"
		default:
			return false, ""
		}
	}
	if activatedAt.IsZero() || now.Sub(activatedAt) < cfg.minHold {
		return true, activeReason(sample, cfg)
	}
	cpuRecovered := sample.cpuAvailable && sample.cpuPercent < float64(recoveryThreshold(cfg.cpuThreshold))
	memoryRecovered := sample.memoryAvailable && sample.memoryPercent < float64(recoveryThreshold(cfg.memoryThreshold))
	if cpuRecovered && memoryRecovered {
		return false, ""
	}
	return true, activeReason(sample, cfg)
}

func activeReason(sample resourceSample, cfg bypassRuntimeConfig) string {
	cpuHigh := sample.cpuAvailable && sample.cpuPercent >= float64(recoveryThreshold(cfg.cpuThreshold))
	memoryHigh := sample.memoryAvailable && sample.memoryPercent >= float64(recoveryThreshold(cfg.memoryThreshold))
	switch {
	case cpuHigh && memoryHigh:
		return "CPU_AND_MEMORY_THRESHOLD"
	case cpuHigh:
		return "CPU_THRESHOLD"
	case memoryHigh:
		return "MEMORY_THRESHOLD"
	default:
		return "MIN_HOLD_OR_SAMPLE_UNAVAILABLE"
	}
}

func recoveryThreshold(threshold int) int {
	return max(1, threshold-softwareBypassRecoveryDelta)
}

func (r *softwareRuntime) snapshot(now time.Time) RuntimeSnapshot {
	r.mu.RLock()
	sample := r.sample
	rates := r.rates
	appRates := make(map[string]appRateState, len(r.appRates))
	for appID, ar := range r.appRates {
		appRates[appID] = ar
	}
	states := make([]*softwareBypassState, 0, len(r.states))
	for state := range r.states {
		states = append(states, state)
	}
	r.mu.RUnlock()
	sort.Slice(states, func(i, j int) bool { return states[i].id < states[j].id })

	activeSessions, newSessions, overflowSessions := r.sessions.snapshot(now)
	defaults := (&SoftwareBypass{}).mustRuntimeConfig()
	snapshot := RuntimeSnapshot{
		TakenAt: now,
		Resources: ResourceSnapshot{
			SampledAt: sample.takenAt,
			Error:     sample.err,
		},
		Connections: ConnectionSnapshot{
			Active:            r.connections.active.Load(),
			AcceptedTotal:     r.connections.acceptedTotal.Load(),
			AcceptedPerSecond: rates.acceptedPerSecond,
			BytesInTotal:      r.connections.bytesInTotal.Load(),
			BytesOutTotal:     r.connections.bytesOutTotal.Load(),
			BytesInPerSecond:  rates.bytesInPerSecond,
			BytesOutPerSecond: rates.bytesOutPerSecond,
		},
		HTTP: HTTPSnapshot{
			RequestsPerSecond:     rates.requestsPerSecond,
			SessionsActive:        activeSessions,
			SessionsNewTotal:      newSessions,
			SessionsNewPerSecond:  rates.sessionsNewPerSecond,
			SessionsOverflowTotal: overflowSessions,
			Status2xxPerSecond:    rates.status2xxPerSecond,
			Status3xxPerSecond:    rates.status3xxPerSecond,
			Status4xxPerSecond:    rates.status4xxPerSecond,
			Status5xxPerSecond:    rates.status5xxPerSecond,
		},
		SoftwareBypass: SoftwareBypassSnapshot{
			CPUThresholdPercent:    defaults.cpuThreshold,
			MemoryThresholdPercent: defaults.memoryThreshold,
			RecoveryCPUPercent:     recoveryThreshold(defaults.cpuThreshold),
			RecoveryMemoryPercent:  recoveryThreshold(defaults.memoryThreshold),
			MinHoldSeconds:         int(defaults.minHold / time.Second),
		},
		Applications: make([]ApplicationRuntimeSnapshot, 0),
	}

	appMap := make(map[string]*ApplicationRuntimeSnapshot)
	haveConfig := false
	for i, state := range states {
		cfg := state.config
		stateSnapshot := state.snapshot()
		if i == 0 {
			snapshot.Node = state.node
		}
		reqInFlight := state.requestsInFlight.Load()
		reqTotal := state.requestsTotal.Load()
		bypassedTotal := state.bypassedRequestsTotal.Load()
		bytesIn := state.bytesInTotal.Load()
		bytesOut := state.bytesOutTotal.Load()
		status2xx := state.status2xxTotal.Load()
		status3xx := state.status3xxTotal.Load()
		status4xx := state.status4xxTotal.Load()
		status5xx := state.status5xxTotal.Load()

		snapshot.HTTP.RequestsInFlight += reqInFlight
		snapshot.HTTP.RequestsTotal += reqTotal
		snapshot.HTTP.Status2xxTotal += status2xx
		snapshot.HTTP.Status3xxTotal += status3xx
		snapshot.HTTP.Status4xxTotal += status4xx
		snapshot.HTTP.Status5xxTotal += status5xx
		snapshot.SoftwareBypass.TransitionsTotal += stateSnapshot.transitionsTotal
		snapshot.SoftwareBypass.BypassedRequestsTotal += bypassedTotal

		if state.appID != "" {
			appEntry, ok := appMap[state.appID]
			if !ok {
				ar := appRates[state.appID]
				appEntry = &ApplicationRuntimeSnapshot{
					AppID:             state.appID,
					RequestsPerSecond: ar.requestsPerSecond,
					BytesInPerSecond:  ar.bytesInPerSecond,
					BytesOutPerSecond: ar.bytesOutPerSecond,
				}
				appMap[state.appID] = appEntry
			}
			appEntry.RequestsInFlight += reqInFlight
			appEntry.RequestsTotal += reqTotal
			appEntry.BypassedRequestsTotal += bypassedTotal
			appEntry.BytesInTotal += bytesIn
			appEntry.BytesOutTotal += bytesOut
			appEntry.Status4xxTotal += status4xx
			appEntry.Status5xxTotal += status5xx
		}

		if !haveConfig {
			haveConfig = true
			setSoftwareBypassPolicySnapshot(&snapshot.SoftwareBypass, cfg)
		}
		if cfg.enabled {
			if !snapshot.SoftwareBypass.Enabled {
				setSoftwareBypassPolicySnapshot(&snapshot.SoftwareBypass, cfg)
			} else {
				snapshot.SoftwareBypass.CPUThresholdPercent = min(snapshot.SoftwareBypass.CPUThresholdPercent, cfg.cpuThreshold)
				snapshot.SoftwareBypass.MemoryThresholdPercent = min(snapshot.SoftwareBypass.MemoryThresholdPercent, cfg.memoryThreshold)
				snapshot.SoftwareBypass.MinHoldSeconds = min(snapshot.SoftwareBypass.MinHoldSeconds, int(cfg.minHold/time.Second))
			}
			snapshot.SoftwareBypass.Enabled = true
			snapshot.SoftwareBypass.RecoveryCPUPercent = recoveryThreshold(snapshot.SoftwareBypass.CPUThresholdPercent)
			snapshot.SoftwareBypass.RecoveryMemoryPercent = recoveryThreshold(snapshot.SoftwareBypass.MemoryThresholdPercent)
		}
		if stateSnapshot.active {
			if !snapshot.SoftwareBypass.Active {
				snapshot.SoftwareBypass.Reason = stateSnapshot.reason
			}
			snapshot.SoftwareBypass.Active = true
			if !stateSnapshot.activatedAt.IsZero() &&
				(snapshot.SoftwareBypass.ActivatedAt == nil || stateSnapshot.activatedAt.Before(*snapshot.SoftwareBypass.ActivatedAt)) {
				value := stateSnapshot.activatedAt
				snapshot.SoftwareBypass.ActivatedAt = &value
			}
		}
	}
	if snapshot.Node == "" {
		snapshot.Node = runtimeNode("")
	}
	if len(appMap) > 0 {
		apps := make([]ApplicationRuntimeSnapshot, 0, len(appMap))
		for _, entry := range appMap {
			apps = append(apps, *entry)
		}
		sort.Slice(apps, func(i, j int) bool {
			if apps[i].RequestsPerSecond != apps[j].RequestsPerSecond {
				return apps[i].RequestsPerSecond > apps[j].RequestsPerSecond
			}
			if apps[i].RequestsTotal != apps[j].RequestsTotal {
				return apps[i].RequestsTotal > apps[j].RequestsTotal
			}
			return apps[i].AppID < apps[j].AppID
		})
		if len(apps) > maxRuntimeApplications {
			apps = apps[:maxRuntimeApplications]
		}
		snapshot.Applications = apps
	}

	if sample.cpuAvailable {
		value := sample.cpuPercent
		snapshot.Resources.CPUPercent = &value
	}
	if sample.memoryAvailable {
		value := sample.memoryPercent
		snapshot.Resources.MemoryPercent = &value
	}
	if sample.memoryBytesAvailable {
		used := sample.memoryUsedBytes
		total := sample.memoryTotalBytes
		snapshot.Resources.MemoryUsedBytes = &used
		snapshot.Resources.MemoryTotalBytes = &total
	}
	if sample.loadAvailable {
		l1, l5, l15 := sample.load1, sample.load5, sample.load15
		snapshot.Resources.Load1 = &l1
		snapshot.Resources.Load5 = &l5
		snapshot.Resources.Load15 = &l15
	}
	if sample.fdOpenAvailable {
		open := sample.fdOpen
		snapshot.Resources.FDOpen = &open
	}
	if sample.fdMaxAvailable {
		maxFD := sample.fdMax
		snapshot.Resources.FDMax = &maxFD
	}
	if sample.fdUsageAvailable {
		usage := sample.fdUsagePercent
		snapshot.Resources.FDUsagePercent = &usage
	}
	if sample.tcpStates != nil {
		cp := *sample.tcpStates
		snapshot.Connections.TCPStates = &cp
	}
	return snapshot
}

func (r *softwareRuntime) historySnapshot() RuntimeHistory {
	r.mu.RLock()
	var node string
	var minID uint64
	for state := range r.states {
		if minID == 0 || state.id < minID {
			minID = state.id
			node = state.node
		}
	}
	points := r.history.snapshot()
	r.mu.RUnlock()
	if node == "" {
		node = runtimeNode("")
	}
	return RuntimeHistory{
		Node:            node,
		IntervalSeconds: int(softwareBypassSampleInterval / time.Second),
		Points:          points,
	}
}

func setSoftwareBypassPolicySnapshot(snapshot *SoftwareBypassSnapshot, cfg bypassRuntimeConfig) {
	snapshot.CPUThresholdPercent = cfg.cpuThreshold
	snapshot.MemoryThresholdPercent = cfg.memoryThreshold
	snapshot.RecoveryCPUPercent = recoveryThreshold(cfg.cpuThreshold)
	snapshot.RecoveryMemoryPercent = recoveryThreshold(cfg.memoryThreshold)
	snapshot.MinHoldSeconds = int(cfg.minHold / time.Second)
}
