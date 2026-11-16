package jiuzhang_guard

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
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

	sampleMu          sync.Mutex
	mu                sync.RWMutex
	sample            resourceSample
	lastAcceptedTotal uint64
	lastRateSampleAt  time.Time
	acceptedPerSecond float64
	states            map[*softwareBypassState]struct{}
	nextStateID       uint64
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

func (r *softwareRuntime) sampleOnce() {
	// Manual sampling in diagnostics/tests and the ticker may overlap. The
	// proc sampler contains CPU deltas, so all sampling must be serialized.
	r.sampleMu.Lock()
	defer r.sampleMu.Unlock()
	sample := r.sampler.Sample()
	acceptedTotal := r.connections.acceptedTotal.Load()
	r.mu.Lock()
	if !r.lastRateSampleAt.IsZero() {
		elapsed := sample.takenAt.Sub(r.lastRateSampleAt).Seconds()
		if elapsed > 0 && acceptedTotal >= r.lastAcceptedTotal {
			r.acceptedPerSecond = float64(acceptedTotal-r.lastAcceptedTotal) / elapsed
		}
	}
	r.lastAcceptedTotal = acceptedTotal
	r.lastRateSampleAt = sample.takenAt
	r.sample = sample
	r.mu.Unlock()

	r.sessions.prune(sample.takenAt)
	for _, state := range r.currentStates() {
		state.evaluate(sample)
	}
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
	rate := r.acceptedPerSecond
	r.mu.RUnlock()
	states := r.currentStates()
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
			AcceptedPerSecond: rate,
		},
		HTTP: HTTPSnapshot{
			SessionsActive:        activeSessions,
			SessionsNewTotal:      newSessions,
			SessionsOverflowTotal: overflowSessions,
		},
		SoftwareBypass: SoftwareBypassSnapshot{
			CPUThresholdPercent:    defaults.cpuThreshold,
			MemoryThresholdPercent: defaults.memoryThreshold,
			RecoveryCPUPercent:     recoveryThreshold(defaults.cpuThreshold),
			RecoveryMemoryPercent:  recoveryThreshold(defaults.memoryThreshold),
			MinHoldSeconds:         int(defaults.minHold / time.Second),
		},
	}

	haveConfig := false
	for i, state := range states {
		cfg := state.config
		stateSnapshot := state.snapshot()
		if i == 0 {
			snapshot.Node = state.node
		}
		snapshot.HTTP.RequestsInFlight += state.requestsInFlight.Load()
		snapshot.HTTP.RequestsTotal += state.requestsTotal.Load()
		snapshot.SoftwareBypass.TransitionsTotal += stateSnapshot.transitionsTotal
		snapshot.SoftwareBypass.BypassedRequestsTotal += state.bypassedRequestsTotal.Load()

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
	if sample.cpuAvailable {
		value := sample.cpuPercent
		snapshot.Resources.CPUPercent = &value
	}
	if sample.memoryAvailable {
		value := sample.memoryPercent
		snapshot.Resources.MemoryPercent = &value
	}
	return snapshot
}

func setSoftwareBypassPolicySnapshot(snapshot *SoftwareBypassSnapshot, cfg bypassRuntimeConfig) {
	snapshot.CPUThresholdPercent = cfg.cpuThreshold
	snapshot.MemoryThresholdPercent = cfg.memoryThreshold
	snapshot.RecoveryCPUPercent = recoveryThreshold(cfg.cpuThreshold)
	snapshot.RecoveryMemoryPercent = recoveryThreshold(cfg.memoryThreshold)
	snapshot.MinHoldSeconds = int(cfg.minHold / time.Second)
}
