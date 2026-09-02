package identitybehavior

import "testing"

type metricsStoreStub struct {
	metrics ValkeyDegradationMetrics
}

func (s *metricsStoreStub) Observe(ObserveInput) (*Snapshot, error) { return &Snapshot{}, nil }
func (s *metricsStoreStub) Close() error                            { return nil }
func (s *metricsStoreStub) DegradationMetrics() ValkeyDegradationMetrics {
	return s.metrics
}

func TestEngineDegradationMetricsAdapter(t *testing.T) {
	want := ValkeyDegradationMetrics{FallbackTotal: 3, TimeoutTotal: 2, ErrorTotal: 1}
	e := NewEngine(nil, &metricsStoreStub{metrics: want}, nil, Options{})

	if got := e.DegradationMetrics(); got != want {
		t.Fatalf("degradation metrics = %+v, want %+v", got, want)
	}
}

func TestEngineDegradationMetricsAdapterWithoutSource(t *testing.T) {
	e := NewEngine(nil, NewMemoryStore(1, nil), nil, Options{})
	if got := e.DegradationMetrics(); got != (ValkeyDegradationMetrics{}) {
		t.Fatalf("memory degradation metrics = %+v, want zero", got)
	}

	var nilEngine *Engine
	if got := nilEngine.DegradationMetrics(); got != (ValkeyDegradationMetrics{}) {
		t.Fatalf("nil engine degradation metrics = %+v, want zero", got)
	}
}
