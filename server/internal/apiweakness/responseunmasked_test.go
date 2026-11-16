package apiweakness

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func (f *fakeSignals) SensitiveResponseUnmasked(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error) {
	if f.err != nil {
		return nil, f.err
	}
	return nil, nil
}

type responseUnmaskedSignals struct {
	fakeSignals
	signals      []EndpointSignal
	err          error
	gotSince     time.Time
	gotMinSample int
}

func (s *responseUnmaskedSignals) SensitiveResponseUnmasked(ctx context.Context, since time.Time, minSamples int) ([]EndpointSignal, error) {
	s.gotSince = since
	s.gotMinSample = minSamples
	if s.err != nil {
		return nil, s.err
	}
	out := make([]EndpointSignal, 0, len(s.signals))
	for _, sig := range s.signals {
		if sig.Hits >= minSamples {
			out = append(out, sig)
		}
	}
	return out, nil
}

func TestSensitiveResponseUnmaskedSweep(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	endpointID := uuid.New()
	belowThresholdID := uuid.New()
	const endpointKey = "GET /v1/customers/{id}"
	source := &responseUnmaskedSignals{signals: []EndpointSignal{
		sigFor(endpointID, endpointKey, 3, now),
		sigFor(belowThresholdID, "GET /v1/below-threshold", 2, now),
	}}
	store := NewMemStore()
	store.SetEndpointKey(endpointID, endpointKey)

	result, err := newTestSweeper(source, store, now).SweepOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Inserted != 1 || result.Updated != 0 || result.ByCode[CodeSensitiveResponseUnmasked] != 1 {
		t.Fatalf("unexpected response-unmasked derivation: %+v", result)
	}
	if source.gotMinSample != 3 || !source.gotSince.Equal(now.Add(-24*time.Hour)) {
		t.Fatalf("default window/threshold not applied: since=%s minSamples=%d", source.gotSince, source.gotMinSample)
	}

	items, total, err := store.List(context.Background(), ListFilter{Page: 1, PageSize: 20})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("unexpected weaknesses: total=%d items=%+v err=%v", total, items, err)
	}
	weakness := items[0]
	if weakness.WeaknessCode != CodeSensitiveResponseUnmasked ||
		weakness.WeaknessName != "响应敏感信息未观察到成功脱敏" ||
		weakness.Category != CategorySensitive || weakness.Severity != SeverityMedium || weakness.Status != StatusNew {
		t.Fatalf("unexpected response-unmasked metadata: %+v", weakness)
	}

	var evidence map[string]any
	if err := json.Unmarshal(weakness.Evidence, &evidence); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"rule": true, "endpoint_key": true, "sample_count": true,
		"window_hours": true, "first_seen": true, "last_seen": true,
	}
	if len(evidence) != len(allowed) {
		t.Fatalf("evidence keys=%v, want exact whitelist", evidence)
	}
	for key := range evidence {
		if !allowed[key] {
			t.Fatalf("evidence contains unexpected key %q: %v", key, evidence)
		}
	}
	if evidence["rule"] != CodeSensitiveResponseUnmasked || evidence["endpoint_key"] != endpointKey ||
		evidence["sample_count"] != float64(3) || evidence["window_hours"] != float64(24) {
		t.Fatalf("unexpected evidence: %v", evidence)
	}
	for _, key := range []string{"first_seen", "last_seen"} {
		value, ok := evidence[key].(string)
		if !ok {
			t.Fatalf("evidence %s is not a timestamp string: %v", key, evidence[key])
		}
		if _, err := time.Parse(time.RFC3339, value); err != nil {
			t.Fatalf("evidence %s is not RFC3339: %v", key, err)
		}
	}
}

func TestSensitiveResponseUnmaskedSourceError(t *testing.T) {
	wantErr := errors.New("response signal query failed")
	source := &responseUnmaskedSignals{err: wantErr}
	_, err := newTestSweeper(source, NewMemStore(), time.Now().UTC()).SweepOnce(context.Background())
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), CodeSensitiveResponseUnmasked) {
		t.Fatalf("response signal error must propagate with rule code, got %v", err)
	}
}
