package requestpcap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

type memSpoolStore struct {
	artifacts  map[uuid.UUID]Artifact
	linked     map[string]bool
	reqResults map[string]error
}

func newMemSpoolStore() *memSpoolStore {
	return &memSpoolStore{
		artifacts:  make(map[uuid.UUID]Artifact),
		linked:     make(map[string]bool),
		reqResults: make(map[string]error),
	}
}

func (m *memSpoolStore) GetArtifact(_ context.Context, id uuid.UUID) (Artifact, error) {
	a, ok := m.artifacts[id]
	if !ok {
		return Artifact{}, ErrArtifactNotFound
	}
	return a, nil
}

func (m *memSpoolStore) CreateArtifact(_ context.Context, a Artifact) error {
	m.artifacts[a.ID] = a
	return nil
}

func (m *memSpoolStore) RecordCapturedRequest(_ context.Context, _ uuid.UUID, req CapturedRequest) error {
	if err, ok := m.reqResults[req.RequestID]; ok {
		return err
	}
	m.linked[req.RequestID] = true
	return nil
}

func writeSpoolFixture(t *testing.T, hotRoot string, seed Artifact, ciphertext []byte, name string, reqs []pcapevidence.RequestEvidence) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(hotRoot, seed.ID.String()+".wpcap"), ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(spoolRecord{
		Manifest:   seed.Manifest,
		KeyID:      seed.KeyID,
		WrappedKey: seed.WrappedDEK,
		Requests:   reqs,
	})
	if err != nil {
		t.Fatal(err)
	}
	sidecar := filepath.Join(hotRoot, name)
	if err := os.WriteFile(sidecar, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return sidecar
}

func TestSpoolQuarantinesExpiredStuckSidecars(t *testing.T) {
	seed, svc, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	ciphertext, err := os.ReadFile(filepath.Join(svc.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemSpoolStore()
	store.reqResults["req-missing"] = ErrRequestAuditNotFound

	sidecar := writeSpoolFixture(t, hotRoot, seed.artifact, ciphertext, seed.artifact.ID.String()+".wpcap.json", []pcapevidence.RequestEvidence{
		{
			RequestID:     "req-missing",
			ConnectionID:  string(bytesRepeat('a', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "GATEWAY_EGRESS",
			Method:        "GET",
			Path:          "/missing",
			FirstPacketNo: 1,
			LastPacketNo:  1,
		},
	})
	oldTime := time.Now().UTC().Add(-15 * time.Minute)
	if err := os.Chtimes(sidecar, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}

	collector, err := NewSpoolCollector(store, hotRoot, seed.artifact.NodeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce error = %v", err)
	}
	if _, err := os.Stat(sidecar); !os.IsNotExist(err) {
		t.Fatalf("expired stuck sidecar was not quarantined: %v", err)
	}
	if _, err := os.Stat(sidecar + ".quarantined"); err != nil {
		t.Fatalf("quarantined sidecar missing: %v", err)
	}
	if collector.Stats().Quarantined != 1 {
		t.Fatalf("quarantined count = %d, want 1", collector.Stats().Quarantined)
	}
}

func TestSpoolCorrelatesSiblingRequestsIndependently(t *testing.T) {
	seed, svc, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	ciphertext, err := os.ReadFile(filepath.Join(svc.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemSpoolStore()
	store.reqResults["req-bad"] = errors.New("method mismatch")
	store.reqResults["req-pending"] = ErrRequestAuditNotFound

	writeSpoolFixture(t, hotRoot, seed.artifact, ciphertext, seed.artifact.ID.String()+".wpcap.json", []pcapevidence.RequestEvidence{
		{
			RequestID:     "req-untrusted",
			ConnectionID:  string(bytesRepeat('a', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "UNTRUSTED",
			Method:        "GET",
			Path:          "/bad",
			FirstPacketNo: 1,
			LastPacketNo:  1,
		},
		{
			RequestID:     "req-bad",
			ConnectionID:  string(bytesRepeat('b', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "GATEWAY_EGRESS",
			Method:        "GET",
			Path:          "/bad2",
			FirstPacketNo: 2,
			LastPacketNo:  2,
		},
		{
			RequestID:     "req-pending",
			ConnectionID:  string(bytesRepeat('c', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "GATEWAY_EGRESS",
			Method:        "GET",
			Path:          "/pending",
			FirstPacketNo: 3,
			LastPacketNo:  3,
		},
		{
			RequestID:     "req-good",
			ConnectionID:  string(bytesRepeat('d', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "GATEWAY_EGRESS",
			Method:        "GET",
			Path:          "/good",
			FirstPacketNo: 4,
			LastPacketNo:  4,
		},
	})

	collector, err := NewSpoolCollector(store, hotRoot, seed.artifact.NodeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(context.Background()); err == nil {
		t.Fatal("expected error for untrusted/bad sibling requests")
	}
	if !store.linked["req-good"] {
		t.Fatal("good sibling request was blocked by earlier bad/pending requests")
	}
}

func TestSpoolDoesNotStarveBehind64StuckFiles(t *testing.T) {
	seed, svc, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	ciphertext, err := os.ReadFile(filepath.Join(svc.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	store := newMemSpoolStore()
	// Create 70 lexicographically earlier stuck supplemental files (pending)
	for i := 0; i < 70; i++ {
		reqID := fmt.Sprintf("req-stuck-%03d", i)
		store.reqResults[reqID] = ErrRequestAuditNotFound
		stuckName := fmt.Sprintf("00000000-0000-4000-8000-%012d.wpcap.json", i)
		if err := os.WriteFile(filepath.Join(hotRoot, stuckName), []byte("invalid-json"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Create 1 valid file sorting lexicographically after all 70 stuck files
	goodName := seed.artifact.ID.String() + ".wpcap.json"
	if goodName[0] == '0' {
		// Force supplemental suffix or rewrite artifact ID prefix? Instead use supplemental file with ffff...
		goodName = seed.artifact.ID.String() + ".ffffffff-ffff-4fff-8fff-ffffffffffff.wpcap.json"
	}
	// Guarantee stuck names sort before goodName by naming stuck files with "00000000-..."?
	// Even if seed.artifact.ID starts with "00000000-", use 70 files starting with "00000000-0000-..." and put good artifact in store.
	goodSidecar := writeSpoolFixture(t, hotRoot, seed.artifact, ciphertext, goodName, []pcapevidence.RequestEvidence{
		{
			RequestID:     "req-good-after-64",
			ConnectionID:  string(bytesRepeat('e', 64)),
			ObservedAt:    time.Now().UTC(),
			CapturePoint:  "GATEWAY_EGRESS",
			Method:        "POST",
			Path:          "/ok",
			FirstPacketNo: 1,
			LastPacketNo:  1,
		},
	})

	collector, err := NewSpoolCollector(store, hotRoot, seed.artifact.NodeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = collector.CollectOnce(context.Background())
	if !store.linked["req-good-after-64"] {
		t.Fatal("valid sidecar starved behind 70 lexicographically earlier stuck files")
	}
	if _, err := os.Stat(goodSidecar); !os.IsNotExist(err) {
		t.Fatalf("delivered sidecar still exists: %v", err)
	}
}

type memLifecycleStore struct {
	artifacts map[uuid.UUID]Artifact
}

func (m *memLifecycleStore) GetArtifact(_ context.Context, id uuid.UUID) (Artifact, error) {
	a, ok := m.artifacts[id]
	if !ok {
		return Artifact{}, ErrArtifactNotFound
	}
	return a, nil
}

func (m *memLifecycleStore) BeginMigration(_ context.Context, id uuid.UUID) error {
	a := m.artifacts[id]
	if a.State != "HOT" {
		return ErrInvalidTransition
	}
	a.State = "MIGRATING"
	m.artifacts[id] = a
	return nil
}

func (m *memLifecycleStore) CompleteMigration(_ context.Context, id uuid.UUID, hash string) error {
	a := m.artifacts[id]
	if a.State != "MIGRATING" || a.CiphertextSHA256 != hash {
		return ErrInvalidTransition
	}
	a.State = "WARM"
	a.StorageTier = "WARM"
	m.artifacts[id] = a
	return nil
}

func (m *memLifecycleStore) BeginExpiry(_ context.Context, id uuid.UUID) error {
	a := m.artifacts[id]
	if a.State != "WARM" && a.State != "HOT" {
		return ErrInvalidTransition
	}
	a.State = "EXPIRING"
	m.artifacts[id] = a
	return nil
}

func (m *memLifecycleStore) CompleteExpiry(_ context.Context, id uuid.UUID) error {
	a := m.artifacts[id]
	if a.State != "EXPIRING" {
		return ErrInvalidTransition
	}
	a.State = "EXPIRED"
	m.artifacts[id] = a
	return nil
}

func (m *memLifecycleStore) MarkUnavailable(_ context.Context, id uuid.UUID) error {
	a := m.artifacts[id]
	a.State = "UNAVAILABLE"
	m.artifacts[id] = a
	return nil
}

func (m *memLifecycleStore) ListHotArtifacts(_ context.Context, nodeID string, before time.Time, limit int) ([]Artifact, error) {
	var out []Artifact
	for _, a := range m.artifacts {
		if a.NodeID == nodeID && (a.State == "HOT" || a.State == "MIGRATING") && !a.CaptureEndedAt.After(before) {
			out = append(out, a)
		}
	}
	return out, nil
}

func (m *memLifecycleStore) ListExpiredArtifacts(_ context.Context, nodeID string, at time.Time, limit int) ([]Artifact, error) {
	var out []Artifact
	for _, a := range m.artifacts {
		if a.NodeID == nodeID && (a.State == "WARM" || a.State == "EXPIRING" || a.State == "HOT") && !a.ExpiresAt.After(at) {
			out = append(out, a)
		}
	}
	return out, nil
}

func TestStorageExpireOneHandlesHotAndExpiringHotArtifacts(t *testing.T) {
	hotRoot := t.TempDir()
	warmRoot := t.TempDir()
	store := &memLifecycleStore{artifacts: make(map[uuid.UUID]Artifact)}
	manager, err := NewStorageManager(store, hotRoot, warmRoot, "gw-storage")
	if err != nil {
		t.Fatal(err)
	}

	// 1. Expired HOT artifact (never migrated to warm)
	hotArt := createStorageArtifact(t, hotRoot, true)
	hotArt.State = "HOT"
	hotArt.StorageTier = "HOT"
	store.artifacts[hotArt.ID] = hotArt

	if err := manager.RunExpiryBatch(context.Background()); err != nil {
		t.Fatalf("RunExpiryBatch on HOT artifact failed: %v", err)
	}
	if got := store.artifacts[hotArt.ID].State; got != "EXPIRED" {
		t.Fatalf("HOT expired artifact state = %s, want EXPIRED", got)
	}
	if _, err := os.Stat(filepath.Join(hotRoot, hotArt.ID.String()+".wpcap")); !os.IsNotExist(err) {
		t.Fatalf("expired HOT file still exists: %v", err)
	}

	// 2. Crash recovery: EXPIRING artifact with StorageTier == HOT whose hot file was already removed
	expArt := createStorageArtifact(t, hotRoot, true)
	expArt.State = "EXPIRING"
	expArt.StorageTier = "HOT"
	store.artifacts[expArt.ID] = expArt
	if err := os.Remove(filepath.Join(hotRoot, expArt.ID.String()+".wpcap")); err != nil {
		t.Fatal(err)
	}
	if err := manager.RunExpiryBatch(context.Background()); err != nil {
		t.Fatalf("RunExpiryBatch crash recovery on EXPIRING HOT artifact failed: %v", err)
	}
	if got := store.artifacts[expArt.ID].State; got != "EXPIRED" {
		t.Fatalf("recovered EXPIRING HOT artifact state = %s, want EXPIRED", got)
	}
}

func TestStorageMigrateOneResumesMigratingArtifact(t *testing.T) {
	hotRoot := t.TempDir()
	warmRoot := t.TempDir()
	store := &memLifecycleStore{artifacts: make(map[uuid.UUID]Artifact)}
	manager, err := NewStorageManager(store, hotRoot, warmRoot, "gw-storage")
	if err != nil {
		t.Fatal(err)
	}
	manager.MinWarmFreePercent = 1

	art := createStorageArtifact(t, hotRoot, false)
	art.State = "MIGRATING"
	art.StorageTier = "HOT"
	store.artifacts[art.ID] = art

	if err := manager.RunMigrationBatch(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("RunMigrationBatch failed to resume MIGRATING: %v", err)
	}
	if got := store.artifacts[art.ID].State; got != "WARM" {
		t.Fatalf("resumed MIGRATING artifact state = %s, want WARM", got)
	}
}
