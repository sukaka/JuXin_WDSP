package requestpcap

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
	"github.com/jiuzhang-waf/server/internal/accesslogs"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestSpoolDeliveryRetriesUntilRealAccessLogArrives(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real spool integration")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatal(err)
	}
	seed, oldService, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	content, err := os.ReadFile(filepath.Join(oldService.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	requestID := "req-spool-real"
	traceID := "0123456789abcdef0123456789abcdef"
	record := spoolRecord{Manifest: seed.artifact.Manifest, KeyID: seed.artifact.KeyID, WrappedKey: seed.artifact.WrappedDEK,
		Requests: []pcapevidence.RequestEvidence{{RequestID: requestID, TraceID: traceID, ConnectionID: string(bytesRepeat('a', 64)),
			ObservedAt: time.Now().UTC(), CapturePoint: "GATEWAY_EGRESS", Method: "POST", Path: "/v1/login", FirstPacketNo: 2, LastPacketNo: 2}}}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	sidecarPath := filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap.json")
	if err := os.WriteFile(sidecarPath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	collector, err := NewSpoolCollector(store, hotRoot, seed.artifact.NodeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sidecarPath); err != nil {
		t.Fatalf("sidecar was removed before the real access log arrived: %v", err)
	}
	if _, err := store.ListRequestLinks(ctx, requestID); err != nil {
		t.Fatal(err)
	}
	manager, err := NewStorageManager(store, hotRoot, t.TempDir(), seed.artifact.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	manager.MinWarmFreePercent = 1
	if err := manager.MigrateOne(ctx, seed.artifact.ID); err != nil {
		t.Fatalf("migrate pending evidence before log arrival: %v", err)
	}
	if _, err := os.Stat(filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap")); !os.IsNotExist(err) {
		t.Fatalf("hot replica still exists after migration: %v", err)
	}
	logEntry := &accesslogs.LogEntry{OccurredAt: time.Now().UTC(), RequestID: requestID, RequestMethod: "POST", RequestPath: "/v1/login", TraceID: traceID,
		RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}}
	if _, err := accesslogs.NewStore(pool).Insert(ctx, logEntry); err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	links, err := store.ListRequestLinks(ctx, requestID)
	if err != nil || len(links) != 1 || links[0].ArtifactID != seed.artifact.ID || links[0].FirstPacketNo == nil || *links[0].FirstPacketNo != 2 {
		t.Fatalf("real spool link incorrect: %+v err=%v", links, err)
	}
	if _, err := os.Stat(sidecarPath); !os.IsNotExist(err) {
		t.Fatalf("delivered sidecar still exists: %v", err)
	}
	if collector.Stats().Delivered != 1 || collector.Stats().Pending != 1 || collector.Stats().Errors != 0 {
		t.Fatalf("unexpected spool counters: %+v", collector.Stats())
	}
}

func bytesRepeat(value byte, count int) []byte {
	result := make([]byte, count)
	for i := range result {
		result[i] = value
	}
	return result
}

func TestSpoolRejectsTamperedCiphertext(t *testing.T) {
	seed, oldService, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	path := filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap")
	content, err := os.ReadFile(filepath.Join(oldService.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	content[len(content)-1] ^= 1
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(spoolRecord{Manifest: seed.artifact.Manifest, KeyID: seed.artifact.KeyID, WrappedKey: seed.artifact.WrappedDEK})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".json", encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	store := &spoolRejectStore{}
	collector := &SpoolCollector{store: store, hotRoot: hotRoot, nodeID: seed.artifact.NodeID, retention: time.Hour}
	if err := collector.collect(context.Background(), seed.artifact.ID.String()+".wpcap.json"); err == nil {
		t.Fatal("tampered ciphertext was accepted into the spool")
	}
	if store.called {
		t.Fatal("tampered ciphertext reached the store")
	}
	if _, err := os.Stat(path + ".json"); err != nil {
		t.Fatalf("tampered evidence sidecar was discarded before review: %v", err)
	}
}

type spoolRejectStore struct{ called bool }

func (s *spoolRejectStore) GetArtifact(context.Context, uuid.UUID) (Artifact, error) {
	return Artifact{}, ErrArtifactNotFound
}

func (s *spoolRejectStore) CreateArtifact(context.Context, Artifact) error {
	s.called = true
	return errors.New("unexpected artifact insert")
}

func (s *spoolRejectStore) RecordCapturedRequest(context.Context, uuid.UUID, CapturedRequest) error {
	s.called = true
	return errors.New("unexpected request link")
}

func TestSupplementalSpoolUsesOriginalArtifactIdentity(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real supplemental spool test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool, "../../migrations", "up"); err != nil {
		t.Fatal(err)
	}
	seed, oldService, _ := newServiceFixture(t)
	hotRoot := t.TempDir()
	content, err := os.ReadFile(filepath.Join(oldService.hotRoot, seed.artifact.ID.String()+".wpcap"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hotRoot, seed.artifact.ID.String()+".wpcap"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewStore(pool)
	if err := store.CreateArtifact(ctx, seed.artifact); err != nil {
		t.Fatal(err)
	}
	requestID := "req-supplemental"
	if _, err := accesslogs.NewStore(pool).Insert(ctx, &accesslogs.LogEntry{OccurredAt: time.Now().UTC(), RequestID: requestID,
		RequestMethod: "POST", RequestPath: "/v1/login", RequestHeaders: map[string][]string{}, ResponseHeaders: map[string][]string{}}); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(spoolRecord{Manifest: seed.artifact.Manifest, KeyID: seed.artifact.KeyID, WrappedKey: seed.artifact.WrappedDEK,
		Requests: []pcapevidence.RequestEvidence{{RequestID: requestID, ConnectionID: string(bytesRepeat('b', 64)), ObservedAt: time.Now().UTC(),
			CapturePoint: "GATEWAY_EGRESS", Method: "POST", Path: "/v1/login", FirstPacketNo: 2, LastPacketNo: 2}}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(hotRoot, seed.artifact.ID.String()+"."+uuid.NewString()+".wpcap.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	collector, err := NewSpoolCollector(store, hotRoot, seed.artifact.NodeID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if err := collector.CollectOnce(ctx); err != nil {
		t.Fatal(err)
	}
	links, err := store.ListRequestLinks(ctx, requestID)
	if err != nil || len(links) != 1 || links[0].ArtifactID != seed.artifact.ID || links[0].FirstPacketNo == nil || *links[0].FirstPacketNo != 2 {
		t.Fatalf("supplemental evidence linked incorrectly: %+v err=%v", links, err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("delivered supplemental sidecar remains: %v", err)
	}
}
