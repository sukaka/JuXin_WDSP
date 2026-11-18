package requestpcap

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/database"
)

func TestStorageMigrationAndExpiryIntegration(t *testing.T) {
	dsn := os.Getenv("REQUEST_PCAP_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("REQUEST_PCAP_TEST_PG_DSN not set, skipping real storage integration")
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
	store := NewStore(pool)
	hotRoot := t.TempDir()
	warmRoot := t.TempDir()
	manager, err := NewStorageManager(store, hotRoot, warmRoot, "gw-storage")
	if err != nil {
		t.Fatal(err)
	}
	manager.MinWarmFreePercent = 1

	t.Run("normal migration and idempotent cleanup", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, false)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		candidates, err := store.ListHotArtifacts(ctx, artifact.NodeID, time.Now().Add(time.Minute), 20)
		if err != nil || !containsArtifact(candidates, artifact.ID.String()) {
			t.Fatalf("hot candidate missing: %+v err=%v", candidates, err)
		}
		if err := manager.RunMigrationBatch(ctx, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		assertWarmEvidence(t, store, manager, artifact)
		if err := manager.MigrateOne(ctx, artifact.ID); err != nil {
			t.Fatalf("repeat warm migration must be safe: %v", err)
		}
	})

	t.Run("resume after warm copy before database commit", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, false)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginMigration(ctx, artifact.ID); err != nil {
			t.Fatal(err)
		}
		warmPath := filepath.Join(warmRoot, artifact.ID.String()+".wpcap")
		hotData, err := os.ReadFile(filepath.Join(hotRoot, artifact.ID.String()+".wpcap"))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(warmPath, hotData, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manager.MigrateOne(ctx, artifact.ID); err != nil {
			t.Fatalf("resume valid warm copy: %v", err)
		}
		assertWarmEvidence(t, store, manager, artifact)
	})

	t.Run("tampered warm copy is unavailable and hot evidence retained", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, false)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		if err := store.BeginMigration(ctx, artifact.ID); err != nil {
			t.Fatal(err)
		}
		warmPath := filepath.Join(warmRoot, artifact.ID.String()+".wpcap")
		if err := os.WriteFile(warmPath, bytes.Repeat([]byte{0x5c}, int(artifact.CiphertextSizeBytes)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := manager.MigrateOne(ctx, artifact.ID); err == nil {
			t.Fatal("tampered warm evidence was accepted")
		}
		stored, err := store.GetArtifact(ctx, artifact.ID)
		if err != nil || stored.State != "UNAVAILABLE" {
			t.Fatalf("tampered artifact state=%s err=%v", stored.State, err)
		}
		if _, err := os.Stat(filepath.Join(hotRoot, artifact.ID.String()+".wpcap")); err != nil {
			t.Fatalf("hot evidence was lost after failed migration: %v", err)
		}
	})

	t.Run("expiry deletes file and retains tombstone", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, true)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		if err := manager.MigrateOne(ctx, artifact.ID); err != nil {
			t.Fatal(err)
		}
		expired, err := store.ListExpiredArtifacts(ctx, artifact.NodeID, time.Now(), 20)
		if err != nil || !containsArtifact(expired, artifact.ID.String()) {
			t.Fatalf("expired candidate missing: %+v err=%v", expired, err)
		}
		if err := manager.RunExpiryBatch(ctx); err != nil {
			t.Fatal(err)
		}
		stored, err := store.GetArtifact(ctx, artifact.ID)
		if err != nil || stored.State != "EXPIRED" {
			t.Fatalf("missing expiry tombstone: %s err=%v", stored.State, err)
		}
		if _, err := os.Stat(filepath.Join(warmRoot, artifact.ID.String()+".wpcap")); !os.IsNotExist(err) {
			t.Fatalf("expired file still exists: %v", err)
		}
	})

	t.Run("unexpected missing warm file is not normal expiry", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, true)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		if err := manager.MigrateOne(ctx, artifact.ID); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(warmRoot, artifact.ID.String()+".wpcap")); err != nil {
			t.Fatal(err)
		}
		if err := manager.ExpireOne(ctx, artifact.ID); err == nil {
			t.Fatal("missing warm file was incorrectly marked as normal expiry")
		}
		stored, err := store.GetArtifact(ctx, artifact.ID)
		if err != nil || stored.State != "UNAVAILABLE" {
			t.Fatalf("unexpected missing file state=%s err=%v", stored.State, err)
		}
	})
	t.Run("warm capacity watermark retains hot evidence", func(t *testing.T) {
		artifact := createStorageArtifact(t, hotRoot, false)
		if err := store.CreateArtifact(ctx, artifact); err != nil {
			t.Fatal(err)
		}
		manager.MinWarmFreePercent = 100
		if err := manager.MigrateOne(ctx, artifact.ID); err == nil {
			t.Fatal("migration bypassed warm capacity watermark")
		}
		stored, err := store.GetArtifact(ctx, artifact.ID)
		if err != nil || stored.State != "HOT" {
			t.Fatalf("capacity rejection changed evidence state: %s err=%v", stored.State, err)
		}
		if _, err := os.Stat(filepath.Join(warmRoot, artifact.ID.String()+".wpcap")); !os.IsNotExist(err) {
			t.Fatalf("capacity rejection created a warm file: %v", err)
		}
		manager.MinWarmFreePercent = 10
	})
}

func createStorageArtifact(t *testing.T, hotRoot string, expired bool) Artifact {
	t.Helper()
	artifact := validTestArtifact(t)
	artifact.NodeID = "gw-storage"
	if expired {
		artifact.CaptureEndedAt = time.Now().Add(-time.Hour)
		artifact.CaptureStartedAt = artifact.CaptureEndedAt.Add(-time.Second)
		artifact.ExpiresAt = time.Now().Add(-time.Minute)
	}
	ciphertext := bytes.Repeat([]byte("sealed-evidence-"), 8)
	digest := sha256.Sum256(ciphertext)
	artifact.CiphertextSizeBytes = int64(len(ciphertext))
	artifact.CiphertextSHA256 = hex.EncodeToString(digest[:])
	var manifest map[string]interface{}
	if err := json.Unmarshal(artifact.Manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest["size_encrypted"] = artifact.CiphertextSizeBytes
	manifest["sha256_encrypted"] = artifact.CiphertextSHA256
	segment := manifest["segment"].(map[string]interface{})
	segment["node_id"] = artifact.NodeID
	segment["started_at"] = artifact.CaptureStartedAt
	manifest["ended_at"] = artifact.CaptureEndedAt
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	artifact.Manifest = encoded
	path := filepath.Join(hotRoot, artifact.ID.String()+".wpcap")
	if err := os.WriteFile(path, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}
	return artifact
}

func containsArtifact(artifacts []Artifact, id string) bool {
	for _, artifact := range artifacts {
		if artifact.ID.String() == id {
			return true
		}
	}
	return false
}

func assertWarmEvidence(t *testing.T, store *Store, manager *StorageManager, artifact Artifact) {
	t.Helper()
	stored, err := store.GetArtifact(context.Background(), artifact.ID)
	if err != nil || stored.State != "WARM" || stored.StorageTier != "WARM" {
		t.Fatalf("artifact not WARM: state=%s tier=%s err=%v", stored.State, stored.StorageTier, err)
	}
	if _, err := os.Stat(filepath.Join(manager.hotRoot, artifact.ID.String()+".wpcap")); !os.IsNotExist(err) {
		t.Fatalf("hot replica was not removed after warm commit: %v", err)
	}
	warmPath := filepath.Join(manager.warmRoot, artifact.ID.String()+".wpcap")
	if err := verifyRegularFile(warmPath, artifact.CiphertextSHA256, artifact.CiphertextSizeBytes); err != nil {
		t.Fatalf("warm evidence verification failed: %v", err)
	}
}
