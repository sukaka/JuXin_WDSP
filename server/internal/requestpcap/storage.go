package requestpcap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
)

// StorageManager 执行证据文件迁移与到期；仅按UUID访问受控根目录，不接受任意路径。
type StorageManager struct {
	store                 ArtifactLifecycleStore
	nodeID                string
	hotRoot               string
	warmRoot              string
	now                   func() time.Time
	MaxArtifactBytes      int64
	MigrateBytesPerSecond int64
	MinWarmFreePercent    int
}

func NewStorageManager(store ArtifactLifecycleStore, hotRoot, warmRoot, nodeID string) (*StorageManager, error) {
	if store == nil || nodeID == "" || !filepath.IsAbs(hotRoot) || !filepath.IsAbs(warmRoot) || filepath.Clean(hotRoot) == filepath.Clean(warmRoot) {
		return nil, fmt.Errorf("evidence store, node and distinct absolute hot/warm roots are required")
	}
	for _, root := range []string{hotRoot, warmRoot} {
		stat, err := os.Stat(root)
		if err != nil || !stat.IsDir() {
			return nil, fmt.Errorf("evidence storage root is unavailable")
		}
	}
	return &StorageManager{
		store: store, nodeID: nodeID, hotRoot: filepath.Clean(hotRoot), warmRoot: filepath.Clean(warmRoot),
		now: time.Now, MaxArtifactBytes: 4 << 30, MigrateBytesPerSecond: 32 << 20, MinWarmFreePercent: 10,
	}, nil
}

func (m *StorageManager) MigrateOne(ctx context.Context, id uuid.UUID) error {
	artifact, err := m.store.GetArtifact(ctx, id)
	if err != nil {
		return err
	}
	if artifact.NodeID != m.nodeID {
		return fmt.Errorf("evidence belongs to a different gateway node")
	}
	if artifact.CiphertextSizeBytes <= 0 || artifact.CiphertextSizeBytes > m.MaxArtifactBytes {
		return fmt.Errorf("evidence size exceeds migration limit")
	}
	if artifact.State == "WARM" {
		return m.cleanupHotReplica(ctx, artifact)
	}
	if artifact.State != "HOT" && artifact.State != "MIGRATING" {
		return fmt.Errorf("evidence state %s cannot migrate", artifact.State)
	}
	hotPath, warmPath, err := m.paths(artifact.ID)
	if err != nil {
		return err
	}
	if err := m.checkWarmCapacity(artifact.CiphertextSizeBytes); err != nil {
		return err
	}
	if artifact.State == "HOT" {
		if err := m.store.BeginMigration(ctx, artifact.ID); err != nil {
			return err
		}
	}
	warmReady := false
	if _, err := os.Lstat(warmPath); err == nil {
		if err := verifyRegularFile(warmPath, artifact.CiphertextSHA256, artifact.CiphertextSizeBytes); err != nil {
			_ = m.store.MarkUnavailable(ctx, artifact.ID)
			return fmt.Errorf("existing warm evidence failed verification: %w", err)
		}
		warmReady = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if !warmReady {
		if err := copyArtifactFile(ctx, hotPath, warmPath, artifact.CiphertextSHA256, artifact.CiphertextSizeBytes, m.MigrateBytesPerSecond); err != nil {
			if ctx.Err() == nil {
				_ = m.store.MarkUnavailable(ctx, artifact.ID)
			}
			return err
		}
	}
	if err := m.store.CompleteMigration(ctx, artifact.ID, artifact.CiphertextSHA256); err != nil {
		return err
	}
	if err := removeRegularIfExists(hotPath); err != nil {
		return fmt.Errorf("remove hot evidence after warm commit: %w", err)
	}
	return nil
}

func (m *StorageManager) cleanupHotReplica(ctx context.Context, artifact Artifact) error {
	_, warmPath, err := m.paths(artifact.ID)
	if err != nil {
		return err
	}
	if err := verifyRegularFile(warmPath, artifact.CiphertextSHA256, artifact.CiphertextSizeBytes); err != nil {
		_ = m.store.MarkUnavailable(ctx, artifact.ID)
		return fmt.Errorf("warm evidence unavailable during hot cleanup: %w", err)
	}
	hotPath, _, _ := m.paths(artifact.ID)
	return removeRegularIfExists(hotPath)
}

func (m *StorageManager) ExpireOne(ctx context.Context, id uuid.UUID) error {
	artifact, err := m.store.GetArtifact(ctx, id)
	if err != nil {
		return err
	}
	if artifact.NodeID != m.nodeID {
		return fmt.Errorf("evidence belongs to a different gateway node")
	}
	if m.now().Before(artifact.ExpiresAt) {
		return nil
	}
	wasExpiring := artifact.State == "EXPIRING"
	if artifact.State != "WARM" && !wasExpiring {
		return fmt.Errorf("evidence state %s cannot expire", artifact.State)
	}
	if !wasExpiring {
		if err := m.store.BeginExpiry(ctx, artifact.ID); err != nil {
			return err
		}
	}
	_, warmPath, err := m.paths(artifact.ID)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(warmPath); err != nil {
		if os.IsNotExist(err) && wasExpiring {
			// 已有删除意图，允许在崩溃恢复时确认文件已不再存在。
			return m.store.CompleteExpiry(ctx, artifact.ID)
		}
		_ = m.store.MarkUnavailable(ctx, artifact.ID)
		return fmt.Errorf("expired evidence is unexpectedly missing: %w", err)
	}
	if err := removeRegularIfExists(warmPath); err != nil {
		_ = m.store.MarkUnavailable(ctx, artifact.ID)
		return fmt.Errorf("delete expired evidence: %w", err)
	}
	return m.store.CompleteExpiry(ctx, artifact.ID)
}

func (m *StorageManager) RunMigrationBatch(ctx context.Context, before time.Time) error {
	artifacts, err := m.store.ListHotArtifacts(ctx, m.nodeID, before, 20)
	if err != nil {
		return err
	}
	var errs []error
	for _, artifact := range artifacts {
		if err := m.MigrateOne(ctx, artifact.ID); err != nil {
			errs = append(errs, fmt.Errorf("migrate %s: %w", artifact.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (m *StorageManager) RunExpiryBatch(ctx context.Context) error {
	artifacts, err := m.store.ListExpiredArtifacts(ctx, m.nodeID, m.now(), 20)
	if err != nil {
		return err
	}
	var errs []error
	for _, artifact := range artifacts {
		if err := m.ExpireOne(ctx, artifact.ID); err != nil {
			errs = append(errs, fmt.Errorf("expire %s: %w", artifact.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (m *StorageManager) paths(id uuid.UUID) (string, string, error) {
	if id == uuid.Nil {
		return "", "", fmt.Errorf("evidence id is required")
	}
	name := id.String() + ".wpcap"
	return filepath.Join(m.hotRoot, name), filepath.Join(m.warmRoot, name), nil
}

func copyArtifactFile(ctx context.Context, hotPath, warmPath, expectedHash string, expectedSize int64, bytesPerSecond int64) error {
	source, err := openRegularFile(hotPath)
	if err != nil {
		return fmt.Errorf("open hot evidence: %w", err)
	}
	defer source.Close()
	if stat, err := source.Stat(); err != nil || stat.Size() != expectedSize {
		return fmt.Errorf("hot evidence size does not match manifest")
	}
	temporary := warmPath + ".tmp"
	if err := removeRegularIfExists(temporary); err != nil && !os.IsNotExist(err) {
		return err
	}
	target, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create warm temporary evidence: %w", err)
	}
	ok := false
	defer func() {
		_ = target.Close()
		if !ok {
			_ = os.Remove(temporary)
		}
	}()
	hash := sha256.New()
	throttled := &throttledWriter{writer: target, rate: bytesPerSecond}
	written, err := io.Copy(io.MultiWriter(throttled, hash), contextReader{ctx: ctx, reader: source})
	if err != nil {
		return fmt.Errorf("copy evidence: %w", err)
	}
	if written != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return fmt.Errorf("copied evidence does not match sealed hash")
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("sync warm evidence: %w", err)
	}
	if err := target.Close(); err != nil {
		return fmt.Errorf("close warm evidence: %w", err)
	}
	if err := os.Link(temporary, warmPath); err != nil {
		return fmt.Errorf("publish warm evidence without overwrite: %w", err)
	}
	if err := os.Remove(temporary); err != nil {
		return fmt.Errorf("remove warm temporary link: %w", err)
	}
	ok = true
	return nil
}

func verifyRegularFile(path, expectedHash string, expectedSize int64) error {
	file, err := openRegularFile(path)
	if err != nil {
		return err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || stat.Size() != expectedSize {
		return fmt.Errorf("evidence file size mismatch")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedHash {
		return fmt.Errorf("evidence SHA-256 mismatch")
	}
	return nil
}

func openRegularFile(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return nil, fmt.Errorf("evidence is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		_ = file.Close()
		return nil, fmt.Errorf("evidence file changed or is not regular")
	}
	return file, nil
}

func removeRegularIfExists(path string) error {
	stat, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() && stat.Mode()&os.ModeSymlink == 0 {
		return fmt.Errorf("refusing to remove non-regular evidence path")
	}
	return os.Remove(path)
}
