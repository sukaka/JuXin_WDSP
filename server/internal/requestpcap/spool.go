package requestpcap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/gateway/pcapevidence"
)

type spoolRecord struct {
	Manifest   json.RawMessage                `json:"manifest"`
	KeyID      string                         `json:"key_id"`
	WrappedKey []byte                         `json:"wrapped_key"`
	Requests   []pcapevidence.RequestEvidence `json:"requests,omitempty"`
}

type SpoolStats struct {
	Scanned   uint64
	Delivered uint64
	Pending   uint64
	Errors    uint64
}

type spoolStore interface {
	GetArtifact(context.Context, uuid.UUID) (Artifact, error)
	CreateArtifact(context.Context, Artifact) error
	RecordCapturedRequest(context.Context, uuid.UUID, CapturedRequest) error
}

type SpoolCollector struct {
	store     spoolStore
	hotRoot   string
	nodeID    string
	retention time.Duration
	now       func() time.Time
	scanned   atomic.Uint64
	delivered atomic.Uint64
	pending   atomic.Uint64
	errors    atomic.Uint64
}

func NewSpoolCollector(store spoolStore, hotRoot, nodeID string, retention time.Duration) (*SpoolCollector, error) {
	if store == nil || !filepath.IsAbs(hotRoot) || nodeID == "" || retention <= 0 {
		return nil, fmt.Errorf("evidence store, absolute hot root, node and positive retention are required")
	}
	if stat, err := os.Stat(hotRoot); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("evidence spool root is unavailable")
	}
	return &SpoolCollector{store: store, hotRoot: filepath.Clean(hotRoot), nodeID: nodeID, retention: retention, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *SpoolCollector) Stats() SpoolStats {
	return SpoolStats{Scanned: c.scanned.Load(), Delivered: c.delivered.Load(), Pending: c.pending.Load(), Errors: c.errors.Load()}
}

func (c *SpoolCollector) CollectOnce(ctx context.Context) error {
	entries, err := os.ReadDir(c.hotRoot)
	if err != nil {
		return err
	}
	processed := 0
	var errs []error
	for _, entry := range entries {
		if processed >= 64 {
			break
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wpcap.json") {
			continue
		}
		processed++
		c.scanned.Add(1)
		if err := c.collect(ctx, entry.Name()); err != nil {
			if errors.Is(err, ErrRequestAuditNotFound) {
				c.pending.Add(1)
				continue
			}
			c.errors.Add(1)
			errs = append(errs, fmt.Errorf("collect %s: %w", entry.Name(), err))
		}
	}
	return errors.Join(errs...)
}

func (c *SpoolCollector) collect(ctx context.Context, name string) error {
	baseName := strings.TrimSuffix(name, ".wpcap.json")
	artifactName := baseName
	if separator := strings.IndexByte(baseName, '.'); separator >= 0 {
		artifactName = baseName[:separator]
		if _, err := uuid.Parse(baseName[separator+1:]); err != nil {
			return fmt.Errorf("invalid supplemental evidence name")
		}
	}
	artifactID, err := uuid.Parse(artifactName)
	if err != nil {
		return fmt.Errorf("invalid spool evidence name")
	}
	path := filepath.Join(c.hotRoot, name)
	file, err := openRegularFile(path)
	if err != nil {
		return err
	}
	payload, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	closeErr := file.Close()
	if err != nil || closeErr != nil || len(payload) > 1<<20 {
		return fmt.Errorf("invalid or oversized evidence sidecar")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var record spoolRecord
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("invalid evidence sidecar: %w", err)
	}
	if decoder.More() {
		return fmt.Errorf("evidence sidecar contains trailing content")
	}
	projection, err := decodeManifest(record.Manifest)
	if err != nil {
		return err
	}
	artifact, err := ArtifactFromManifest(record.Manifest, record.WrappedKey, record.KeyID, projection.EndedAt.Add(c.retention))
	if err != nil {
		return err
	}
	if artifact.ID != artifactID || artifact.NodeID != c.nodeID {
		return fmt.Errorf("spool evidence identity or node mismatch")
	}
	existing, getErr := c.store.GetArtifact(ctx, artifact.ID)
	switch {
	case getErr == nil:
		// 已登记证据可能已迁移到温层；重放只校验不可变事实，不再要求热文件存在。
		artifact.ExpiresAt = existing.ExpiresAt
	case errors.Is(getErr, ErrArtifactNotFound):
		if err := verifyRegularFile(filepath.Join(c.hotRoot, artifact.ID.String()+".wpcap"), artifact.CiphertextSHA256, artifact.CiphertextSizeBytes); err != nil {
			return err
		}
	default:
		return getErr
	}
	if err := c.store.CreateArtifact(ctx, artifact); err != nil {
		return err
	}
	for _, request := range record.Requests {
		if request.CapturePoint != "GATEWAY_EGRESS" {
			return fmt.Errorf("untrusted capture point cannot be correlated")
		}
		if err := c.store.RecordCapturedRequest(ctx, artifact.ID, CapturedRequest(request)); err != nil {
			return err
		}
	}
	if err := removeRegularIfExists(path); err != nil {
		return err
	}
	c.delivered.Add(1)
	return nil
}

func (c *SpoolCollector) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := c.CollectOnce(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("request PCAP spool collection failed", "node", c.nodeID, "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
