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
	"sync"
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

const (
	defaultSpoolRetryTTL   = 10 * time.Minute
	spoolDeliverBatchLimit = 64
	spoolScanBatchLimit    = 1024
)

type SpoolStats struct {
	Scanned     uint64
	Delivered   uint64
	Pending     uint64
	Errors      uint64
	Quarantined uint64
}

type spoolStore interface {
	GetArtifact(context.Context, uuid.UUID) (Artifact, error)
	CreateArtifact(context.Context, Artifact) error
	RecordCapturedRequest(context.Context, uuid.UUID, CapturedRequest) error
}

type SpoolCollector struct {
	store       spoolStore
	hotRoot     string
	nodeID      string
	retention   time.Duration
	retryTTL    time.Duration
	now         func() time.Time
	mu          sync.Mutex
	scanCursor  int
	scanned     atomic.Uint64
	delivered   atomic.Uint64
	pending     atomic.Uint64
	errors      atomic.Uint64
	quarantined atomic.Uint64
}

func NewSpoolCollector(store spoolStore, hotRoot, nodeID string, retention time.Duration) (*SpoolCollector, error) {
	if store == nil || !filepath.IsAbs(hotRoot) || nodeID == "" || retention <= 0 {
		return nil, fmt.Errorf("evidence store, absolute hot root, node and positive retention are required")
	}
	if stat, err := os.Stat(hotRoot); err != nil || !stat.IsDir() {
		return nil, fmt.Errorf("evidence spool root is unavailable")
	}
	return &SpoolCollector{store: store, hotRoot: filepath.Clean(hotRoot), nodeID: nodeID, retention: retention, retryTTL: defaultSpoolRetryTTL, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (c *SpoolCollector) currentTime() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now().UTC()
}

func (c *SpoolCollector) effectiveRetryTTL() time.Duration {
	if c.retryTTL > 0 {
		return c.retryTTL
	}
	return defaultSpoolRetryTTL
}

func (c *SpoolCollector) Stats() SpoolStats {
	return SpoolStats{
		Scanned:     c.scanned.Load(),
		Delivered:   c.delivered.Load(),
		Pending:     c.pending.Load(),
		Errors:      c.errors.Load(),
		Quarantined: c.quarantined.Load(),
	}
}

func (c *SpoolCollector) CollectOnce(ctx context.Context) error {
	entries, err := os.ReadDir(c.hotRoot)
	if err != nil {
		return err
	}
	candidates := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".wpcap.json") {
			continue
		}
		candidates = append(candidates, entry)
	}
	if len(candidates) == 0 {
		c.mu.Lock()
		c.scanCursor = 0
		c.mu.Unlock()
		return nil
	}

	c.mu.Lock()
	start := c.scanCursor % len(candidates)
	c.mu.Unlock()

	now := c.currentTime()
	retryTTL := c.effectiveRetryTTL()
	scanned := 0
	delivered := 0
	var errs []error
	for i := 0; i < len(candidates) && scanned < spoolScanBatchLimit && delivered < spoolDeliverBatchLimit; i++ {
		if ctx.Err() != nil {
			break
		}
		entry := candidates[(start+i)%len(candidates)]
		scanned++
		c.scanned.Add(1)
		if err := c.collect(ctx, entry.Name()); err != nil {
			if info, infoErr := entry.Info(); infoErr == nil && now.Sub(info.ModTime()) > retryTTL {
				c.quarantineSidecar(entry.Name(), err)
				if !errors.Is(err, ErrRequestAuditNotFound) {
					c.errors.Add(1)
					errs = append(errs, fmt.Errorf("collect %s (quarantined): %w", entry.Name(), err))
				}
				continue
			}
			if errors.Is(err, ErrRequestAuditNotFound) {
				c.pending.Add(1)
				continue
			}
			c.errors.Add(1)
			errs = append(errs, fmt.Errorf("collect %s: %w", entry.Name(), err))
			continue
		}
		delivered++
	}

	c.mu.Lock()
	c.scanCursor = (start + scanned) % len(candidates)
	c.mu.Unlock()
	return errors.Join(errs...)
}

func (c *SpoolCollector) quarantineSidecar(name string, cause error) {
	src := filepath.Join(c.hotRoot, name)
	dst := src + ".quarantined"
	if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
		slog.Warn("quarantine expired PCAP spool sidecar failed", "file", name, "error", err, "cause", cause)
		return
	}
	c.quarantined.Add(1)
	slog.Warn("quarantined expired PCAP spool sidecar", "file", name, "cause", cause)
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
	var pendingCount int
	var permanentErrs []error
	for _, request := range record.Requests {
		if request.CapturePoint != "GATEWAY_EGRESS" {
			permanentErrs = append(permanentErrs, fmt.Errorf("untrusted capture point cannot be correlated for request %s", request.RequestID))
			continue
		}
		if err := c.store.RecordCapturedRequest(ctx, artifact.ID, CapturedRequest(request)); err != nil {
			if errors.Is(err, ErrRequestAuditNotFound) {
				pendingCount++
				continue
			}
			permanentErrs = append(permanentErrs, fmt.Errorf("correlate request %s: %w", request.RequestID, err))
		}
	}
	if len(permanentErrs) > 0 {
		return errors.Join(permanentErrs...)
	}
	if pendingCount > 0 {
		return ErrRequestAuditNotFound
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
