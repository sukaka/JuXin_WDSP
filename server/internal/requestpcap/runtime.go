package requestpcap

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/config"
	"github.com/jiuzhang-waf/server/internal/encryption"
)

type Runtime struct {
	Store     *Store
	Keyring   *Keyring
	Collector *SpoolCollector
	Storage   *StorageManager
	hotAge    time.Duration
	grantTTL  time.Duration
	grantPath string
	trustPath string
	rotateMu  sync.Mutex
}

func NewRuntime(db *pgxpool.Pool, cfg config.RequestPCAPConfig, nodeID string, encryption *encryption.Service) (*Runtime, error) {
	if db == nil || !cfg.Enabled() || encryption == nil {
		return nil, fmt.Errorf("database, complete request PCAP configuration and encryption are required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	keyring, err := LoadOrCreateKeyring(cfg.KeyFile, encryption)
	if err != nil {
		return nil, err
	}
	store := NewStore(db)
	collector, err := NewSpoolCollector(store, cfg.HotDir, nodeID, cfg.Retention)
	if err != nil {
		keyring.Close()
		return nil, err
	}
	storage, err := NewStorageManager(store, cfg.HotDir, cfg.WarmDir, nodeID)
	if err != nil {
		keyring.Close()
		return nil, err
	}
	storage.MigrateBytesPerSecond = cfg.MigrateBytesPerSecond
	storage.MinWarmFreePercent = cfg.MinFreePercent
	publicDir := cfg.PublicDir
	if publicDir == "" {
		publicDir = filepath.Dir(cfg.KeyFile)
	}
	runtime := &Runtime{Store: store, Keyring: keyring, Collector: collector, Storage: storage,
		hotAge: cfg.HotAge, grantTTL: cfg.GrantTTL, grantPath: filepath.Join(publicDir, "pcap-public.json"),
		trustPath: filepath.Join(publicDir, "pcap-release.pub")}
	if err := runtime.publishGrant(time.Now().UTC()); err != nil {
		keyring.Close()
		return nil, err
	}
	return runtime, nil
}

func (r *Runtime) Rotate() error {
	r.rotateMu.Lock()
	defer r.rotateMu.Unlock()
	if err := r.Keyring.Rotate(); err != nil {
		return err
	}
	return r.Keyring.WritePublicGrant(r.grantPath, r.trustPath, r.Storage.nodeID, time.Now().UTC(), r.grantTTL)
}

func (r *Runtime) publishGrant(now time.Time) error {
	r.rotateMu.Lock()
	defer r.rotateMu.Unlock()
	return r.Keyring.WritePublicGrant(r.grantPath, r.trustPath, r.Storage.nodeID, now, r.grantTTL)
}

func (r *Runtime) Run(ctx context.Context) {
	spoolTicker := time.NewTicker(2 * time.Second)
	storageTicker := time.NewTicker(30 * time.Second)
	grantInterval := r.grantTTL / 3
	if grantInterval <= 0 {
		grantInterval = time.Hour
	}
	grantTicker := time.NewTicker(grantInterval)
	defer spoolTicker.Stop()
	defer storageTicker.Stop()
	defer grantTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Keyring.Close()
			return
		case <-spoolTicker.C:
			if err := r.Collector.CollectOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("request PCAP delivery failed", "error", err)
			}
		case <-storageTicker.C:
			if err := r.Storage.RunMigrationBatch(ctx, time.Now().UTC().Add(-r.hotAge)); err != nil && ctx.Err() == nil {
				slog.Warn("request PCAP migration failed", "error", err)
			}
			if err := r.Storage.RunExpiryBatch(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("request PCAP expiry failed", "error", err)
			}
		case <-grantTicker.C:
			if err := r.publishGrant(time.Now().UTC()); err != nil && ctx.Err() == nil {
				slog.Error("request PCAP public key grant renewal failed", "error", err)
			}
		}
	}
}
