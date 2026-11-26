// syncer.go XDP 加速单次同步与 fail-open 后台周期同步器。
package xdpaccel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Syncer 负责将控制面全局 IP 黑名单与全局临时封禁安全过滤后同步至本地 xdpguard 守护进程。
type Syncer struct {
	store  Repository
	client DaemonClient
	mu     sync.Mutex
}

// NewSyncer 创建 XDP 同步器。
func NewSyncer(store Repository, client DaemonClient) *Syncer {
	if client == nil {
		client = NewUnixClient(defaultStatusTimeout, defaultSyncTimeout)
	}
	return &Syncer{
		store:  store,
		client: client,
	}
}

// SyncOnce 读取当前 XDP 配置、全局黑名单/全局临时封禁与保护地址，执行控制面重叠过滤后
// 通过 Unix Socket 下发 POST /v1/sync。
// 当 enabled=false 时发送 enabled:false 与空 blocked_cidrs，通知 xdpguard 安全卸载网卡 XDP 程序并清空映射。
func (s *Syncer) SyncOnce(ctx context.Context) (*SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfg, err := s.store.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("load xdp config: %w", err)
	}
	if msg := s.client.ValidateSocketPath(cfg.SocketPath); msg != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSocketPath, msg)
	}

	req := SyncRequest{
		SchemaVersion:  SchemaVersion,
		Enabled:        cfg.Enabled,
		AttachMode:     cfg.AttachMode,
		Interfaces:     nonNilStrings(cfg.Interfaces),
		BlockedCIDRs:   []string{},
		ProtectedCIDRs: []string{},
	}

	var controlPlaneExcluded int
	if cfg.Enabled {
		blacklistAddrs, tempBlockIPs, protectedAddrs, err := s.store.LoadGlobalBlockSources(ctx)
		if err != nil {
			return nil, fmt.Errorf("load xdp global block sources: %w", err)
		}
		blocked, protected, excluded := FilterBlocklist(blacklistAddrs, tempBlockIPs, protectedAddrs)
		req.BlockedCIDRs = blocked
		req.ProtectedCIDRs = protected
		controlPlaneExcluded = excluded
	}

	resp, err := s.client.PushSync(ctx, cfg.SocketPath, req)
	if err != nil {
		return nil, err
	}
	return &SyncResult{
		Synced:                    resp.Synced,
		Mode:                      resp.Mode,
		KernelAttached:            resp.KernelAttached,
		AttachedInterfaces:        nonNilStrings(resp.AttachedInterfaces),
		SyncedV4CIDRs:             resp.SyncedV4CIDRs,
		SyncedV6CIDRs:             resp.SyncedV6CIDRs,
		ExcludedProtectedCount:    resp.ExcludedProtectedCount,
		ControlPlaneExcludedCount: controlPlaneExcluded,
		InvalidCIDRsSkipped:       resp.InvalidCIDRsSkipped,
		LastSyncAt:                resp.LastSyncAt,
		Error:                     resp.Error,
	}, nil
}

// StartLoop 启动轻量级 fail-open 周期同步循环：
//   - 仅在 xdp_acceleration.enabled=true 时周期向 xdpguard 推送同步；关闭时空转不访问 Socket；
//   - 动态遵循 sync_interval_seconds（1..300s）；
//   - 任何数据库或守护进程不可达异常仅记日志并降级重试，绝不阻塞或导致管理服务崩溃。
func (s *Syncer) StartLoop(ctx context.Context) {
	if s == nil || s.store == nil || s.client == nil {
		return
	}
	interval := time.Duration(DefaultSyncIntervalSeconds) * time.Second
	timer := time.NewTimer(interval)
	defer timer.Stop()

	var lastErr string
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			nextInterval := time.Duration(DefaultSyncIntervalSeconds) * time.Second
			cfg, err := s.store.GetConfig(ctx)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				errStr := err.Error()
				if errStr != lastErr {
					slog.Warn("xdp acceleration sync loop failed to load config", "error", err)
					lastErr = errStr
				} else {
					slog.Debug("xdp acceleration sync loop failed to load config", "error", err)
				}
				timer.Reset(nextInterval)
				continue
			}

			if cfg.SyncIntervalSeconds >= MinSyncIntervalSeconds && cfg.SyncIntervalSeconds <= MaxSyncIntervalSeconds {
				nextInterval = time.Duration(cfg.SyncIntervalSeconds) * time.Second
			}

			if cfg.Enabled {
				syncCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
				res, syncErr := s.SyncOnce(syncCtx)
				cancel()
				if syncErr != nil {
					if ctx.Err() != nil {
						return
					}
					errStr := syncErr.Error()
					if errStr != lastErr {
						slog.Warn("xdp acceleration periodic sync failed (fail-open)", "error", syncErr)
						lastErr = errStr
					} else {
						slog.Debug("xdp acceleration periodic sync failed (fail-open)", "error", syncErr)
					}
				} else {
					if lastErr != "" {
						slog.Info("xdp acceleration periodic sync recovered",
							"mode", res.Mode,
							"kernel_attached", res.KernelAttached,
							"synced_v4_cidrs", res.SyncedV4CIDRs,
							"synced_v6_cidrs", res.SyncedV6CIDRs,
						)
						lastErr = ""
					}
					if !res.Synced && res.Error != "" {
						slog.Debug("xdp acceleration periodic sync completed in fallback mode",
							"mode", res.Mode, "error", res.Error)
					}
				}
			} else {
				lastErr = ""
			}

			timer.Reset(nextInterval)
		}
	}
}
