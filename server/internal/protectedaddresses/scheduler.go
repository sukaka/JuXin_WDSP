package protectedaddresses

import (
	"context"
	"log/slog"
	"time"
)

// DefaultRefreshInterval 保护地址自动维护默认刷新周期。
const DefaultRefreshInterval = time.Hour

// RefreshIntervalEnv 刷新周期环境变量（time.ParseDuration 格式，如 30m/1h）。
const RefreshIntervalEnv = "PROTECTED_ADDRESS_REFRESH_INTERVAL"

// RefreshIntervalFromEnv 解析刷新周期：空或非法值回退默认，非正值回退默认。
func RefreshIntervalFromEnv(getenv func(string) string) time.Duration {
	if v := getenv(RefreshIntervalEnv); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return DefaultRefreshInterval
}

// RefreshStore 是 Refresher 依赖的刷新接口（Store 已实现；测试可注入假实现）。
type RefreshStore interface {
	Refresh(ctx context.Context) (added, skipped int, err error)
}

// Refresher 保护地址自动维护调度器：启动时执行一次 Refresh，之后按周期刷新。
type Refresher struct {
	store    RefreshStore
	interval time.Duration
}

// NewRefresher 创建调度器；interval 非正值时使用默认周期。
func NewRefresher(store RefreshStore, interval time.Duration) *Refresher {
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	return &Refresher{store: store, interval: interval}
}

// Interval 返回实际生效的刷新周期。
func (r *Refresher) Interval() time.Duration { return r.interval }

// Run 阻塞运行直到 ctx 取消。启动时立即刷新一次，之后按周期刷新；
// 单次刷新失败仅记错误日志，不退出循环。
func (r *Refresher) Run(ctx context.Context) {
	r.refreshOnce(ctx)
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.refreshOnce(ctx)
		}
	}
}

func (r *Refresher) refreshOnce(ctx context.Context) {
	added, skipped, err := r.store.Refresh(ctx)
	if err != nil {
		slog.Error("protected addresses auto refresh failed", "error", err)
		return
	}
	slog.Info("protected addresses auto refreshed", "added", added, "skipped", skipped)
}
