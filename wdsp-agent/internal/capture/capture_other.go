//go:build !linux

// 非 Linux 平台桩：AF_PACKET 不可用（TASK-004 为 Linux 专用）。
// 桩模式返回 ErrUnsupported，上层降级为仅控制通道运行（心跳/配置），进程不退出。
package capture

import (
	"log/slog"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// Handle 桩句柄。
type Handle struct{}

// Start 桩：返回 ErrUnsupported。
func Start(iface string, filt *filter.Filter, consumer func(Packet), st *Stats, log *slog.Logger) (*Handle, error) {
	return nil, ErrUnsupported
}

// KernelStats 桩。
func (h *Handle) KernelStats() (packets, drops uint32, err error) { return 0, 0, ErrUnsupported }

// Close 桩。
func (h *Handle) Close() error { return nil }
