//go:build !linux

// 非 Linux 平台桩：AF_PACKET 为 Linux 专有，其他平台给出明确错误（不静默）。
package mirrorcap

import (
	"errors"
)

// Capture 非 Linux 平台不可用。
type Capture struct{}

// NewCapture 非 Linux 平台直接失败并提示。
func NewCapture(cfg Config, consumer IfaceConsumer, stats *Stats) (*Capture, error) {
	return nil, errors.New("mirrorcap 抓包仅支持 Linux（AF_PACKET）；当前平台不可用")
}

// StatsFunc 非 Linux 平台无内核统计。
func (c *Capture) StatsFunc() func() (packets, drops uint32, err error) { return nil }

// Run 非 Linux 平台直接失败。
func (c *Capture) Run() error { return errors.New("mirrorcap 仅支持 Linux") }

// Close 非 Linux 平台无操作。
func (c *Capture) Close() error { return nil }

// SetPorts 非 Linux 平台无操作（NewCapture 已失败，不会到达运行态）。
func (c *Capture) SetPorts(ports []uint16) {}

// 确保 *Capture 满足 Supervisor 的 Runner 抽象（编译期检查）。
var _ Runner = (*Capture)(nil)
