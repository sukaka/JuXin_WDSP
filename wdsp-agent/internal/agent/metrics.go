// 运行指标：atomic 计数 + 速率派生（TASK-009，契约 §3.2 metrics）。
package agent

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/transport"
)

// Metrics 运行计数器（全部原子操作，热路径无锁）。
type Metrics struct {
	Processed       atomic.Uint64 // 通过过滤进入管线的报文数
	CaptureBytes    atomic.Uint64 // 通过过滤的报文字节（线上长度）
	Forwarded       atomic.Uint64 // 成功外发的条目数（事件+帧）
	ForwardBytes    atomic.Uint64 // 成功外发字节（数据通道）
	Dropped         atomic.Uint64 // 丢弃总数（队列满/限速/缓存满/RAW 失败）
	RawDropped      atomic.Uint64 // RAW 通道丢弃（限速桶满/发送失败）
	FlowBuffered    atomic.Uint64 // 转磁盘缓存的 FLOW 事件数
	HTTPBuffered    atomic.Uint64 // 转磁盘缓存的 HTTP 记录数
	BufferFailed    atomic.Uint64 // 缓存满/关闭导致丢弃的 FLOW 事件数
	TruncatedFrames atomic.Uint64 // 捕获不完整帧数（OrigLen > CapLen，D-06）

	// P1-03 统一指标（任务书 §5.7）：
	Accepted          atomic.Uint64 // 服务端确认接收条目数（accepted 累加）
	Duplicate         atomic.Uint64 // 服务端确认重复条目数（v2 duplicate_count）
	SourceDisconnects atomic.Uint64 // 控制/数据通道断连次数

	dropReasonsMu sync.Mutex
	dropReasons   map[string]uint64 // dropped_by_reason 分账（懒初始化）

	rateMu        sync.Mutex
	lastTime      time.Time
	lastProcessed uint64
	lastCapBytes  uint64
	lastForwarded uint64
	lastFwdBytes  uint64
	lastDropped   uint64
	capturePPS    float64
	captureBPS    float64
	forwardPPS    float64
	forwardBPS    float64
	dropPPS       float64
}

// DropReason 按原因记丢弃分账（dropped_by_reason 指标；reason 取 DropReasonXxx /
// events.DropXxx 冻结词表）。
func (m *Metrics) DropReason(reason string, n uint64) {
	m.dropReasonsMu.Lock()
	if m.dropReasons == nil {
		m.dropReasons = make(map[string]uint64)
	}
	m.dropReasons[reason] += n
	m.dropReasonsMu.Unlock()
}

// dropReasonsSnapshot 丢弃分账快照（返回副本）。
func (m *Metrics) dropReasonsSnapshot() map[string]uint64 {
	m.dropReasonsMu.Lock()
	defer m.dropReasonsMu.Unlock()
	if len(m.dropReasons) == 0 {
		return nil
	}
	out := make(map[string]uint64, len(m.dropReasons))
	for k, v := range m.dropReasons {
		out[k] = v
	}
	return out
}

// snapshot 汇总心跳 metrics（contract §3.2）。速率按两次快照差值/间隔计算。
// backend/fallbackReason 为 Phase 2 追加字段（omitempty，服务端可忽略）。
func (m *Metrics) snapshot(received, kernelDrops uint64, cpu, mem float64, queueDepth int, bufferBytes int64, backend, fallbackReason string) transport.Metrics {
	m.rateMu.Lock()
	now := time.Now()
	if m.lastTime.IsZero() {
		m.lastTime = now
		m.lastProcessed = m.Processed.Load()
		m.lastCapBytes = m.CaptureBytes.Load()
		m.lastForwarded = m.Forwarded.Load()
		m.lastFwdBytes = m.ForwardBytes.Load()
		m.lastDropped = m.Dropped.Load()
	}
	elapsed := now.Sub(m.lastTime).Seconds()
	if elapsed >= 1 {
		processed := m.Processed.Load()
		capBytes := m.CaptureBytes.Load()
		fwd := m.Forwarded.Load()
		fwdBytes := m.ForwardBytes.Load()
		dropped := m.Dropped.Load()
		m.capturePPS = float64(processed-m.lastProcessed) / elapsed
		m.captureBPS = float64(capBytes-m.lastCapBytes) / elapsed
		m.forwardPPS = float64(fwd-m.lastForwarded) / elapsed
		m.forwardBPS = float64(fwdBytes-m.lastFwdBytes) / elapsed
		m.dropPPS = float64(dropped-m.lastDropped) / elapsed
		m.lastTime = now
		m.lastProcessed = processed
		m.lastCapBytes = capBytes
		m.lastForwarded = fwd
		m.lastFwdBytes = fwdBytes
		m.lastDropped = dropped
	}
	out := transport.Metrics{
		CPUPercent:       cpu,
		MemoryMB:         mem,
		CapturePPS:       m.capturePPS,
		CaptureBPS:       m.captureBPS,
		ForwardPPS:       m.forwardPPS,
		ForwardBPS:       m.forwardBPS,
		DropPPS:          m.dropPPS,
		QueueDepth:       queueDepth,
		BufferBytes:      bufferBytes,
		PacketsReceived:  received,
		PacketsProcessed: m.Processed.Load(),
		PacketsForwarded: m.Forwarded.Load(),
		PacketsDropped:   m.Dropped.Load(),
		KernelDrops:      kernelDrops,
		CurrentMbps:      m.forwardBPS * 8 / 1e6,

		CaptureBackend:        backend,
		BackendFallbackReason: fallbackReason,
		TruncatedFrames:       m.TruncatedFrames.Load(),
	}
	m.rateMu.Unlock()
	return out
}
