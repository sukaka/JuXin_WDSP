// 运行统计：抓包/丢包/重组/请求计数，周期性输出一行状态日志（旁路可观测性底线）。
package mirrorcap

import (
	"log"
	"sync/atomic"
	"time"
)

// Stats 运行计数器（全部原子操作，热路径无锁）。
type Stats struct {
	PacketsCaptured   atomic.Uint64 // 网卡交付的报文数（应用侧计数）
	PacketsDropped    atomic.Uint64 // 内核态丢包数（socket 统计差值累计）
	PacketsFiltered   atomic.Uint64 // 非目标端口/非 TCP 被过滤的报文数
	StreamsOpened     atomic.Uint64
	StreamsClosed     atomic.Uint64
	StreamsRejected   atomic.Uint64 // 超 MaxStreamConns 被拒的新流
	RequestsParsed    atomic.Uint64 // 成功还原的 HTTP 请求数
	RequestErrors     atomic.Uint64 // 流解析失败/截断丢弃次数
	EventsEmitted     atomic.Uint64 // 事件写入成功数
	EventErrors       atomic.Uint64 // 事件写入失败数
	DiscoveryObserved atomic.Uint64 // 发现观察受理计数（Observe 调用）
	DiscoveryFlushed  atomic.Uint64 // 发现记录落盘条数
	DiscoveryErrors   atomic.Uint64 // 发现落盘失败次数
	// DiscoveryKeysDropped 窗口键总数超限丢弃的发现观察数（随机域名洪泛护栏）。
	DiscoveryKeysDropped atomic.Uint64
}

// Logger 周期性输出一行统计日志，直到 stop 关闭。
func (s *Stats) Logger(interval time.Duration, kernelStats func() (packets, drops uint32, err error), stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if kernelStats != nil {
			if _, dr, err := kernelStats(); err == nil {
				// Linux PACKET_STATISTICS 每次读取后由内核清零，返回的是自上次调用以来的周期增量，
				// 直接累加即可，不可再减去上周期值（否则持续丢包会被漏报）。
				s.PacketsDropped.Add(uint64(dr))
			}
		}
		log.Printf("[mirrorcap] stats packets=%d dropped=%d filtered=%d streams(open=%d closed=%d rejected=%d) requests=%d req_errors=%d events=%d event_errors=%d discovery_obs=%d discovery_flushed=%d discovery_err=%d discovery_keys_dropped=%d",
			s.PacketsCaptured.Load(), s.PacketsDropped.Load(), s.PacketsFiltered.Load(),
			s.StreamsOpened.Load(), s.StreamsClosed.Load(), s.StreamsRejected.Load(),
			s.RequestsParsed.Load(), s.RequestErrors.Load(),
			s.EventsEmitted.Load(), s.EventErrors.Load(),
			s.DiscoveryObserved.Load(), s.DiscoveryFlushed.Load(), s.DiscoveryErrors.Load(),
			s.DiscoveryKeysDropped.Load())
	}
}
