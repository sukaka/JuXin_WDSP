// 运行统计：连接/拒绝/字节计数，周期性输出一行状态日志（串接链路可观测性底线）。
package tproxyd

import (
	"log"
	"sync/atomic"
	"time"
)

// Stats 运行计数器（全部原子操作，热路径无锁）。
type Stats struct {
	ConnAccepted      atomic.Uint64 // 接受并进入转发流程的连接数
	ConnRejected      atomic.Uint64 // 超 MaxConns 被立即关闭的新连接数（背压护栏）
	ActiveConns       atomic.Int64  // 当前在途连接数
	BytesToTarget     atomic.Uint64 // 客户端 → Caddy 方向透传字节数
	BytesToClient     atomic.Uint64 // Caddy → 客户端方向透传字节数
	OrigDstErrors     atomic.Uint64 // SO_ORIGINAL_DST 读取失败数（连接未经牵引等）
	DialErrors        atomic.Uint64 // 连接下游 Caddy 失败数
	HeaderErrors      atomic.Uint64 // PROXY 头写入失败数
	AcceptErrors      atomic.Uint64 // accept 异常数（句柄耗尽等，记录后重试）
	ShutdownForceCx   atomic.Uint64 // 优雅退出宽限超时被强制断开的连接数
	ConnsProtected    atomic.Uint64 // SNI 命中防护清单、送 Caddy TLS 终结检测的连接数
	ConnsPassthrough  atomic.Uint64 // SNI 在清单外、按原始目的端到端透传的连接数
	SniffErrors       atomic.Uint64 // ClientHello 解析失败数（倒向 TLS 检测路径）
	SniffTimeouts     atomic.Uint64 // SNI 嗅探读超时关闭的连接数
	RelayIdleTimeouts atomic.Uint64 // 透传滚动空闲超时关闭的连接数
}

// Logger 周期性输出一行统计日志，直到 stop 关闭。
func (s *Stats) Logger(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		log.Printf("[tproxyd] stats accepted=%d rejected=%d active=%d bytes(c2t=%d t2c=%d) errors(origdst=%d dial=%d header=%d accept=%d) force_closed=%d sni(protected=%d passthrough=%d sniff_err=%d sniff_timeout=%d) relay_idle_timeout=%d",
			s.ConnAccepted.Load(), s.ConnRejected.Load(), s.ActiveConns.Load(),
			s.BytesToTarget.Load(), s.BytesToClient.Load(),
			s.OrigDstErrors.Load(), s.DialErrors.Load(), s.HeaderErrors.Load(), s.AcceptErrors.Load(),
			s.ShutdownForceCx.Load(),
			s.ConnsProtected.Load(), s.ConnsPassthrough.Load(), s.SniffErrors.Load(), s.SniffTimeouts.Load(),
			s.RelayIdleTimeouts.Load())
	}
}
