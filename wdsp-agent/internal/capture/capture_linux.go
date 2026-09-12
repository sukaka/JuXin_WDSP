//go:build linux

// 抓包句柄（Linux）：AF_PACKET 纯 syscall raw socket，CGO_ENABLED=0 可构建。
//
// D-06：接收句柄实现见 eth_linux.go（64KB 单帧缓冲 + 4MB SO_RCVBUF +
// auxdata 线上长度），替代 pcapgo.NewEthernetHandle（其接收缓冲=接口 MTU，
// TSO/GRO 聚合超帧被静默截断）。截断检测在平台无关的 DecodePacket 中完成
// （OrigLen > len(Frame) → Packet.Truncated），供 httpsensor 快速失败。
package capture

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"github.com/jiuzhang-waf/wdsp-agent/internal/filter"
)

// Handle 单接口抓包句柄。内部 goroutine recover 保护 + 崩溃降级重试（红线）。
type Handle struct {
	iface    string
	filt     *filter.Filter
	consumer func(Packet)
	stats    *Stats
	log      *slog.Logger

	mu     sync.Mutex
	eth    *ethHandle
	stopCh chan struct{}
	doneCh chan struct{}
}

// Start 打开接口并启动抓包 goroutine（需要 CAP_NET_RAW；混杂模式失败非致命）。
// consumer 必须快速返回或自行异步化，且注意 Packet 的 NoCopy 内存语义。
func Start(iface string, filt *filter.Filter, consumer func(Packet), st *Stats, log *slog.Logger) (*Handle, error) {
	h := &Handle{
		iface: iface, filt: filt, consumer: consumer, stats: st, log: log,
		stopCh: make(chan struct{}), doneCh: make(chan struct{}),
	}
	if err := h.open(); err != nil {
		return nil, err
	}
	go h.run()
	return h, nil
}

// open 建立 AF_PACKET 句柄。
func (h *Handle) open() error {
	eth, err := newEthHandle(h.iface, h.log)
	if err != nil {
		return fmt.Errorf("打开接口 %s: %w（需要 cap_net_raw；接口须存在且 UP）", h.iface, err)
	}
	h.mu.Lock()
	h.eth = eth
	h.mu.Unlock()
	return nil
}

// run 主循环：读包→解码过滤→消费；panic/句柄异常 → recover 后按退避降级重试，绝不退出进程。
func (h *Handle) run() {
	defer close(h.doneCh)
	backoff := time.Second
	for {
		select {
		case <-h.stopCh:
			return
		default:
		}
		crashed := h.loop()
		select {
		case <-h.stopCh:
			return
		default:
		}
		if crashed {
			h.log.Error("抓包循环异常，降级后重试", "iface", h.iface, "retry_in", backoff)
			// 退避必须可被 Close 中断（最高 60s），且停止后不得再重建句柄
			// （否则 stopCh 关闭后 open() 泄漏 fd）
			timer := time.NewTimer(backoff)
			select {
			case <-h.stopCh:
				timer.Stop()
				return
			case <-timer.C:
			}
			if backoff < 60*time.Second {
				backoff *= 2
			}
			select {
			case <-h.stopCh:
				return // 退避期间收到停止：不重建句柄
			default:
			}
			// 重建句柄重试
			h.mu.Lock()
			if h.eth != nil {
				h.eth.close()
				h.eth = nil
			}
			h.mu.Unlock()
			if err := h.open(); err != nil {
				h.log.Error("重建抓包句柄失败", "iface", h.iface, "err", err)
			} else {
				// 与 Close 竞态：越过停止点打开的句柄补关闭，不泄漏 fd
				select {
				case <-h.stopCh:
					h.mu.Lock()
					if h.eth != nil {
						h.eth.close()
						h.eth = nil
					}
					h.mu.Unlock()
					return
				default:
				}
				h.log.Info("抓包句柄已重建", "iface", h.iface)
			}
		}
	}
}

// loop 单次读包循环；返回 true 表示因 panic/错误退出（需降级重试）。
func (h *Handle) loop() (crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error("抓包 panic 已捕获（Fail-Open，不影响业务）", "iface", h.iface, "panic", r)
			crashed = true
		}
	}()
	h.mu.Lock()
	eth := h.eth
	h.mu.Unlock()
	if eth == nil {
		return true
	}
	for {
		select {
		case <-h.stopCh:
			return false
		default:
		}
		data, ci, err := eth.readFrame()
		if errors.Is(err, errFrameTimeout) {
			continue // 周期超时：回环顶检查 stopCh（Close 响应）
		}
		if err != nil {
			select {
			case <-h.stopCh:
				return false // Close 关闭 fd 导致的退出
			default:
			}
			h.log.Warn("读包失败，重建句柄", "iface", h.iface, "err", err)
			return true
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet,
			gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		pkt.Metadata().Timestamp = ci.Timestamp
		pkt.Metadata().CaptureInfo = ci
		p, keep := DecodePacket(pkt, h.filt, h.stats)
		if keep {
			h.consume(p)
		}
	}
}

// consume 消费回调（recover 保护：单个消费方 panic 不拖垮抓包循环）。
func (h *Handle) consume(p Packet) {
	defer func() {
		if r := recover(); r != nil {
			h.log.Error("消费回调 panic 已捕获", "iface", h.iface, "panic", r)
		}
	}()
	h.consumer(p)
}

// KernelStats 读取内核 socket 统计（PACKET_STATISTICS 读后清零：返回值为
// 自上次调用起的 packets/drops 差值，同 pcapgo SocketStats 语义）。
func (h *Handle) KernelStats() (packets, drops uint32, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.eth == nil {
		return 0, 0, fmt.Errorf("句柄未打开")
	}
	return h.eth.stats()
}

// Close 停止抓包（幂等）。
func (h *Handle) Close() error {
	select {
	case <-h.stopCh:
	default:
		close(h.stopCh)
	}
	h.mu.Lock()
	if h.eth != nil {
		h.eth.close()
		h.eth = nil
	}
	h.mu.Unlock()
	<-h.doneCh
	return nil
}
