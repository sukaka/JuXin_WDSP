//go:build linux

// 抓包层（Linux）：AF_PACKET 纯 syscall raw socket。
//
// 实现选择说明（与任务书"afpacket"表述的偏差及原因）：
// gopacket v1.1.19 的 afpacket 包源文件含 `import "C"`（TPACKET 统计结构体经 cgo 声明），
// CGO_ENABLED=0 静态编译下不可用；同版本 pcapgo.EthernetHandle 为纯 syscall 实现
// （unix.Socket(AF_PACKET, SOCK_RAW) + recvmsg），不依赖 libpcap、不引入 cgo，
// 满足网关静态编译约束。代价：逐包 recvmsg，无 TPACKET_V3 环形缓冲，高带宽下
// 丢包率高于 afpacket（PoC 可接受；生产化可换纯 syscall TPACKET_V3 自实现）。
//
// 角色说明（检测/发现双功能，见 supervisor.go）：
//   - 纯检测句柄：抓包层按目的端口集合过滤（仅重组 client→server 目标流）；
//   - 承担发现角色的句柄（含双角色）：抓包层放宽为全量 TCP（发现需嗅探全端口
//     过境流量），检测端口过滤下沉到流工厂分流（两级共用同一原子端口集合指针，
//     SetPorts 热更新一致生效）。
package mirrorcap

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/tcpassembly"
)

// Capture 抓包→重组主循环（Linux）。
type Capture struct {
	cfg        Config
	ports      atomic.Pointer[map[uint16]struct{}] // 检测端口集合（与流工厂共享；SetPorts 热更新，feed 无锁读）
	captureAll bool                                // 承担发现角色：抓包层不按端口过滤（全量 TCP 进重组）
	handle     *pcapgo.EthernetHandle
	assembler  *tcpassembly.Assembler
	stats      *Stats
	stopCh     chan struct{}
}

// NewCapture 打开镜像接口（需要 CAP_NET_RAW；混杂模式需要 CAP_NET_ADMIN）。
// consumer 为本接口流消费组合（检测/发现/双角色；发现角色开启时抓全量 TCP）。
func NewCapture(cfg Config, consumer IfaceConsumer, stats *Stats) (*Capture, error) {
	h, err := pcapgo.NewEthernetHandle(cfg.Iface)
	if err != nil {
		return nil, fmt.Errorf("打开镜像接口 %s: %w（需要 cap_net_raw；接口须存在且 UP）", cfg.Iface, err)
	}
	// SPAN/镜像口流量目的 MAC 非本机，必须混杂模式；失败不致命（本网关命名空间内
	// 直抵本机的流量仍可捕获），仅告警由调用方日志输出
	promiscErr := h.SetPromiscuous(true)

	c := &Capture{
		cfg:        cfg,
		handle:     h,
		stats:      stats,
		stopCh:     make(chan struct{}),
		captureAll: consumer.Sniff != nil,
	}
	ports := cfg.PortSet()
	c.ports.Store(&ports)
	pool := tcpassembly.NewStreamPool(newIfaceStreamFactory(consumer, &c.ports, cfg.BodyMax, cfg.MaxStreamConns, stats))
	c.assembler = tcpassembly.NewAssembler(pool)
	if promiscErr != nil {
		// 非致命：记录到统计日志流（标准 log），继续运行
		fmt.Printf("[mirrorcap] warn: 接口 %s 混杂模式设置失败: %v（仅本机定向流量可捕获）\n", cfg.Iface, promiscErr)
	}
	return c, nil
}

// SetPorts 热更新目标端口过滤集合（配置文件端口变化时由 Supervisor 调用；
// 整表原子替换，feed 与流工厂分流同一指针无锁读，句柄不重启、在途流不中断）。
func (c *Capture) SetPorts(ports []uint16) {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	c.ports.Store(&m)
}

// StatsFunc 返回内核 socket 统计读取闭包（供 Stats.Logger 周期采集丢包数）。
func (c *Capture) StatsFunc() func() (packets, drops uint32, err error) {
	return func() (uint32, uint32, error) {
		st, err := c.handle.Stats()
		if err != nil {
			return 0, 0, err
		}
		return st.Packets, st.Drops, nil
	}
}

// Run 主循环：读包 → 端口过滤（发现角色句柄不过滤）→ TCP 重组；周期冲刷空闲流
// （半开连接清理）。阻塞运行直到 Close 或读包不可恢复错误。
func (c *Capture) Run() error {
	src := gopacket.NewPacketSource(c.handle, layers.LayerTypeEthernet)
	src.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	flush := time.NewTicker(c.cfg.StreamIdleTimeout / 2)
	defer flush.Stop()
	packets := src.Packets()
	for {
		select {
		case <-c.stopCh:
			return nil
		case <-flush.C:
			// 空闲流冲刷：推送滞留字节并关闭半开连接（防内存泄漏）
			c.assembler.FlushWithOptions(tcpassembly.FlushOptions{
				T: time.Now().Add(-c.cfg.StreamIdleTimeout),
			})
		case pkt, ok := <-packets:
			if !ok {
				// Close 先关 stopCh 再关句柄：通道随句柄关闭属优雅退出，按 nil 返回
				select {
				case <-c.stopCh:
					return nil
				default:
				}
				return errors.New("抓包通道关闭")
			}
			c.feed(pkt)
		}
	}
}

// feed 解析单包并送入重组器。纯检测句柄仅放行 TCP 且目的端口命中集合的包；
// 发现角色句柄放行全量 TCP（端口过滤下沉到流工厂分流）。
func (c *Capture) feed(pkt gopacket.Packet) {
	if c.stats != nil {
		c.stats.PacketsCaptured.Add(1)
	}
	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		if c.stats != nil {
			c.stats.PacketsFiltered.Add(1)
		}
		return
	}
	tcp, _ := tcpLayer.(*layers.TCP)
	if !c.captureAll {
		ports := c.ports.Load()
		if _, ok := (*ports)[uint16(tcp.DstPort)]; !ok {
			// 仅重组 client→server 方向；响应方向（源端口命中）与非目标端口一并过滤
			if c.stats != nil {
				c.stats.PacketsFiltered.Add(1)
			}
			return
		}
	}
	nl := pkt.NetworkLayer()
	if nl == nil {
		if c.stats != nil {
			c.stats.PacketsFiltered.Add(1)
		}
		return
	}
	ts := pkt.Metadata().Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	c.assembler.AssembleWithTimestamp(nl.NetworkFlow(), tcp, ts)
}

// Close 停止抓包并关闭全部重组流（SIGTERM 优雅退出路径；幂等）。
func (c *Capture) Close() error {
	select {
	case <-c.stopCh:
	default:
		close(c.stopCh)
	}
	c.handle.Close()
	// 冲刷并关闭所有连接：流 goroutine 收 EOF 退出
	c.assembler.FlushWithOptions(tcpassembly.FlushOptions{T: time.Now(), CloseAll: true})
	return nil
}

// 确保 io.Closer 语义可用（防未来重构误删 Close）。
var _ io.Closer = (*Capture)(nil)

// 确保 *Capture 满足 Supervisor 的 Runner 抽象（编译期检查）。
var _ Runner = (*Capture)(nil)
