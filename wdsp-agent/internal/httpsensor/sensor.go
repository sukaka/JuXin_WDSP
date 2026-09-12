// Package httpsensor TCP 双向流重组 + HTTP/1.1 完整解析（Phase 3 契约 §2/§3/§4/§5/§8）。
//
// 设计要点（先例参照 gateway/mirrorcap/stream.go 的 tcpassembly 工厂模式，
// 本包为 wdsp-agent 独立 module 内实现，不 import gateway）：
//   - 重组：gopacket tcpassembly 双方向工厂；每条连接两个半流（c2s/s2c）各一条
//     tcpreader.ReaderStream + 消费 goroutine；LossErrors=true（镜像丢包显式失败，
//     不无限等待缺失字节）；
//   - 关联：HTTP/1.1 keep-alive 多对请求按到达顺序配对（不支持 pipelining 乱序，
//     见契约 §8）；响应可为 null（响应未捕获/连接关闭/超时）；
//   - 回退红线：解析失败/非 HTTP 的流静默回退为既有 flow 事件行为（不产生 HTTP
//     记录、不报错、不 panic）——flow 层独立运行不受影响，本包所有 goroutine
//     recover 保护；
//   - 资源红线：连接表上限（默认 4096，超出拒绝并排空）；Body 捕获永不超
//     limits.max_body_size 驻留内存（超出部分边读边丢，仅计数原始大小）；
//     Header 存储钳 16KB/消息（契约 §4）；
//   - 脱敏红线：所有 HTTP 记录唯一出口为 conn.emit → buildMessage，脱敏在记录
//     离开主机前强制执行（契约 §5），发送路径无旁路。
package httpsensor

import (
	"encoding/binary"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"

	"github.com/jiuzhang-waf/wdsp-agent/internal/capture"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

// 资源护栏（设计 §68 / 契约 §8：重组流表沿用 flow 上限思路，Body 缓冲计入内存保护）。
const (
	// DefaultMaxConns 重组连接表硬上限（每连接至多 2 个消费 goroutine）。
	DefaultMaxConns = 4096
	// maxPendingRequests 单连接未配对请求上限（防对端不应答时积压 Body 缓冲）。
	maxPendingRequests = 128
	// 重组器乱序页缓冲：page≈1900B，total 8192 ≈ 15MB 硬上限。
	maxBufferedPagesTotal   = 8192
	maxBufferedPagesPerConn = 64
)

// Policy 采集策略快照（热更整表原子替换）。
type Policy struct {
	Level       string // L0|L1|L2|L3（config.LevelLx）
	MaxBodySize int    // 已钳制（config.Limits.EffectiveMaxBodySize）
	Masking     config.Masking
}

// connKey 归一化连接键（client→server 视角，与 flow 包 canonical key 一致）。
type connKey struct {
	srcIP   string
	srcPort uint16
	dstIP   string
	dstPort uint16
}

// Stats 传感器计数（agent 聚合到自身 metrics/日志）。
type Stats struct {
	RecordsEmitted atomic.Uint64 // 产出的 HTTP 记录数
	ConnsRejected  atomic.Uint64 // 连接表满拒绝
	ParseFallbacks atomic.Uint64 // 解析失败/非 HTTP 回退连接数
	HeaderClamped  atomic.Uint64 // Header 总量超 16KB 被钳次数
	MaskedFields   atomic.Uint64 // 实际脱敏的 Header/参数值数（masked 指标，P1-03 §5.7）
}

// Sensor HTTP 传感器（重组器非并发安全，内部串行化；Assemble/Sweep/Close 可直接并发调用）。
type Sensor struct {
	agentID      string
	isServerPort func(uint16) bool
	onRecord     func(events.HTTPRecord)
	log          *slog.Logger
	maxConns     int

	policy atomic.Pointer[Policy]
	Stats  Stats

	mu    sync.Mutex // 保护 asm 与 conns
	asm   *tcpassembly.Assembler
	conns map[connKey]*conn
}

// New 创建 HTTP 传感器。isServerPort 判定采集端口集合（server 端识别，与 flow
// 层 canonical 语义一致）；onRecord 必须非阻塞快速返回（自行异步化）。
func New(agentID string, isServerPort func(uint16) bool, onRecord func(events.HTTPRecord), log *slog.Logger) *Sensor {
	if log == nil {
		log = slog.Default()
	}
	s := &Sensor{
		agentID:      agentID,
		isServerPort: isServerPort,
		onRecord:     onRecord,
		log:          log,
		maxConns:     DefaultMaxConns,
		conns:        make(map[connKey]*conn),
	}
	factory := &streamFactory{sensor: s}
	pool := tcpassembly.NewStreamPool(factory)
	s.asm = tcpassembly.NewAssembler(pool)
	s.asm.AssemblerOptions.MaxBufferedPagesTotal = maxBufferedPagesTotal
	s.asm.AssemblerOptions.MaxBufferedPagesPerConnection = maxBufferedPagesPerConn
	// 默认 L0（不启用），待策略下发
	s.policy.Store(&Policy{Level: config.LevelL0, MaxBodySize: config.DefaultMaxBodySize, Masking: config.DefaultMasking()})
	return s
}

// UpdatePolicy 热更采集策略（整表原子替换；进行中的连接在新消息解析时生效）。
func (s *Sensor) UpdatePolicy(level string, maxBodySize int, masking config.Masking) {
	if maxBodySize <= 0 {
		maxBodySize = config.DefaultMaxBodySize
	}
	if maxBodySize > config.HardMaxBodySize {
		maxBodySize = config.HardMaxBodySize
	}
	s.policy.Store(&Policy{Level: level, MaxBodySize: maxBodySize, Masking: masking})
}

// Enabled 当前是否启用（L1 及以上才需要重组）。
func (s *Sensor) Enabled() bool {
	return s.policy.Load().Level != config.LevelL0
}

// Assemble 喂入一个已过滤包（capture 层交付）。仅全局策略 L1+ 生效；
// 任何输入错误只导致本连接回退，绝不影响其他连接与进程。
// Phase 4 起上层按流生效等级调用 AssembleLevel；本方法保持 Phase 3 全局语义。
func (s *Sensor) Assemble(p capture.Packet) {
	if !s.Enabled() {
		return
	}
	s.AssembleLevel(p, s.policy.Load().Level)
}

// AssembleLevel 按流生效等级喂入一个已过滤包（Phase 4 契约 §2.4/§3.1）：
//   - level ≥ L1：正常重组（连接不存在则创建；L0 流被规则提升后从当前包起
//     建链采集，此前已过的 Header/Body 不补——重组自首个喂入包开始）；
//   - level < L1：连接不存在直接跳过；连接已存在（降级帽回落）立即终止并
//     补发 response=null 记录（已采集数据不丢），释放重组资源。
func (s *Sensor) AssembleLevel(p capture.Packet, level string) {
	if level == "" {
		level = s.policy.Load().Level
	}
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("httpsensor Assemble panic 已捕获（Fail-Open）", "panic", r)
		}
	}()

	// canonical：server 端 = 命中采集端口的一端（同 flow 层语义）；
	// 两端端口均在采集集时以五元组排序兜底（小端点为 client 侧，与 flow 层一致）
	key := connKey{srcIP: p.SrcIP, srcPort: p.SrcPort, dstIP: p.DstIP, dstPort: p.DstPort}
	dir := "ingress"
	swap := !p.Ingress
	if p.BothHit {
		swap = !endpointLess(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	if swap {
		key = connKey{srcIP: p.DstIP, srcPort: p.DstPort, dstIP: p.SrcIP, dstPort: p.SrcPort}
		dir = "egress"
	}
	atLeastL1 := config.LevelRank(level) >= 1

	s.mu.Lock()
	c := s.conns[key]
	if p.Truncated {
		// D-06 快速失败：截断包意味着重组流永久缺段（旁路无重传），
		// 立即终止本连接并补发 response=null 记录，不得干等空闲冲刷。
		if c != nil {
			delete(s.conns, key)
		}
		s.mu.Unlock()
		if c != nil {
			c.fail()
			c.finalize()
		}
		return
	}
	if c == nil {
		if !atLeastL1 {
			s.mu.Unlock()
			return // L0 流：不建链（此前已过的 Header/Body 不补）
		}
		if len(s.conns) >= s.maxConns {
			s.Stats.ConnsRejected.Add(1)
			s.mu.Unlock()
			return
		}
		c = newConn(s, key, dir, p.Ts)
		s.conns[key] = c
	}
	if !atLeastL1 {
		// 降级帽压回 L0：终止既有连接（补发 response=null），释放重组资源
		delete(s.conns, key)
		s.mu.Unlock()
		c.fail()
		c.finalize()
		return
	}
	c.setLevel(level)
	c.lastSeen.Store(p.Ts.UnixNano())
	defer s.mu.Unlock()

	netFlow, ok := ipFlow(p.SrcIP, p.DstIP)
	if !ok {
		return // 无法构造网络流（畸形 IP）：跳过本包，不影响连接
	}
	// 中段建链（L0 流被规则提升后从当前包起采集）：tcpassembly 各方向需
	// 先见 SYN 建立序列基准，否则数据永久缓冲。为该方向补一个合成 SYN
	// （seq=当前包 seq-1，无 payload）——语义即"已过的不补，从当前包起"。
	halfIdx := halfS2C
	if s.isC2S(p) {
		halfIdx = halfC2S
	}
	if !c.started[halfIdx] {
		c.started[halfIdx] = true
		if !p.SYN {
			syn := p
			syn.SYN, syn.ACK, syn.PSH, syn.FIN, syn.RST = true, false, false, false, false
			syn.Payload = nil
			syn.Seq = p.Seq - 1
			if tcp, ok := buildTCPLayer(syn); ok {
				s.asm.AssembleWithTimestamp(netFlow, tcp, p.Ts)
			}
		}
	}
	tcp, ok := buildTCPLayer(p)
	if !ok {
		return
	}
	s.asm.AssembleWithTimestamp(netFlow, tcp, p.Ts)
}

// Conns 当前重组连接表条数（观测与测试用）。
func (s *Sensor) Conns() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.conns)
}

// isC2S 判定包是否 client→server 方向（server 端 = 命中采集端口的一端；
// 两端端口均在采集集时按五元组排序的小端点为 client 侧，与 flow 层
// canonical 语义一致，避免同一连接两向被挂到同一半流槽位）。
func (s *Sensor) isC2S(p capture.Packet) bool {
	if p.BothHit {
		return endpointLess(p.SrcIP, p.SrcPort, p.DstIP, p.DstPort)
	}
	return s.isServerPort(p.DstPort)
}

// endpointLess 五元组端点排序（双采集端口 canonical 兜底，同 flow 层）。
func endpointLess(ipA string, portA uint16, ipB string, portB uint16) bool {
	if ipA != ipB {
		return ipA < ipB
	}
	return portA < portB
}

// buildTCPLayer 由包字段重建 layers.TCP。必须经 DecodeFromBytes 解码：
// 手工构造的 layers.TCP 未填充内部 sPort/dPort 字段，TransportFlow() 会
// panic（EndpointTCPPort 键为空）。头部 20 字节（无 options）。
func buildTCPLayer(p capture.Packet) (*layers.TCP, bool) {
	hdr := make([]byte, 20, 20+len(p.Payload))
	binary.BigEndian.PutUint16(hdr[0:2], p.SrcPort)
	binary.BigEndian.PutUint16(hdr[2:4], p.DstPort)
	binary.BigEndian.PutUint32(hdr[4:8], p.Seq)
	hdr[12] = 5 << 4 // data offset = 5（20 字节头）
	if p.FIN {
		hdr[13] |= 0x01
	}
	if p.SYN {
		hdr[13] |= 0x02
	}
	if p.RST {
		hdr[13] |= 0x04
	}
	if p.PSH {
		hdr[13] |= 0x08
	}
	if p.ACK {
		hdr[13] |= 0x10
	}
	tcp := &layers.TCP{}
	if err := tcp.DecodeFromBytes(append(hdr, p.Payload...), gopacket.NilDecodeFeedback); err != nil {
		return nil, false
	}
	return tcp, true
}

// Sweep 周期维护（建议与 flow.Expire 同周期）：先冲刷重组器中超时空闲的连接，
// 再收尾「半流已全部结束但长时间无活动」的连接（单边抓包/半关闭场景），
// 为其未配对请求补发 response=null 的记录并移出连接表。
func (s *Sensor) Sweep(now time.Time, idleTimeout time.Duration) {
	if idleTimeout <= 0 {
		idleTimeout = 90 * time.Second
	}
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("httpsensor Sweep panic 已捕获（Fail-Open）", "panic", r)
		}
	}()
	cutoff := now.Add(-idleTimeout)
	s.mu.Lock()
	s.asm.FlushOlderThan(cutoff)
	var stale []*conn
	for k, c := range s.conns {
		if !c.allHalvesDone() {
			continue
		}
		if time.Unix(0, c.lastSeen.Load()).Before(cutoff) || c.isFailed() {
			stale = append(stale, c)
			delete(s.conns, k)
		}
	}
	s.mu.Unlock()
	for _, c := range stale {
		c.finalize()
	}
}

// Close 停机冲刷：重组器全部关闭，连接表逐条收尾。
func (s *Sensor) Close() {
	s.mu.Lock()
	s.asm.FlushAll()
	all := make([]*conn, 0, len(s.conns))
	for k, c := range s.conns {
		all = append(all, c)
		delete(s.conns, k)
	}
	s.mu.Unlock()
	for _, c := range all {
		c.finalize()
	}
}

// removeConn 连接收尾后移出连接表（防御重复移除）。
func (s *Sensor) removeConn(key connKey, c *conn) {
	s.mu.Lock()
	if s.conns[key] == c {
		delete(s.conns, key)
	}
	s.mu.Unlock()
}

// ipFlow 由 IP 字符串构造 gopacket 网络流（tcpassembly 连接键的一半）。
func ipFlow(src, dst string) (gopacket.Flow, bool) {
	sIP := net.ParseIP(src)
	dIP := net.ParseIP(dst)
	if sIP == nil || dIP == nil {
		return gopacket.Flow{}, false
	}
	s4, d4 := sIP.To4(), dIP.To4()
	if s4 != nil && d4 != nil {
		return gopacket.NewFlow(layers.EndpointIPv4, s4, d4), true
	}
	s16, d16 := sIP.To16(), dIP.To16()
	if s16 == nil || d16 == nil {
		return gopacket.Flow{}, false
	}
	return gopacket.NewFlow(layers.EndpointIPv6, s16, d16), true
}
