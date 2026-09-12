// 站点资产被动发现：从全部 TCP 端口的过境流量中嗅探站点（HTTP 取 Host、TLS 取 SNI），
// 与四元组目的端（真实服务器 IP:Port）聚合成发现记录，周期追加写入 JSONL 文件，
// 供服务端采集入库（字段契约为服务端解析依据，不得改名）。
//
// 设计要点：
//   - 与检测管线完全解耦：发现走独立抓包句柄（supervisor 按 discovery.enabled 单独
//     启停；同一接口双角色时共用句柄，见 supervisor.go），嗅探只做首包分类，不做
//     完整 HTTP 解析循环，绝不影响检测路径；
//   - 聚合窗口：map[{Domain,IP,Port,Protocol}] 聚合 hits/首末见时间与窗口内去重
//     客户端集合；每 flush_interval（默认 30s）整体换出窗口、锁外写盘（抓包 goroutine
//     不被磁盘 IO 反压），随后重置窗口；
//   - 护栏：单键客户端去重集合上限 1000（超限只计 hits 不再扩集合，内存有界）；
//     窗口键总数上限 maxDiscoveryKeys（键含攻击者可控 Host/SNI，随机域名洪泛
//     防护——超限新键丢弃并计数，已有键照计 hits）；嗅探单流读取上限 16KB、
//     每条流只判定一次；非 HTTP/TLS 流直接排空不记录。
//
// 方向性说明：镜像/路由口同见双向流量，响应方向首包（HTTP 状态行不匹配方法前缀、
// ServerHello 非 ClientHello）在嗅探分类处即被识别并丢弃，不会污染发现记录。
package mirrorcap

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// 发现协议标识（记录 protocol 字段取值域）。
const (
	protoHTTP  = "HTTP"
	protoHTTPS = "HTTPS"
)

const (
	// maxDiscoveryClients 单键窗口内去重客户端集合上限（防高基数源 IP 撑爆内存）。
	maxDiscoveryClients = 1000
	// maxDiscoveryKeys 窗口键总数上限（键含攻击者可控 Host/SNI，防随机域名洪泛
	// 撑大窗口内存与落盘量；超限新键丢弃并计 DiscoveryKeysDropped，已有键照计）。
	maxDiscoveryKeys = 10000
	// defaultSniffMaxBytes 单流嗅探读取上限（覆盖 TLS record 上界）。
	defaultSniffMaxBytes = 16 << 10
	// sniffPeekBytes 首包分类窥视字节数（覆盖最长 HTTP 方法前缀 CONNECT + 空格）。
	sniffPeekBytes = 16
	// recordTypeSiteDiscovery 发现记录 type 字段恒定值。
	recordTypeSiteDiscovery = "site_discovery"
)

// DiscoveryRecord 站点发现记录（JSONL 行契约；服务端按字段名解析，禁止改名）。
type DiscoveryRecord struct {
	Type        string `json:"type"`         // 恒 "site_discovery"
	Node        string `json:"node"`         // 网关节点名
	Domain      string `json:"domain"`       // 站点域名（Host/SNI；未识别为空串）
	IP          string `json:"ip"`           // 真实服务器 IP（四元组目的地址）
	Port        uint16 `json:"port"`         // 真实服务器端口
	Protocol    string `json:"protocol"`     // HTTP / HTTPS
	SourceMode  string `json:"source_mode"`  // 流量来源模式（配置下发：MIRROR / ROUTED / TRANSPARENT）
	Hits        uint64 `json:"hits"`         // 窗口内命中次数
	ClientCount int    `json:"client_count"` // 窗口内去重客户端数（上限 maxDiscoveryClients）
	WindowStart string `json:"window_start"` // 聚合窗口起点（RFC3339）
	WindowEnd   string `json:"window_end"`   // 聚合窗口终点（RFC3339）
}

// DiscoveryObserver 检测器可选实现：接收发现聚合器注入（检测路径顺带记发现）。
// Supervisor 按发现启停动态调用；agg 为 nil 表示发现已停用（撤销注入）。
type DiscoveryObserver interface {
	SetDiscovery(agg *DiscoveryAggregator)
}

// discoveryKey 聚合键（Domain 允许空串——未识别站点仍按 IP:Port 资产记录）。
type discoveryKey struct {
	Domain   string
	IP       string
	Port     uint16
	Protocol string
}

// discoveryEntry 窗口内聚合值。
type discoveryEntry struct {
	mode    string // 窗口内首见 source_mode（同键跨接口多源时先见先得，部署期应避免双口镜像同流）
	first   time.Time
	last    time.Time
	hits    uint64
	clients map[string]struct{}
}

// DiscoveryAggregator 发现聚合器（goroutine 安全：抓包多 goroutine 并发 Observe）。
type DiscoveryAggregator struct {
	node     string
	mode     string // 默认 source_mode：Observe 直调路径（检测顺带记录）使用
	path     string
	interval time.Duration
	stats    *Stats
	now      func() time.Time // 时间源（测试可注入）

	mu       sync.Mutex
	entries  map[discoveryKey]*discoveryEntry
	winStart time.Time
	closed   bool

	stopCh    chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewDiscoveryAggregator 构建聚合器并启动周期落盘循环。
// 创建期探测输出路径可写性（与事件日志 eager-open 风格一致：配置错误在启动期暴露，
// 由 Supervisor 下周期重试，而不是运行期才显现）。flushInterval <= 0 取默认 30s。
func NewDiscoveryAggregator(node, sourceMode, logPath string, flushInterval time.Duration, stats *Stats) (*DiscoveryAggregator, error) {
	if flushInterval <= 0 {
		flushInterval = defaultDiscoveryFlushInterval
	}
	if sourceMode == "" {
		sourceMode = "MIRROR"
	}
	if node == "" {
		node = "mirror-unknown"
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("打开站点发现日志 %s: %w", logPath, err)
	}
	_ = f.Close()
	a := &DiscoveryAggregator{
		node: node, mode: sourceMode, path: logPath, interval: flushInterval, stats: stats,
		now: time.Now, entries: make(map[discoveryKey]*discoveryEntry), winStart: time.Now(),
		stopCh: make(chan struct{}),
	}
	a.wg.Add(1)
	go a.run()
	return a, nil
}

// Observe 记录一次站点观察（聚合器默认 source_mode；检测路径顺带记录走此入口）。
func (a *DiscoveryAggregator) Observe(domain string, meta FlowMeta, protocol string) {
	a.observe(a.mode, domain, meta, protocol)
}

// observe 记录一次站点观察（显式 source_mode；发现接口嗅探路径按接口 mode 记录）。
func (a *DiscoveryAggregator) observe(mode, domain string, meta FlowMeta, protocol string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if mode == "" {
		mode = a.mode
	}
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return // 停用后到达的观察直接丢弃（停用即不再产出，语义对齐事件文件关闭）
	}
	now := a.now()
	k := discoveryKey{Domain: domain, IP: meta.DstIP, Port: meta.DstPort, Protocol: protocol}
	e, ok := a.entries[k]
	if !ok {
		if len(a.entries) >= maxDiscoveryKeys {
			a.mu.Unlock()
			if a.stats != nil {
				a.stats.DiscoveryKeysDropped.Add(1)
			}
			return // 窗口键总数护栏：随机 Host/SNI 洪泛时新键丢弃，窗口内存有界
		}
		e = &discoveryEntry{mode: mode, first: now, clients: make(map[string]struct{})}
		a.entries[k] = e
	}
	e.last = now
	e.hits++
	if ip := meta.SrcIP; ip != "" {
		if _, seen := e.clients[ip]; seen || len(e.clients) < maxDiscoveryClients {
			e.clients[ip] = struct{}{}
		}
		// 超上限只计 hits 不再扩集合（高基数源 IP 护栏）
	}
	a.mu.Unlock()
	if a.stats != nil {
		a.stats.DiscoveryObserved.Add(1)
	}
}

// run 周期落盘循环（直到 Close）。
func (a *DiscoveryAggregator) run() {
	defer a.wg.Done()
	t := time.NewTicker(a.interval)
	defer t.Stop()
	for {
		select {
		case <-a.stopCh:
			return
		case <-t.C:
			if err := a.flush(); err != nil {
				a.logFlushErr(err)
			}
		}
	}
}

// Close 停止周期循环并做最终冲刷（幂等；最终冲刷失败返回错误供调用方告警）。
func (a *DiscoveryAggregator) Close() error {
	var ferr error
	a.closeOnce.Do(func() {
		close(a.stopCh)
		a.wg.Wait()
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		if err := a.flush(); err != nil {
			a.logFlushErr(err)
			ferr = err
		}
	})
	return ferr
}

// flush 换出当前窗口并逐条 append 写入 JSONL（锁外写盘：抓包 goroutine 不被磁盘 IO 反压）。
// 写盘失败仅计数告警并重置窗口（窗口驻留内存有界优先于单窗数据完整性，对齐旁路不熔断纪律）。
func (a *DiscoveryAggregator) flush() error {
	a.mu.Lock()
	entries := a.entries
	a.entries = make(map[discoveryKey]*discoveryEntry)
	winStart, winEnd := a.winStart, a.now()
	a.winStart = winEnd
	a.mu.Unlock()

	if len(entries) == 0 {
		return nil
	}
	// 键序稳定输出（便于人工查阅与测试比对）
	keys := make([]discoveryKey, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Domain != b.Domain {
			return a.Domain < b.Domain
		}
		if a.IP != b.IP {
			return a.IP < b.IP
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("打开站点发现日志 %s: %w", a.path, err)
	}
	w := bufio.NewWriter(f)
	var flushed uint64
	for _, k := range keys {
		e := entries[k]
		rec := DiscoveryRecord{
			Type:        recordTypeSiteDiscovery,
			Node:        a.node,
			Domain:      k.Domain,
			IP:          k.IP,
			Port:        k.Port,
			Protocol:    k.Protocol,
			SourceMode:  e.mode,
			Hits:        e.hits,
			ClientCount: len(e.clients),
			WindowStart: winStart.Format(time.RFC3339),
			WindowEnd:   winEnd.Format(time.RFC3339),
		}
		line, err := json.Marshal(rec)
		if err != nil {
			continue // 字段全为可序列化标量，理论上不可达；防御性跳过
		}
		if _, err := w.Write(line); err != nil {
			_ = f.Close()
			return fmt.Errorf("写入站点发现日志 %s: %w", a.path, err)
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = f.Close()
			return fmt.Errorf("写入站点发现日志 %s: %w", a.path, err)
		}
		flushed++
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return fmt.Errorf("冲刷站点发现日志 %s: %w", a.path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭站点发现日志 %s: %w", a.path, err)
	}
	if a.stats != nil {
		a.stats.DiscoveryFlushed.Add(flushed)
	}
	return nil
}

func (a *DiscoveryAggregator) logFlushErr(err error) {
	if a.stats != nil {
		a.stats.DiscoveryErrors.Add(1)
	}
	log.Printf("[mirrorcap] 站点发现落盘失败（窗口已重置）: %v", err)
}

// DiscoverySniffer 发现流协议嗅探器：绑定聚合器与接口 source_mode（每发现接口一实例）。
type DiscoverySniffer struct {
	agg      *DiscoveryAggregator
	mode     string
	maxBytes int // 单流嗅探读取上限
}

// newDiscoverySniffer 构建嗅探器（mode 空取 MIRROR——旁路采集器原生模式）。
func newDiscoverySniffer(agg *DiscoveryAggregator, mode string) *DiscoverySniffer {
	if mode == "" {
		mode = "MIRROR"
	}
	return &DiscoverySniffer{agg: agg, mode: mode, maxBytes: defaultSniffMaxBytes}
}

// Sniff 首包分类 → 提取域名 → Observe → 排空流剩余内容。
// 在流读取 goroutine 内同步执行；读取总量上限 maxBytes（护栏），每条流只判定一次。
// 响应方向流（HTTP 状态行/ServerHello）在分类处被识别，不会产出记录。
func (s *DiscoverySniffer) Sniff(rs io.Reader, meta FlowMeta) {
	br := bufio.NewReaderSize(io.LimitReader(rs, int64(s.maxBytes)), 4096)
	// 短读容忍：流首包不足 16B 时以已缓冲字节判定（err 吞掉是有意的——分类只看字节）
	head, _ := br.Peek(sniffPeekBytes)
	switch classifyFlowHead(head) {
	case protoHTTP:
		// HTTP：读一个请求取 Host；解析失败仍按 IP:Port 资产记录（域名未识别为空串）
		domain := ""
		if req, err := http.ReadRequest(br); err == nil {
			domain = hostOnly(req.Host)
		}
		if s.agg != nil {
			s.agg.observe(s.mode, domain, meta, protoHTTP)
		}
	case protoHTTPS:
		// TLS：取 SNI；false = 非 ClientHello（含响应方向 ServerHello）/畸形/截断，不记录
		if sni, ok := ParseClientHelloSNI(br, s.maxBytes); ok && s.agg != nil {
			s.agg.observe(s.mode, sni, meta, protoHTTPS)
		}
	default:
		// 非 HTTP/TLS：不识别，不记录
	}
	// 排空剩余字节：嗅探只取首包，不排空会反压该流的重组消费（LossErrors 纪律不变）
	_, _ = io.Copy(io.Discard, rs)
}

// httpMethodPrefixes 请求行方法前缀（含空格，避免误匹配如 "GETTING"）。
var httpMethodPrefixes = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "),
	[]byte("OPTIONS "), []byte("PATCH "), []byte("TRACE "), []byte("CONNECT "),
}

// classifyFlowHead 首包协议分类：HTTP 方法前缀 → HTTP；0x16 0x03 → TLS(handshake)；
// 其余（含 HTTP 响应行 "HTTP/1.1 ..."、SSH、二进制协议）→ 空串不识别。
func classifyFlowHead(head []byte) string {
	for _, m := range httpMethodPrefixes {
		if bytes.HasPrefix(head, m) {
			return protoHTTP
		}
	}
	if len(head) >= 2 && head[0] == 0x16 && head[1] == 0x03 {
		return protoHTTPS
	}
	return ""
}
