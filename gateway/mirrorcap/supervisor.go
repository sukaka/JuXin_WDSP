// 配置文件监督器：轮询发布链路下发文件（默认 15s），驱动抓包启停与热更新。
//
// 状态语义（进程永不因配置变化退出，启停切换全部在线完成）：
//   - 检测与站点发现为两个独立功能，分别由 enabled 与 discovery.enabled 驱动启停，
//     互不牵连（检测沿用端口集合过滤；发现抓全端口 TCP 流做首包嗅探）；
//   - 文件存在且功能开启 → 以文件配置为准启动/更新抓包：接口集合变化增量起停抓包
//     句柄，端口集合变化热更新过滤（句柄不重启、流不中断）；
//   - 同一接口同时承担检测与发现角色时共用一个抓包句柄（绝不对同一 ifname 开两个
//     AF_PACKET socket），流工厂按目的端口分流两类消费（见 stream.go）；
//   - 文件双功能全禁 / 文件曾生效后被删除 → 关闭全部抓包句柄与输出文件，进入空转
//     （idle，状态日志显式说明）；单功能禁用只收敛该功能资源，另一功能保持运行；
//   - 文件从未出现 → env 模式（PoC/lab 路径）：按环境变量配置启动并保持；
//   - 文件解析/校验失败 → 保留上一份生效配置（last-good），显式告警；
//   - 抓包句柄异常退出（接口抖动等）→ 告警并在同一轮询周期内按当前角色重建。
//
// 并发模型：Run 循环串行执行 tick（无重入）；Close/StatsFunc 与 tick 经 mu 互斥。
package mirrorcap

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
)

// Runner 单接口抓包执行体抽象（生产为 *Capture；测试注入桩）。
type Runner interface {
	// Run 阻塞运行抓包主循环，直到 Close 或不可恢复错误。
	Run() error
	// Close 停止抓包并释放句柄（幂等）。
	Close() error
	// SetPorts 热更新目标端口过滤集合（句柄不重启，在途流不中断）。
	SetPorts(ports []uint16)
	// StatsFunc 内核 socket 统计读取闭包（非 Linux 平台为 nil）。
	StatsFunc() func() (packets, drops uint32, err error)
}

// EventsFactory 事件日志工厂（生产为 apievents.NewLogger）。
type EventsFactory func(path, node string) (*apievents.Logger, error)

// DetectorFactory 检测器工厂（生产为 NewDetector；测试注入桩避免加载规则集）。
type DetectorFactory func(cfg Config, events *apievents.Logger, stats *Stats) (RequestHandler, error)

// RunnerFactory 抓包句柄工厂（生产为 NewCapture 适配；测试注入桩）。
// consumer 承载该接口的消费组合：检测与发现可叠加于同一句柄（共享 socket）。
type RunnerFactory func(cfg Config, consumer IfaceConsumer, stats *Stats) (Runner, error)

// handle 运行中的单接口句柄。
type handle struct {
	runner   Runner
	done     chan error        // Run 退出时回传结果（缓冲 1，goroutine 不泄漏）
	stopping bool              // 主动关闭标记（区分优雅停止与异常退出）
	handler  RequestHandler    // 创建时绑定的检测消费者（nil = 不承担检测角色）
	sniffer  *DiscoverySniffer // 创建时绑定的发现嗅探器（nil = 不承担发现角色）
}

// generation 一代生效配置占有的运行时资源（检测资源 + 发现资源 + 各接口句柄；
// 两功能资源相互独立，可单独收敛）。
type generation struct {
	// 检测资源（handler 非 nil = 检测运行中）
	events  *apievents.Logger
	handler RequestHandler
	ports   []uint16
	key     string // eventsLog|node 指纹：二者变化需重建检测资源（换事件文件必须先停写）
	// 发现资源（disc 非 nil = 发现运行中）
	disc *discoveryRuntime
	// 各接口抓包句柄（双角色接口只有一个句柄）
	runners map[string]*handle
}

// discoveryRuntime 发现功能运行时（聚合器 + 按接口绑定的嗅探器）。
type discoveryRuntime struct {
	agg      *DiscoveryAggregator
	sniffers map[string]*DiscoverySniffer // 接口名 → 嗅探器（mode 已绑定）
	key      string                       // log|flush|node|ifaces 指纹：变化需重建（换输出须先停写）
}

// Supervisor 配置文件监督器（goroutine 安全）。
type Supervisor struct {
	base     Config
	baseErr  error // env 基线不可用原因（仅日志；文件到达后仍可生效）
	filePath string
	interval time.Duration
	stats    *Stats

	newEvents   EventsFactory
	newDetector DetectorFactory
	newRunner   RunnerFactory

	mu        sync.Mutex
	stopCh    chan struct{}
	closed    bool
	everFile  bool // 文件曾成功解析（此后删除文件 = 收回配置 → 空转，不再回落 env）
	gen       *generation
	lastState string // 上次已日志记录的状态指纹（防止每周期刷屏）
	lastErr   string
}

// NewSupervisor 构建监督器。base 为 env 基线配置；baseErr 非空表示 env 不可用
// （此时无文件期间保持空转并等待下发，不退出进程）。interval <= 0 取默认 15s。
func NewSupervisor(base Config, baseErr error, filePath string, interval time.Duration, stats *Stats,
	ef EventsFactory, df DetectorFactory, rf RunnerFactory) *Supervisor {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &Supervisor{
		base: base, baseErr: baseErr, filePath: filePath, interval: interval, stats: stats,
		newEvents: ef, newDetector: df, newRunner: rf,
		stopCh: make(chan struct{}),
	}
}

// desired 一次轮询解析出的期望状态。
type desired struct {
	enabled bool     // 检测开关
	cfg     Config   // 生效基线（Iface 字段不用；接口集合见 ifaces）
	ifaces  []string // 期望检测抓包接口集合（已去重）
	source  string   // file / file-disabled / file-deleted / env / env-invalid（日志用）
	disc    discDesired
}

// discDesired 站点发现期望状态（enabled=false 时其余字段零值）。
type discDesired struct {
	enabled bool
	ifaces  []DiscoveryIface // 期望发现接口集合（name+mode，已去重）
	log     string
	flush   time.Duration
	node    string
}

// key 发现资源指纹（log/flush/node/接口集合任一变化都需重建聚合器与嗅探器绑定——
// 换输出文件必须先停写，接口 mode 变化需重绑嗅探器）。
func (d discDesired) key() string {
	parts := make([]string, 0, len(d.ifaces))
	for _, di := range d.ifaces {
		parts = append(parts, di.Name+":"+di.Mode)
	}
	sort.Strings(parts)
	return fmt.Sprintf("log=%s|flush=%s|node=%s|ifaces=%s", d.log, d.flush, d.node, strings.Join(parts, ","))
}

// stateKey 状态指纹（集合类字段排序后参与，避免顺序抖动引起重复日志）。
func (d desired) stateKey() string {
	ifs := append([]string(nil), d.ifaces...)
	sort.Strings(ifs)
	ports := append([]uint16(nil), d.cfg.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	doms := append([]string(nil), d.cfg.Domains...)
	sort.Strings(doms)
	return fmt.Sprintf("%s|enabled=%v|ifaces=%s|ports=%v|domains=%s|log=%s|audit=%s|rules=%s|node=%s|disc=%v|%s",
		d.source, d.enabled, strings.Join(ifs, ","), ports, strings.Join(doms, ","), d.cfg.EventsLog, d.cfg.AuditLog, d.cfg.RulesDir, d.cfg.NodeName,
		d.disc.enabled, d.disc.key())
}

// Run 阻塞运行监督循环：启动即应用一次，此后每 interval 轮询，直到 Close。
func (s *Supervisor) Run() {
	s.tick()
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-t.C:
			s.tick()
		}
	}
}

// Close 停止监督并释放全部运行时资源（幂等）。
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.stopCh)
	if s.gen != nil {
		s.teardownLocked()
	}
}

// StatsFunc 聚合各接口句柄的内核抓包统计（无句柄时返回全零；单口读取失败
// 跳过该口——与 Stats.Logger 对内核统计错误的既有容忍策略一致）。
func (s *Supervisor) StatsFunc() func() (packets, drops uint32, err error) {
	return func() (uint32, uint32, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		var p, d uint32
		if s.gen != nil {
			for _, h := range s.gen.runners {
				fn := h.runner.StatsFunc()
				if fn == nil {
					continue
				}
				pp, dd, err := fn()
				if err != nil {
					continue
				}
				p += pp
				d += dd
			}
		}
		return p, d, nil
	}
}

// tick 单轮：解析期望状态 → 应用差异。
func (s *Supervisor) tick() {
	d, err := s.resolve()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if err != nil {
		// 配置文件存在但不可用：保留上一份生效配置（last-good），显式告警
		if msg := err.Error(); msg != s.lastErr {
			log.Printf("[mirrorcap] 配置文件不可用，保留当前状态: %v", err)
			s.lastErr = msg
		}
		return
	}
	s.lastErr = ""
	if d.source == "file" || d.source == "file-disabled" {
		s.everFile = true
	}
	s.applyLocked(d)
}

// resolve 计算期望状态。返回错误表示配置文件存在但不可用（保留 last-good）。
func (s *Supervisor) resolve() (desired, error) {
	fc, err := LoadFileConfig(s.filePath)
	if err == nil {
		// 文件存在即文件优先
		cfg := fc.overlay(s.base)
		if !fc.Enabled && !cfg.Discovery.Enabled {
			// 检测与发现均关闭：空转
			return desired{source: "file-disabled"}, nil
		}
		d := desired{enabled: fc.Enabled, cfg: cfg, source: "file", disc: discDesiredFrom(cfg)}
		if fc.Enabled {
			d.ifaces = fc.Ifaces
		}
		return d, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if s.everFile {
			// 发布方收回配置：停止抓包进入空转（进程不退出）
			return desired{source: "file-deleted"}, nil
		}
		if s.baseErr != nil {
			// env 不可用（如 MIRROR_IFACE 未设置）：空转等待下发文件
			return desired{source: "env-invalid"}, nil
		}
		return desired{enabled: true, cfg: s.base, ifaces: []string{s.base.Iface}, source: "env", disc: discDesiredFrom(s.base)}, nil
	}
	return desired{}, err
}

// discDesiredFrom 从生效配置提取发现期望状态（文件/env 两路径共用）。
func discDesiredFrom(cfg Config) discDesired {
	if !cfg.Discovery.Enabled {
		return discDesired{}
	}
	return discDesired{
		enabled: true,
		ifaces:  append([]DiscoveryIface(nil), cfg.Discovery.Ifaces...),
		log:     cfg.Discovery.Log,
		flush:   cfg.Discovery.FlushInterval,
		node:    cfg.NodeName,
	}
}

// applyLocked 把当前运行时状态收敛到期望状态（仅差异部分有动作，重复调用幂等）。
func (s *Supervisor) applyLocked(d desired) {
	state := d.stateKey()
	changed := state != s.lastState
	defer func() { s.lastState = state }()

	if !d.enabled && !d.disc.enabled {
		if s.gen != nil {
			log.Printf("[mirrorcap] 停止抓包进入空转（source=%s）：释放 %d 个接口句柄", d.source, len(s.gen.runners))
			s.teardownLocked()
		} else if changed {
			log.Printf("[mirrorcap] 空转中（source=%s）：无生效抓包配置", d.source)
		}
		return
	}

	if s.gen == nil {
		s.gen = &generation{runners: map[string]*handle{}}
	}

	// 检测资源收敛（独立启停；发现运行状态不受影响）
	if d.enabled {
		doms := append([]string(nil), d.cfg.Domains...)
		sort.Strings(doms)
		key := d.cfg.EventsLog + "|" + d.cfg.AuditLog + "|" + d.cfg.NodeName + "|" + d.cfg.RulesDir + "|" + strings.Join(doms, ",")
		if s.gen.handler == nil || s.gen.key != key {
			s.startDetectLocked(d, key)
		}
		// 端口集合变化：热更新过滤（句柄不重启，在途流不中断）
		if s.gen.handler != nil && !equalPortSet(s.gen.ports, d.cfg.Ports) {
			log.Printf("[mirrorcap] 端口集合更新 %v → %v（热更新过滤）", s.gen.ports, d.cfg.Ports)
			for _, h := range s.gen.runners {
				if h.handler != nil {
					h.runner.SetPorts(d.cfg.Ports)
				}
			}
			s.gen.ports = append([]uint16(nil), d.cfg.Ports...)
		}
	} else if s.gen.handler != nil {
		log.Printf("[mirrorcap] 检测已禁用：关闭检测资源（站点发现保持运行）")
		s.stopDetectLocked()
	}

	// 发现资源收敛（独立启停；检测运行状态不受影响）
	if d.disc.enabled {
		dkey := d.disc.key()
		if s.gen.disc == nil || s.gen.disc.key != dkey {
			s.startDiscoveryLocked(d, dkey)
		}
	} else if s.gen.disc != nil {
		log.Printf("[mirrorcap] 站点发现已禁用：停止发现资源（检测保持运行）")
		s.stopDiscoveryLocked()
	}

	// 句柄收敛：接口移出即关闭；角色或绑定消费者实例变化即重建（一口一句柄）
	s.reconcileHandlesLocked(d)

	// 异常退出句柄重建（接口抖动等；优雅停止的句柄已被 stopping 标记排除）
	for ifs, h := range s.gen.runners {
		if h.stopping {
			continue
		}
		select {
		case err := <-h.done:
			log.Printf("[mirrorcap] 接口 %s 抓包异常退出（%v），重建句柄", ifs, err)
			delete(s.gen.runners, ifs)
			_ = h.runner.Close() // Run 已退出（done 缓冲已收），仅收殓句柄资源
			s.startIfaceLocked(d, ifs, ifaceRole{detect: h.handler != nil, sniff: h.sniffer != nil})
		default:
		}
	}

	if changed {
		log.Printf("[mirrorcap] 生效配置：source=%s interfaces=%v ports=%v events_log=%s node=%s discovery(enabled=%v interfaces=%v log=%s flush=%s)",
			d.source, d.ifaces, d.cfg.Ports, d.cfg.EventsLog, d.cfg.NodeName,
			d.disc.enabled, d.disc.ifaces, d.disc.log, d.disc.flush)
	}
}

// ifaceRole 单接口期望角色（检测与发现可叠加于同一句柄）。
type ifaceRole struct {
	detect bool
	sniff  bool
}

// startDetectLocked 创建/换出检测资源（事件文件 + 检测器）。
// 先建后切：构建失败保留旧资源（last-good 风格），下周期重试；
// 构建成功则先停旧检测角色句柄（停写事件），再关旧事件文件。
func (s *Supervisor) startDetectLocked(d desired, key string) {
	events, err := s.newEvents(d.cfg.EventsLog, d.cfg.NodeName)
	if err != nil {
		log.Printf("[mirrorcap] 打开事件日志 %s: %v（下周期重试）", d.cfg.EventsLog, err)
		return
	}
	handler, err := s.newDetector(d.cfg, events, s.stats)
	if err != nil {
		_ = events.Close()
		log.Printf("[mirrorcap] 构建检测器: %v（下周期重试）", err)
		return
	}
	// 检测路径顺带记发现：注入当前发现聚合器（未启用则为 nil，Detector 跳过）
	if o, ok := handler.(DiscoveryObserver); ok {
		o.SetDiscovery(s.currentAggLocked())
	}
	if s.gen.handler != nil {
		for ifs, h := range s.gen.runners {
			if h.handler != nil {
				s.stopHandleLocked(h)
				delete(s.gen.runners, ifs)
			}
		}
	}
	if s.gen.events != nil {
		if err := s.gen.events.Close(); err != nil {
			log.Printf("[mirrorcap] 关闭旧事件日志失败: %v", err)
		}
	}
	s.gen.events = events
	s.gen.handler = handler
	s.gen.key = key
	s.gen.ports = append([]uint16(nil), d.cfg.Ports...)
}

// stopDetectLocked 关闭检测资源：停检测角色句柄（发现角色句柄由收敛重建保留其余角色），
// 关事件文件。发现功能不受影响。
func (s *Supervisor) stopDetectLocked() {
	for ifs, h := range s.gen.runners {
		if h.handler != nil {
			s.stopHandleLocked(h)
			delete(s.gen.runners, ifs)
		}
	}
	if s.gen.events != nil {
		if err := s.gen.events.Close(); err != nil {
			log.Printf("[mirrorcap] 关闭事件日志失败: %v", err)
		}
	}
	s.gen.events = nil
	s.gen.handler = nil
	s.gen.key = ""
	s.gen.ports = nil
}

// startDiscoveryLocked 创建/换出发现资源（聚合器 + 按接口嗅探器）。
// 先建后切：构建失败保留旧资源，下周期重试；构建成功则先停旧发现角色句柄
// （停观察写入），再关旧聚合器（Close 内做最终冲刷）。
func (s *Supervisor) startDiscoveryLocked(d desired, key string) {
	// 聚合器默认 source_mode 取首个发现接口的 mode（供检测路径顺带记录使用；
	// 精确到接口的 mode 由各发现口嗅探器绑定）
	mode := "MIRROR"
	if len(d.disc.ifaces) > 0 && d.disc.ifaces[0].Mode != "" {
		mode = d.disc.ifaces[0].Mode
	}
	agg, err := NewDiscoveryAggregator(d.disc.node, mode, d.disc.log, d.disc.flush, s.stats)
	if err != nil {
		log.Printf("[mirrorcap] 站点发现输出不可用: %v（下周期重试）", err)
		return
	}
	sniffers := make(map[string]*DiscoverySniffer, len(d.disc.ifaces))
	for _, di := range d.disc.ifaces {
		sniffers[di.Name] = newDiscoverySniffer(agg, di.Mode)
	}
	if s.gen.disc != nil {
		for ifs, h := range s.gen.runners {
			if h.sniffer != nil {
				s.stopHandleLocked(h)
				delete(s.gen.runners, ifs)
			}
		}
		if err := s.gen.disc.agg.Close(); err != nil {
			log.Printf("[mirrorcap] 关闭站点发现聚合器失败: %v", err)
		}
	}
	s.gen.disc = &discoveryRuntime{agg: agg, sniffers: sniffers, key: key}
	// 检测器跨发现重建存活：同步换绑新聚合器（保持顺带发现指向当前输出）
	if o, ok := s.gen.handler.(DiscoveryObserver); ok {
		o.SetDiscovery(agg)
	}
	log.Printf("[mirrorcap] 站点发现已启动：interfaces=%v log=%s flush=%s", d.disc.ifaces, d.disc.log, d.disc.flush)
}

// stopDiscoveryLocked 关闭发现资源：停发现角色句柄，撤销检测路径注入，关聚合器
// （最终冲刷）。检测功能不受影响。
func (s *Supervisor) stopDiscoveryLocked() {
	for ifs, h := range s.gen.runners {
		if h.sniffer != nil {
			s.stopHandleLocked(h)
			delete(s.gen.runners, ifs)
		}
	}
	// 撤销检测路径的顺带发现注入（检测器继续持有已关闭聚合器会丢弃观察）
	if o, ok := s.gen.handler.(DiscoveryObserver); ok {
		o.SetDiscovery(nil)
	}
	if err := s.gen.disc.agg.Close(); err != nil {
		log.Printf("[mirrorcap] 关闭站点发现聚合器失败: %v", err)
	}
	s.gen.disc = nil
}

// currentAggLocked 当前发现聚合器（未启用为 nil）。
func (s *Supervisor) currentAggLocked() *DiscoveryAggregator {
	if s.gen != nil && s.gen.disc != nil {
		return s.gen.disc.agg
	}
	return nil
}

// reconcileHandlesLocked 接口句柄收敛：移出的关闭；角色或绑定消费者实例变化
// （检测器/发现聚合器重建导致实例换绑）的重建；缺失的创建。重复调用幂等。
func (s *Supervisor) reconcileHandlesLocked(d desired) {
	want := map[string]ifaceRole{}
	if d.enabled && s.gen.handler != nil {
		for _, ifs := range d.ifaces {
			want[ifs] = ifaceRole{detect: true}
		}
	}
	if d.disc.enabled && s.gen.disc != nil {
		for _, di := range d.disc.ifaces {
			r := want[di.Name]
			r.sniff = true
			want[di.Name] = r
		}
	}
	for ifs, h := range s.gen.runners {
		r, ok := want[ifs]
		if !ok {
			log.Printf("[mirrorcap] 接口 %s 移出配置，停止抓包", ifs)
			s.stopHandleLocked(h)
			delete(s.gen.runners, ifs)
			continue
		}
		curDetect, curSniff := h.handler != nil, h.sniffer != nil
		staleDetect := r.detect && h.handler != s.gen.handler
		staleSniff := r.sniff && (s.gen.disc == nil || h.sniffer != s.gen.disc.sniffers[ifs])
		if curDetect != r.detect || curSniff != r.sniff || staleDetect || staleSniff {
			log.Printf("[mirrorcap] 接口 %s 角色/消费者变更（detect=%v→%v sniff=%v→%v），重建句柄",
				ifs, curDetect, r.detect, curSniff, r.sniff)
			s.stopHandleLocked(h)
			delete(s.gen.runners, ifs)
		}
	}
	// 排序创建（句柄创建顺序确定，便于日志与测试比对）
	names := make([]string, 0, len(want))
	for ifs := range want {
		names = append(names, ifs)
	}
	sort.Strings(names)
	for _, ifs := range names {
		if _, ok := s.gen.runners[ifs]; !ok {
			s.startIfaceLocked(d, ifs, want[ifs])
		}
	}
}

// startIfaceLocked 为单个接口创建抓包句柄并启动主循环 goroutine。
// 双角色接口只建一个句柄（消费组合携带检测与发现两类消费者，共享 socket）。
// 创建失败仅告警（下周期重试），不影响其他接口。
func (s *Supervisor) startIfaceLocked(d desired, ifs string, role ifaceRole) {
	cfg := d.cfg
	cfg.Iface = ifs
	consumer := IfaceConsumer{}
	if role.detect {
		consumer.Detect = s.gen.handler
	}
	if role.sniff {
		consumer.Sniff = s.gen.disc.sniffers[ifs]
	}
	r, err := s.newRunner(cfg, consumer, s.stats)
	if err != nil {
		log.Printf("[mirrorcap] 接口 %s 抓包句柄创建失败（下周期重试）: %v", ifs, err)
		return
	}
	h := &handle{runner: r, done: make(chan error, 1), handler: consumer.Detect, sniffer: consumer.Sniff}
	s.gen.runners[ifs] = h
	go func() { h.done <- r.Run() }()
	log.Printf("[mirrorcap] 接口 %s 开始抓包（detect=%v sniff=%v ports=%v）", ifs, role.detect, role.sniff, d.cfg.Ports)
}

// stopHandleLocked 关闭句柄并等待其主循环退出（资源释放确定性）。
func (s *Supervisor) stopHandleLocked(h *handle) {
	h.stopping = true
	_ = h.runner.Close()
	<-h.done
}

// teardownLocked 释放整代资源：先停全部句柄（停写输出），再关事件文件与发现聚合器
// （聚合器 Close 内做最终冲刷）。
func (s *Supervisor) teardownLocked() {
	for _, h := range s.gen.runners {
		s.stopHandleLocked(h)
	}
	s.gen.runners = nil
	if s.gen.events != nil {
		if err := s.gen.events.Close(); err != nil {
			log.Printf("[mirrorcap] 关闭事件日志失败: %v", err)
		}
	}
	if s.gen.disc != nil {
		if err := s.gen.disc.agg.Close(); err != nil {
			log.Printf("[mirrorcap] 关闭站点发现聚合器失败: %v", err)
		}
	}
	s.gen = nil
}

// equalPortSet 端口集合相等判断（顺序无关）。
func equalPortSet(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[uint16]struct{}, len(a))
	for _, p := range a {
		seen[p] = struct{}{}
	}
	for _, p := range b {
		if _, ok := seen[p]; !ok {
			return false
		}
	}
	return true
}
