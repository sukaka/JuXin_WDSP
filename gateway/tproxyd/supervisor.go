// 配置文件监督器：轮询发布链路下发文件（默认 15s），驱动牵引服务启停与热切换。
//
// 状态语义（进程永不因配置变化退出，启停切换全部在线完成）：
//   - 文件存在且 enabled=true → 以文件 listen/target 起监听；已监听同地址同下游
//     则不重启（重复轮询幂等）；地址变化先优雅停旧再起新；
//   - 文件 enabled=false / 文件曾生效后被删除 → 优雅关闭监听，进入空转
//     （idle，状态日志显式说明；串接链路 fail-open 由编排层看门狗负责）；
//   - 文件从未出现 → env 模式（PoC/lab 路径）：按环境变量配置启动并保持；
//   - 文件解析/校验失败 → 保留上一份生效配置（last-good），显式告警；
//   - 服务异常退出 → 告警并在同一轮询周期内按当前配置重建。
//
// 并发模型：Run 循环串行执行 tick（无重入）；Close 与 tick 经 mu 互斥。
package tproxyd

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"sync"
	"time"
)

// ServerRunner 牵引服务抽象（生产为 *Server；测试注入桩）。
type ServerRunner interface {
	// Addr 实际监听地址（测试取动态端口用）。
	Addr() string
	// Serve accept 主循环；Shutdown 关闭监听后返回 nil。
	Serve() error
	// Shutdown 优雅退出：关监听 → 宽限等待在途连接 → 超时强制断开。
	Shutdown(grace time.Duration)
}

// ServerFactory 牵引服务工厂（生产为 NewServer 适配；测试注入桩）。
type ServerFactory func(cfg Config, stats *Stats) (ServerRunner, error)

// Supervisor 配置文件监督器（goroutine 安全）。
type Supervisor struct {
	base     Config
	baseErr  error // env 基线不可用原因（仅日志；文件到达后仍可生效）
	filePath string
	interval time.Duration
	stats    *Stats
	factory  ServerFactory

	mu        sync.Mutex
	stopCh    chan struct{}
	closed    bool
	everFile  bool // 文件曾成功解析（此后删除文件 = 收回配置 → 空转，不再回落 env）
	srv       ServerRunner
	done      chan error
	drained   bool   // done 已被探活消费（stopLocked 不再重复等待）
	key       string // listen→target 指纹：相同则不重启
	grace     time.Duration
	lastState string // 上次已日志记录的状态指纹（防止每周期刷屏）
	lastErr   string
}

// NewSupervisor 构建监督器。base 为 env 基线配置；baseErr 非空表示 env 不可用
// （此时无文件期间保持空转并等待下发，不退出进程）。interval <= 0 取默认 15s。
func NewSupervisor(base Config, baseErr error, filePath string, interval time.Duration, stats *Stats, factory ServerFactory) *Supervisor {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &Supervisor{
		base: base, baseErr: baseErr, filePath: filePath, interval: interval,
		stats: stats, factory: factory,
		stopCh: make(chan struct{}),
	}
}

// desired 一次轮询解析出的期望状态。
type desired struct {
	enabled bool
	cfg     Config
	ports   []uint16 // 文件携带的牵引端口集合（信息性：编排层 REDIRECT 规则依据）
	source  string   // file / file-disabled / file-deleted / env / env-invalid（日志用）
}

// stateKey 状态指纹（ports 排序后参与，避免顺序抖动引起重复日志）。
func (d desired) stateKey() string {
	if !d.enabled {
		return "idle:" + d.source
	}
	ports := append([]uint16(nil), d.ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return fmt.Sprintf("run:%s:%s:ports=%v", d.source, cfgKey(d.cfg), ports)
}

// cfgKey 监听配置指纹（listen/target/target_tls/protect_hosts/passthrough_allowlist 全参与：
// 任一变化都需重启监听生效）。
func cfgKey(cfg Config) string {
	return fmt.Sprintf("%s→%s,tls→%s,protect=%v,passthrough=%v", cfg.Listen, cfg.Target, cfg.TargetTLS, cfg.ProtectHosts, cfg.PassthroughAllowlist)
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

// Close 停止监督并优雅关闭在运服务（幂等）。
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.stopCh)
	if s.srv != nil {
		s.stopLocked()
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
			log.Printf("[tproxyd] 配置文件不可用，保留当前状态: %v", err)
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
		if !fc.Enabled {
			return desired{enabled: false, ports: fc.Ports, source: "file-disabled"}, nil
		}
		cfg := s.base
		if fc.Listen != "" {
			cfg.Listen = fc.Listen
		}
		if fc.Target != "" {
			cfg.Target = fc.Target
		}
		if fc.TargetTLS != "" {
			cfg.TargetTLS = fc.TargetTLS
		}
		if len(fc.ProtectHosts) > 0 {
			cfg.ProtectHosts = fc.ProtectHosts
		}
		if fc.PassthroughAllowlist != nil {
			cfg.PassthroughAllowlist = fc.PassthroughAllowlist
		}
		if err := cfg.Validate(); err != nil {
			return desired{}, fmt.Errorf("下发配置叠加 env 基线后校验失败: %w", err)
		}
		return desired{enabled: true, cfg: cfg, ports: fc.Ports, source: "file"}, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		if s.everFile {
			// 发布方收回配置：关闭监听进入空转（进程不退出）
			return desired{enabled: false, source: "file-deleted"}, nil
		}
		if s.baseErr != nil {
			// env 不可用：空转等待下发文件
			return desired{enabled: false, source: "env-invalid"}, nil
		}
		return desired{enabled: true, cfg: s.base, source: "env"}, nil
	}
	return desired{}, err
}

// applyLocked 把当前运行时状态收敛到期望状态（仅差异部分有动作，重复调用幂等）。
func (s *Supervisor) applyLocked(d desired) {
	state := d.stateKey()
	changed := state != s.lastState
	defer func() { s.lastState = state }()

	if !d.enabled {
		if s.srv != nil {
			log.Printf("[tproxyd] 关闭监听进入空转（source=%s）", d.source)
			s.stopLocked()
		} else if changed {
			log.Printf("[tproxyd] 空转中（source=%s）：无生效牵引配置", d.source)
		}
		return
	}

	key := cfgKey(d.cfg)
	if s.srv != nil {
		// 探活：Serve 意外退出（监听被外部关闭等）则按当前配置重建
		alive := true
		select {
		case err := <-s.done:
			log.Printf("[tproxyd] 服务意外退出（%v）", err)
			alive = false
			s.drained = true
		default:
		}
		if alive && s.key == key {
			return // 已监听同地址同下游：不重启
		}
		if alive {
			log.Printf("[tproxyd] 监听配置变化 %s → %s（source=%s），重启牵引服务", s.key, key, d.source)
		} else {
			log.Printf("[tproxyd] 按配置重建牵引服务（listen=%s target=%s）", d.cfg.Listen, d.cfg.Target)
		}
		s.stopLocked()
	}
	if err := s.startLocked(d.cfg); err != nil {
		log.Printf("[tproxyd] 启动失败（下周期重试）: %v", err)
		return
	}
	if changed {
		log.Printf("[tproxyd] 生效配置：source=%s listen=%s target=%s target_tls=%s protect_hosts=%v passthrough_allowlist=%v redirect_ports=%v",
			d.source, d.cfg.Listen, d.cfg.Target, d.cfg.TargetTLS, d.cfg.ProtectHosts, d.cfg.PassthroughAllowlist, d.ports)
	}
}

// startLocked 绑定监听并启动 accept 主循环 goroutine。
func (s *Supervisor) startLocked(cfg Config) error {
	srv, err := s.factory(cfg, s.stats)
	if err != nil {
		return err
	}
	s.srv = srv
	s.key = cfgKey(cfg)
	s.grace = cfg.ShutdownGrace
	s.done = make(chan error, 1)
	s.drained = false
	go func() { s.done <- srv.Serve() }()
	return nil
}

// stopLocked 优雅关闭在运服务并等待主循环退出（资源释放确定性）。
// done 已被探活消费时跳过等待（Serve 已退出，Shutdown 仅收殓在途连接）。
func (s *Supervisor) stopLocked() {
	s.srv.Shutdown(s.grace)
	if !s.drained {
		<-s.done
	}
	s.srv = nil
	s.drained = false
}
