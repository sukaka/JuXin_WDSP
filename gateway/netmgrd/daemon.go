// 配置文件轮询监督器：默认 15s 感知发布链路下发，驱动幂等执行与状态回写。
//
// 状态语义（进程永不因配置/执行失败退出，不 crash-loop）：
//   - 文件不存在 → 等待下发（空转；曾生效后被删除 = 发布方收回，保留主机上
//     已下发网络状态不拆除，日志显式说明）；
//   - 文件解析/校验失败 → 整份拒绝，保留 last-good，status 显式报错；
//   - 配置指纹变化 → 执行一次并回写 status；指纹不变且上次执行成功 → 跳过
//     （幂等，不重写 status）；
//   - 上次执行存在失败项 → 按轮询周期重试（自愈瞬态故障，如成员口后插入），
//     直到成功或配置变化。
//
// 并发模型：Run 循环串行执行 tick（无重入）；Close 幂等停止。
package netmgrd

import (
	"context"
	"errors"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Supervisor 配置轮询监督器。
type Supervisor struct {
	// ConfigPath 期望配置文件路径（network.json）。
	ConfigPath string
	// StatusPath 状态回写路径（network-status.json）。
	StatusPath string
	// Interval 轮询周期（<=0 取 DefaultPollInterval）。
	Interval time.Duration
	// Runner 命令执行器（生产 ExecRunner；测试注入桩）。
	Runner Runner
	// LinkPairs 端口联动监控器（NewSupervisor 自动创建；测试可替换参数）。
	LinkPairs *LinkPairMonitor
	// Diag 网络诊断服务（NewSupervisor 自动创建，目录为 <sidecarDir>/diag；
	// NodeName 缺省空 = 认领全部节点，main 经 --node/NODE_NAME 注入）。
	Diag *DiagService

	mu        sync.Mutex
	stopCh    chan struct{}
	closed    bool
	lastFP    string // 上次执行的配置指纹
	lastOK    bool   // 上次执行是否全项成功
	lastLog   string // 上次已记录日志的键（防每周期刷屏）
	everSeen  bool   // 配置文件曾出现（此后删除 = 收回配置，日志口径不同）
	ready     bool
	lastCheck time.Time
}

// NewSupervisor 构建监督器。
func NewSupervisor(configPath, statusPath string, interval time.Duration, r Runner) *Supervisor {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	return &Supervisor{
		ConfigPath: configPath, StatusPath: statusPath,
		Interval: interval, Runner: r,
		LinkPairs: NewLinkPairMonitor(statusPath, r),
		Diag:      NewDiagService(filepath.Join(filepath.Dir(configPath), "diag"), "", DefaultDiagInterval),
		stopCh:    make(chan struct{}),
	}
}

// Run 阻塞运行监督循环：启动即执行一次 tick，此后每 Interval 轮询，直到 Close。
// 端口联动监控器与诊断服务以独立 goroutine 随监督循环启动/停止。
func (s *Supervisor) Run() {
	go s.LinkPairs.Run()
	go s.Diag.Run()
	s.tick()
	t := time.NewTicker(s.Interval)
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

// Close 停止监督（幂等；不拆除任何网络状态——拆除属高危变更，运维显式处理）。
func (s *Supervisor) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stopCh)
	s.mu.Unlock()
	s.LinkPairs.Close()
	s.Diag.Close()
}

// logOnce 同一键的日志只打一次（键变化时再打），防轮询刷屏。
func (s *Supervisor) logOnce(key, format string, args ...any) {
	if s.lastLog == key {
		return
	}
	s.lastLog = key
	log.Printf("[netmgrd] "+format, args...)
}

func (s *Supervisor) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.ready = false
	defer func() { s.lastCheck = time.Now() }()

	cfg, err := LoadConfig(s.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		if s.everSeen {
			s.logOnce("deleted", "配置文件已被删除（发布方收回）：保留主机已下发网络状态，不拆除网桥/路由（高危变更由运维显式处理）")
		} else {
			s.logOnce("waiting", "等待配置下发: %s", s.ConfigPath)
		}
		s.ready = true
		return
	}
	if err != nil {
		s.logOnce("badcfg", "配置不可用，保留上次生效配置: %v", err)
		// 显式写 status：消费方需要看到「下发被拒」而非过期成功
		werr := WriteStatusAtomic(s.StatusPath, Status{
			AppliedAt: time.Now().UTC().Format(time.RFC3339),
			OK:        false,
			Bridges:   make([]BridgeStatus, 0),
			IPForward: StateSkipped,
			Routes:    make([]RouteStatus, 0),
			Message:   "配置不可用（保留上次生效配置）: " + err.Error(),
		})
		if werr != nil {
			log.Printf("[netmgrd] 状态回写失败: %v", werr)
		}
		return
	}
	s.everSeen = true
	// 端口联动期望跟随最近一份成功解析的配置（与 last-good 语义一致：
	// 解析失败/文件删除时监控器沿用上一份配置继续运行）。
	s.LinkPairs.SetConfig(cfg.Bridges, cfg.UpdatedAt)

	fp := cfg.fingerprint()
	if fp == s.lastFP && s.lastOK {
		s.ready = true
		return // 指纹不变且上次成功：幂等跳过（不重写 status）
	}
	st := Apply(context.Background(), cfg, s.Runner, time.Now())
	if werr := WriteStatusAtomic(s.StatusPath, st); werr != nil {
		log.Printf("[netmgrd] 状态回写失败: %v", werr)
		// 不更新 lastFP/lastOK：下周期重试执行与回写
		return
	}
	s.lastFP = fp
	s.lastOK = st.OK
	s.ready = st.OK
	if st.OK {
		s.logOnce("applied:"+fp, "已生效: bridges=%d ip_forward=%s routes=%d",
			len(cfg.Bridges), st.IPForward, len(cfg.Routes))
	} else {
		s.logOnce("failed:"+fp+st.Message, "执行存在失败项（按周期重试）: %s", st.Message)
	}
}
