// 配置文件轮询监督器：默认 15s 感知发布链路下发，驱动幂等执行与状态回写。
//
// 状态语义（进程永不因配置/执行失败退出，不 crash-loop）：
//   - 文件不存在 → 等待下发（空转；曾生效后被删除 = 发布方收回，保留主机上
//     已下发网络状态不拆除，日志显式说明）；
//   - 文件解析/校验失败 → 整份拒绝，保留 last-good，status 显式报错；
//   - 配置指纹变化 → 执行一次并回写 status；指纹不变且上次执行成功且 status 正常 → 跳过
//     （幂等，不重写 status）；
//   - 从非法配置恢复到此前相同的合法配置 → 重新回写健康 status（不滞留 ok: false）；
//   - 上次执行存在失败项 → 按轮询周期重试（自愈瞬态故障，如成员口后插入），
//     直到成功或配置变化。
//
// 并发模型：Run 循环串行执行 tick（无重入）；Close 幂等停止；
// Supervisor / LinkPairMonitor / TransparentManager 共享互斥 StatusWriter 合并写 status。
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
	// StatusWriter 跨子系统共享的互斥状态写入器。
	StatusWriter *StatusWriter
	// LinkPairs 端口联动监控器（NewSupervisor 自动创建；测试可替换参数）。
	LinkPairs *LinkPairMonitor
	// Transparent 透明网桥 netfilter 牵引与 fail-open 看门狗（NewSupervisor 自动创建）。
	Transparent *TransparentManager
	// Diag 网络诊断服务（NewSupervisor 自动创建，目录为 <sidecarDir>/diag；
	// NodeName 缺省空 = 认领全部节点，main 经 --node/NODE_NAME 注入）。
	Diag *DiagService

	mu                sync.Mutex
	stopCh            chan struct{}
	closed            bool
	lastFP            string   // 上次执行的配置指纹
	lastOK            bool     // 上次执行是否全项成功
	lastStatusOK      bool     // 最近一次落盘的 Apply 状态是否健康（防坏配置恢复回同指纹后卡在 ok:false）
	lastAppliedStatus Status   // 最近一次成功 Apply 的状态快照（恢复同指纹时重写用）
	managedBridges    []string // 已纳管的网桥清单（用于配置移除后受控拆除）
	restoredManaged   bool     // 首轮已从历史 network-status.json 对齐 managed_bridges
	lastLog           string   // 上次已记录日志的键（防每周期刷屏）
	everSeen          bool     // 配置文件曾出现（此后删除 = 收回配置，日志口径不同）
	ready             bool
	lastCheck         time.Time
}

// NewSupervisor 构建监督器。
func NewSupervisor(configPath, statusPath string, interval time.Duration, r Runner) *Supervisor {
	if interval <= 0 {
		interval = DefaultPollInterval
	}
	sup := &Supervisor{
		ConfigPath: configPath, StatusPath: statusPath,
		Interval: interval, Runner: r,
		Diag:   NewDiagService(filepath.Join(filepath.Dir(configPath), "diag"), "", DefaultDiagInterval),
		stopCh: make(chan struct{}),
	}
	sup.StatusWriter = NewDynamicStatusWriter(func() string { return sup.StatusPath })
	lp := NewLinkPairMonitor(statusPath, r)
	lp.StatusWriter = sup.StatusWriter
	sup.LinkPairs = lp

	tproxydCfg := filepath.Join(filepath.Dir(configPath), "tproxyd.json")
	sup.Transparent = NewTransparentManager(tproxydCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, r, sup.StatusWriter)
	return sup
}

// Run 阻塞运行监督循环：启动即执行一次 tick，此后每 Interval 轮询，直到 Close。
// 端口联动监控器、透明牵引看门狗与诊断服务以独立 goroutine 随监督循环启动/停止。
func (s *Supervisor) Run() {
	s.tick()
	go s.LinkPairs.Run()
	go s.Transparent.Run()
	go s.Diag.Run()
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

// Close 停止监督（幂等；立即冲刷透明 REDIRECT 链确保 fail-open，不拆除网桥/路由）。
func (s *Supervisor) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stopCh)
	s.mu.Unlock()
	s.Transparent.Close()
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

	if !s.restoredManaged {
		s.restoredManaged = true
		if prev := s.StatusWriter.Read(); prev != nil && len(prev.ManagedBridges) > 0 {
			s.managedBridges = append([]string(nil), prev.ManagedBridges...)
		}
	}

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
		s.lastStatusOK = false
		// 显式写 status：消费方需要看到「下发被拒」而非过期成功（同时保留 link_pairs / transparent / managed_bridges）
		werr := s.StatusWriter.WriteApply(Status{
			AppliedAt: time.Now().UTC().Format(time.RFC3339),
			OK:        false,
			Bridges:   make([]BridgeStatus, 0),
			IPForward: StateSkipped,
			Routes:    make([]RouteStatus, 0),
			Message:   "配置不可用（保留上次生效配置）: " + err.Error(),
		}, true)
		if werr != nil {
			log.Printf("[netmgrd] 状态回写失败: %v", werr)
		}
		return
	}
	s.everSeen = true
	// 端口联动期望跟随最近一份成功解析的配置（与 last-good 语义一致：
	// 解析失败/文件删除时监控器沿用上一份配置继续运行）。
	s.LinkPairs.SetConfig(cfg.Bridges, cfg.UpdatedAt)

	bridgeNames := make([]string, 0, len(cfg.Bridges))
	for _, b := range cfg.Bridges {
		bridgeNames = append(bridgeNames, b.Name)
	}

	fp := cfg.fingerprint()
	if fp == s.lastFP && s.lastOK {
		s.Transparent.SetBridges(context.Background(), bridgeNames)
		if !s.lastStatusOK {
			// 从非法配置恢复回此前已生效的同指纹配置：重刷健康 status，避免滞留 ok: false
			restored := s.lastAppliedStatus
			restored.AppliedAt = time.Now().UTC().Format(time.RFC3339)
			if werr := s.StatusWriter.WriteApply(restored, false); werr != nil {
				log.Printf("[netmgrd] 恢复状态回写失败: %v", werr)
				return
			}
			s.lastStatusOK = true
			s.logOnce("recovered:"+fp, "配置已恢复为上次生效版本，状态已复位 ok=true")
		}
		s.ready = true
		return // 指纹不变且上次成功：幂等跳过（不重复执行网络变更）
	}

	// 若有已纳管网桥被从配置移除，先通知 TransparentManager 冲刷对应牵引规则，再拆除网桥
	s.Transparent.SetBridges(context.Background(), bridgeNames)

	st := ApplyWithOptions(context.Background(), cfg, s.Runner, time.Now(), ApplyOptions{
		HeldDownPorts:  s.LinkPairs.HeldDownPorts(),
		ManagedBridges: s.managedBridges,
	})
	if werr := s.StatusWriter.WriteApply(st, false); werr != nil {
		log.Printf("[netmgrd] 状态回写失败: %v", werr)
		// 不更新 lastFP/lastOK：下周期重试执行与回写
		return
	}
	s.managedBridges = append([]string(nil), st.ManagedBridges...)
	s.lastFP = fp
	s.lastOK = st.OK
	s.lastStatusOK = st.OK
	if st.OK {
		s.lastAppliedStatus = st
	}
	s.ready = st.OK
	if st.OK {
		s.logOnce("applied:"+fp, "已生效: bridges=%d ip_forward=%s routes=%d",
			len(cfg.Bridges), st.IPForward, len(cfg.Routes))
	} else {
		s.logOnce("failed:"+fp+st.Message, "执行存在失败项（按周期重试）: %s", st.Message)
	}
}
