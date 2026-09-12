// 主备 VIP 监督器：配置轮询驱动 keepalived 生命周期，状态轮询采集 VRRP 状态
// 与漂移事件，回写 ha-vip-status.json。
//
// 状态语义（进程永不因配置/执行失败退出，不 crash-loop）：
//   - 配置不存在 → STOPPED（曾生效后被删除 = 收回：停 keepalived 释放 VIP）；
//   - 配置解析/校验失败 → 保留 last-good，status 显式报错；
//   - 配置指纹变化 → 生成 keepalived 配置并启动/重载；DISABLED → 停止实例；
//   - 本机不在 members 中 → 配置非发本节点：停实例 + status 显式报错；
//   - keepalived 缺失/启动失败 → FAULT 状态如实呈现，按周期重试。
//
// 并发模型：configTick 与 stateTick 串行（同一 mu）；Close 幂等停止。
package havipd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Supervisor 主备 VIP 监督器。
type Supervisor struct {
	// Node 本机节点名（部署期注入，用于在 members[] 中定位自身优先级）。
	Node string
	// ConfigPath 期望配置文件路径（ha-vip.json）。
	ConfigPath string
	// StatusPath 状态回写路径（ha-vip-status.json）。
	StatusPath string
	// WorkDir keepalived 配置/pidfile 工作目录（一般与 sidecars 同卷子目录）。
	WorkDir string
	// ConfigInterval 配置轮询周期（<=0 取 DefaultPollInterval）。
	ConfigInterval time.Duration
	// StateInterval 状态采集周期（<=0 取 DefaultStateInterval）。
	StateInterval time.Duration
	// Runner 外部命令执行器（生产 ExecRunner；测试注入桩）。
	Runner Runner
	// Proc 进程信号/存活抽象（生产 SyscallProcess；测试注入桩）。
	Proc Process

	mu             sync.Mutex
	stopCh         chan struct{}
	closed         bool
	lastFP         string     // 上次应用的配置指纹
	cfg            *Config    // last-good 配置
	self           MemberSpec // 本机成员条目（last-good）
	state          string     // 当前 VRRP 运行状态
	vipsHeld       []string   // 本机当前持有 VIP（stateTick 刷新）
	events         []Event    // 漂移事件（新在前，上限 maxEvents）
	message        string     // 最近一次动作/异常说明
	appliedAt      time.Time
	lastTransition time.Time
	lastLog        string
}

// NewSupervisor 构建监督器。
func NewSupervisor(node, configPath, statusPath, workDir string, r Runner, p Process) *Supervisor {
	if p == nil {
		p = SyscallProcess{}
	}
	return &Supervisor{
		Node: node, ConfigPath: configPath, StatusPath: statusPath, WorkDir: workDir,
		Runner: r, Proc: p,
		state:  StateStopped,
		stopCh: make(chan struct{}),
	}
}

// Run 阻塞运行：启动即各执行一次 config/state tick，此后按周期轮询，直到 Close。
func (s *Supervisor) Run() {
	s.configTick()
	s.stateTick()
	cfgT := time.NewTicker(s.configInterval())
	stT := time.NewTicker(s.stateInterval())
	defer cfgT.Stop()
	defer stT.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-cfgT.C:
			s.configTick()
		case <-stT.C:
			s.stateTick()
		}
	}
}

// Close 停止监督（幂等）：先停本组件管理的 keepalived（VIP 随之释放）。
func (s *Supervisor) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stopCh)
	s.stopKeepalivedLocked()
	s.mu.Unlock()
}

// CloseWithoutStop 仅停止监督循环，不停 keepalived（测试与特殊运维路径）。
func (s *Supervisor) CloseWithoutStop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.stopCh)
}

func (s *Supervisor) configInterval() time.Duration {
	if s.ConfigInterval <= 0 {
		return DefaultPollInterval
	}
	return s.ConfigInterval
}

func (s *Supervisor) stateInterval() time.Duration {
	if s.StateInterval <= 0 {
		return DefaultStateInterval
	}
	return s.StateInterval
}

// logOnce 同一键日志只打一次（防轮询刷屏）。
func (s *Supervisor) logOnce(key, format string, args ...any) {
	if s.lastLog == key {
		return
	}
	s.lastLog = key
	log.Printf("[havipd] "+format, args...)
}

// ---------- 配置侧 ----------

// configTick 配置轮询：加载 → 校验 → 按指纹幂等应用（生成配置/启动/重载/停止）。
func (s *Supervisor) configTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	cfg, err := LoadConfig(s.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		// 收回语义：配置被删除 = 发布方收回主备能力 → 停实例释放 VIP（VIP 残留
		// 会导致双主/黑洞，比停机更危险）。
		if s.cfg != nil || s.keepalivedPidLocked() > 0 {
			log.Printf("[havipd] 配置已被删除（发布方收回）：停止 keepalived 并释放 VIP")
			s.stopKeepalivedLocked()
			s.cfg = nil
			s.lastFP = ""
			s.transitionLocked(StateStopped, "配置收回，实例停止")
		}
		return
	}
	if err != nil {
		s.logOnce("badcfg", "配置不可用，保留上次生效配置: %v", err)
		s.message = "配置不可用（保留上次生效配置）: " + err.Error()
		_ = s.writeStatusLocked()
		return
	}

	self, ok := cfg.selfMember(s.Node)
	if !ok {
		s.logOnce("notme:"+cfg.Group, "配置组 %s 不含本节点 %s（非发本节点），实例保持停止", cfg.Group, s.Node)
		s.stopKeepalivedLocked()
		s.cfg = nil
		s.lastFP = ""
		s.message = fmt.Sprintf("配置组 %s 的 members 不含本节点 %s", cfg.Group, s.Node)
		s.transitionLocked(StateStopped, s.message)
		return
	}

	fp := cfg.fingerprint()
	if fp == s.lastFP {
		return // 指纹不变：幂等跳过
	}
	s.cfg = &cfg
	s.self = self

	if cfg.State == ConfigDisabled {
		s.stopKeepalivedLocked()
		s.lastFP = fp
		s.appliedAt = time.Now()
		s.transitionLocked(StateDisabled, "配置 DISABLED，实例停止")
		return
	}

	// ENABLED：生成配置（unicast 源地址探测失败降级为省略该行，keepalived 自动选源）
	var selfSrc string
	if len(cfg.VRRP.UnicastPeers) > 0 {
		selfSrc, _, _ = s.queryIfaceAddrsLocked(cfg.VRRP.Iface)
	}
	paths := pathsFor(s.WorkDir, cfg.Group)
	if err := writeConfAtomic(paths.Conf, renderConfig(cfg, self, selfSrc)); err != nil {
		s.message = "生成 keepalived 配置失败: " + err.Error()
		_ = s.writeStatusLocked()
		return
	}

	pid := s.keepalivedPidLocked()
	switch {
	case pid > 0:
		// 运行中：SIGHUP 重载
		if err := s.Proc.Signal(pid, syscall.SIGHUP); err != nil {
			s.message = fmt.Sprintf("keepalived 重载失败（pid=%d）: %v", pid, err)
			_ = s.writeStatusLocked()
			return
		}
		s.message = fmt.Sprintf("配置已重载（keepalived pid=%d）", pid)
	default:
		if err := s.startKeepalivedLocked(paths); err != nil {
			s.message = "keepalived 启动失败: " + err.Error()
			s.transitionLocked(StateFault, s.message)
			return
		}
		s.message = "keepalived 已启动"
	}
	s.lastFP = fp
	s.appliedAt = time.Now()
	log.Printf("[havipd] 已应用: group=%s node=%s priority=%d vips=%d",
		cfg.Group, s.Node, self.Priority, len(cfg.VRRP.VIPs))
	_ = s.writeStatusLocked()
}

// ---------- 状态侧 ----------

// stateTick 状态轮询：keepalived 存活 + VIP 在位 → 推导运行状态，迁移记事件。
func (s *Supervisor) stateTick() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}

	running := s.keepalivedPidLocked() > 0
	var next string
	switch {
	case s.cfg == nil:
		next = StateStopped
		s.vipsHeld = nil
	case s.cfg.State == ConfigDisabled:
		next = StateDisabled
		s.vipsHeld = nil
	case !running:
		next = StateFault
		s.vipsHeld = nil
	default:
		var held []string
		_, addrs, err := s.queryIfaceAddrsLocked(s.cfg.VRRP.Iface)
		if err != nil {
			s.logOnce("addrerr", "网卡地址查询失败（本轮保持原状态）: %v", err)
			return
		}
		for _, vip := range s.cfg.VRRP.VIPs {
			if vipPresent([]string{vip}, addrs) {
				held = append(held, vip)
			}
		}
		if len(held) > 0 {
			next = StateMaster
		} else {
			next = StateBackup
		}
		s.vipsHeld = held
	}

	if next != s.state {
		detail := ""
		if next == StateMaster {
			detail = fmt.Sprintf("持有 VIP: %s", strings.Join(s.vipsHeld, ", "))
		}
		s.transitionLocked(next, detail)
		return
	}
	// 状态未变但持有集合可能变（多 VIP 部分在位）：如实刷新 status
	_ = s.writeStatusLocked()
}

// vipsHeld 本机当前持有 VIP（stateTick 内联字段，避免 Status 字段噪音）。
func (s *Supervisor) heldVIPs() []string { return s.vipsHeld }

// transitionLocked 状态迁移：更新状态 + 记事件 + 回写 status。
// 状态未变时仅更新说明（detail 非空），不记事件（防周期 tick 刷事件）。
func (s *Supervisor) transitionLocked(next, detail string) {
	if next == s.state {
		if detail != "" {
			s.message = detail
			_ = s.writeStatusLocked()
		}
		return
	}
	from := s.state
	s.state = next
	s.lastTransition = time.Now()
	s.events = append([]Event{{
		At:     s.lastTransition.UTC().Format(time.RFC3339),
		From:   from,
		To:     next,
		Detail: detail,
	}}, s.events...)
	if len(s.events) > maxEvents {
		s.events = s.events[:maxEvents]
	}
	log.Printf("[havipd] 状态迁移 %s → %s %s", from, next, detail)
	_ = s.writeStatusLocked()
}

// ---------- keepalived 生命周期 ----------

// keepalivedPidLocked 读 pidfile 并校验存活（不存活清理 stale pidfile）。
func (s *Supervisor) keepalivedPidLocked() int {
	if s.cfg == nil {
		// 无配置时仍可能残留实例：按工作目录下全部 pidfile 判定过于宽泛，
		// M2 单组语义下仅在持有组名时管理实例。
		return 0
	}
	return s.pidFromFileLocked(pathsFor(s.WorkDir, s.cfg.Group).PidFile)
}

// pidFromFileLocked 读指定 pidfile 并校验存活与身份。
func (s *Supervisor) pidFromFileLocked(pidFile string) int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0
	}
	if !s.Proc.Alive(pid) {
		_ = os.Remove(pidFile) // stale pidfile：清理，避免误判运行中
		return 0
	}
	// 防 PID 复用误信号：pidfile 中的 keepalived 死后 PID 被系统复用给其他进程时，
	// 仅凭存活判定会把 SIGHUP/SIGTERM 发给无关进程（lab 实测暴露）。
	if !procCommMatches(pid, "keepalived") {
		_ = os.Remove(pidFile)
		return 0
	}
	return pid
}

// procCommMatches /proc/<pid>/comm 身份校验（读失败按匹配处理——退回纯存活
// 判定语义，不放大误判面；测试注入的虚拟 PID 无 /proc 条目即走该回退）。
func procCommMatches(pid int, want string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return true
	}
	return strings.TrimSpace(string(data)) == want
}

// startKeepalivedLocked 启动实例（keepalived 自行 daemonize）。
func (s *Supervisor) startKeepalivedLocked(paths keepalivedPaths) error {
	if _, err := execLookPath("keepalived"); err != nil {
		return fmt.Errorf("keepalived 未安装或不在 PATH: %w", err)
	}
	_, err := s.Runner.Run(context.Background(), "keepalived",
		"-f", paths.Conf, "--pid", paths.PidFile)
	if err != nil {
		return err
	}
	return nil
}

// stopKeepalivedLocked 停止本组件管理的实例（SIGTERM，keepalived 释放 VIP）。
// 停止为同步语义：轮询等待进程退出（上限 3s）并清理 pidfile——否则 DISABLED 后
// 立即重新 ENABLED 时，可能向尚未退出的旧实例误发 SIGHUP（lab 实测暴露的竞态）。
func (s *Supervisor) stopKeepalivedLocked() {
	if s.cfg == nil {
		return
	}
	pidFile := pathsFor(s.WorkDir, s.cfg.Group).PidFile
	pid := s.pidFromFileLocked(pidFile)
	if pid <= 0 {
		return
	}
	if err := s.Proc.Signal(pid, syscall.SIGTERM); err != nil {
		s.logOnce("stoperr", "keepalived 停止失败（pid=%d）: %v", pid, err)
		return
	}
	for i := 0; i < 30; i++ {
		if !s.Proc.Alive(pid) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = os.Remove(pidFile) // keepalived 正常退出会自删；异常残留由本组件兜底清理
	log.Printf("[havipd] keepalived 已停止（pid=%d），VIP 已释放", pid)
}

// queryIfaceAddrsLocked 查询承载口地址（srcIP 用于 unicast，addrs 用于 VIP 在位判定）。
func (s *Supervisor) queryIfaceAddrsLocked(iface string) (string, []string, error) {
	out, err := s.Runner.Run(context.Background(), "ip", "-j", "addr", "show", "dev", iface)
	if err != nil {
		return "", nil, err
	}
	return parseAddrDump(out)
}

// writeStatusLocked 回写当前状态快照。
func (s *Supervisor) writeStatusLocked() error {
	st := Status{
		Node:              s.Node,
		State:             s.state,
		KeepalivedRunning: s.keepalivedPidLocked() > 0,
		VIPsPresent:       s.heldVIPs(),
		Events:            s.events,
		Message:           s.message,
		LastTransitionAt:  "",
	}
	if s.cfg != nil {
		st.Group = s.cfg.Group
		st.Priority = s.self.Priority
	}
	if !s.lastTransition.IsZero() {
		st.LastTransitionAt = s.lastTransition.UTC().Format(time.RFC3339)
	}
	if !s.appliedAt.IsZero() {
		st.AppliedAt = s.appliedAt.UTC().Format(time.RFC3339)
	}
	if err := WriteStatusAtomic(s.StatusPath, st); err != nil {
		s.logOnce("werr", "状态回写失败: %v", err)
		return err
	}
	return nil
}

// execLookPath 可执行文件探测（变量化便于测试注入）。
var execLookPath = exec.LookPath
