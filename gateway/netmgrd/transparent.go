// 透明网桥 netfilter 牵引（iptables 专用链）与 fail-open 看门狗。
//
// 职责：
//  1. 维护 3 条隔离的 iptables 专用链（argv 数组 + -w 5，零 shell，严格接口/端口白名单）：
//     - filter/JIUZHANG_TPROXY_FWD（挂 FORWARD）：对全部托管网桥放行 -i <br> -o <br> -j ACCEPT，
//       确保 Docker/firewalld FORWARD DROP 策略下 L2 网桥转发与 fail-open 流量畅通；
//     - filter/JIUZHANG_TPROXY_IN（挂 INPUT）：仅放行托管网桥上经 DNAT/REDIRECT 的目标端口，
//       -i <br> -p tcp --dport <listenPort> -m conntrack --ctstate DNAT -j ACCEPT；
//     - nat/JIUZHANG_TPROXY_PRE（挂 PREROUTING）：对非本机目的流量按配置端口 REDIRECT 到 tproxyd，
//       -i <br> -m addrtype ! --dst-type LOCAL -p tcp --dport <port> -j REDIRECT --to-ports <listenPort>。
//  2. 检查/尝试启用 net.bridge.bridge-nf-call-iptables=1（先读 /proc/sys，已是 1 跳过写入；
//     遇 EROFS 或缺失 br_netfilter 时降级回报 DEGRADED 而不崩溃 netmgrd）。
//  3. 每 2s 运行 fail-open 看门狗：仅当 tproxyd.json enabled=true、ports 非空、托管网桥非空、
//     bridge-nf-call-iptables=1、tproxyd /healthz listening=true 且 Caddy 可达时才安装/维持
//     JIUZHANG_TPROXY_PRE；连续 2 次探活失败、enabled=false、网桥移除或进程退出时立即冲刷
//     JIUZHANG_TPROXY_PRE（保留 JIUZHANG_TPROXY_FWD 使 L2 网桥无损 fail-open）。
package netmgrd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultTproxydHealthURL tproxyd 健康检查端点默认 URL。
	DefaultTproxydHealthURL = "http://127.0.0.1:15001/healthz"
	// DefaultCaddyAdminSocket Caddy Admin Unix Socket 默认路径。
	DefaultCaddyAdminSocket = "/var/run/caddy/admin.sock"
	// DefaultTransparentPollInterval fail-open 看门狗轮询周期。
	DefaultTransparentPollInterval = 2 * time.Second
	// defaultTproxydListenPort tproxyd.json 未指定 listen 时的默认 REDIRECT 目标端口。
	defaultTproxydListenPort uint16 = 15000
	// transparentFailOpenThreshold 连续探活失败达到该次数立即冲刷 REDIRECT 链。
	transparentFailOpenThreshold = 2

	tproxyChainFwd = "JIUZHANG_TPROXY_FWD"
	tproxyChainIn  = "JIUZHANG_TPROXY_IN"
	tproxyChainPre = "JIUZHANG_TPROXY_PRE"
)

// tproxydSidecarConfig netmgrd 读取 tproxyd.json 所需的最小子集。
type tproxydSidecarConfig struct {
	Enabled   bool     `json:"enabled"`
	Listen    string   `json:"listen"`
	Target    string   `json:"target"`
	TargetTLS string   `json:"target_tls"`
	Ports     []uint16 `json:"ports"`
}

// tproxydHealthResp tproxyd GET /healthz 响应契约。
type tproxydHealthResp struct {
	OK        bool   `json:"ok"`
	Enabled   bool   `json:"enabled"`
	Listening bool   `json:"listening"`
	Listen    string `json:"listen"`
}

// TransparentManager 透明网桥 netfilter 牵引管理器与 fail-open 看门狗。
type TransparentManager struct {
	// TproxydConfigPath tproxyd.json 路径（默认与 network.json 同目录）。
	TproxydConfigPath string
	// TproxydHealthURL tproxyd /healthz URL（默认 http://127.0.0.1:15001/healthz）。
	TproxydHealthURL string
	// CaddySocket Caddy Admin Unix Socket 路径（默认 /var/run/caddy/admin.sock）。
	CaddySocket string
	// Interval 看门狗轮询周期（<=0 取 DefaultTransparentPollInterval）。
	Interval time.Duration
	// Runner 命令执行器（iptables / sysctl / ProcSysReader）。
	Runner Runner
	// StatusWriter 跨组件共享的互斥状态写入器。
	StatusWriter *StatusWriter

	// 测试可注入探活与时钟钩子（nil 时使用生产默认实现）。
	probeTproxyd func(ctx context.Context) (tproxydHealthResp, error)
	probeCaddy   func(ctx context.Context, fallbackTargets ...string) error
	now          func() time.Time

	mu                  sync.Mutex
	bridges             []string // 当前托管网桥（已排序去重校验）
	stopCh              chan struct{}
	started             bool
	closed              bool
	probedExisting      bool // 启动后已完成一次只读内核链探测（捕获 SIGKILL 崩溃遗留规则）
	preFromRecovery     bool // preInstalled 来自启动遗留链探测（探活失败时立即 fail-open，不等 2 轮）
	everActive          bool // 是否曾观察到 tproxyd.json 或安装/探测到透明链
	fwdInstalled        bool
	inInstalled         bool
	preInstalled        bool
	appliedFwdKey       string
	appliedInKey        string
	appliedPreKey       string
	consecutiveFailures int
	lastStatusKey       string
	lastLog             string
}

// NewTransparentManager 创建透明牵引管理器。
func NewTransparentManager(tproxydConfigPath, tproxydHealthURL, caddySocket string, r Runner, sw *StatusWriter) *TransparentManager {
	if strings.TrimSpace(tproxydHealthURL) == "" {
		tproxydHealthURL = DefaultTproxydHealthURL
	}
	if strings.TrimSpace(caddySocket) == "" {
		caddySocket = DefaultCaddyAdminSocket
	}
	return &TransparentManager{
		TproxydConfigPath: tproxydConfigPath,
		TproxydHealthURL:  tproxydHealthURL,
		CaddySocket:       caddySocket,
		Interval:          DefaultTransparentPollInterval,
		Runner:            r,
		StatusWriter:      sw,
		stopCh:            make(chan struct{}),
		now:               time.Now,
	}
}

func (m *TransparentManager) interval() time.Duration {
	if m.Interval <= 0 {
		return DefaultTransparentPollInterval
	}
	return m.Interval
}

func (m *TransparentManager) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

func (m *TransparentManager) logOnce(key, format string, args ...any) {
	if m.lastLog == key {
		return
	}
	m.lastLog = key
	log.Printf("[netmgrd/transparent] "+format, args...)
}

// Run 阻塞运行 2s fail-open 看门狗循环，直到 Close。
func (m *TransparentManager) Run() {
	m.mu.Lock()
	if m.started || m.closed {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

	m.cycle(context.Background())
	t := time.NewTicker(m.interval())
	defer t.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-t.C:
			m.cycle(context.Background())
		}
	}
}

// Close 停止看门狗并立即冲刷 nat/JIUZHANG_TPROXY_PRE（保留 JIUZHANG_TPROXY_FWD 确保 fail-open）。
func (m *TransparentManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	close(m.stopCh)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	m.probeExistingChainsLocked(ctx)
	if m.preInstalled || m.inInstalled {
		m.flushInterceptLocked(ctx)
		log.Printf("[netmgrd/transparent] 进程退出，已冲刷 %s 与 %s（保留 %s 以 fail-open）",
			tproxyChainPre, tproxyChainIn, tproxyChainFwd)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateInactive,
			Enabled:        false,
			RedirectActive: false,
			Bridges:        append([]string(nil), m.bridges...),
			Message:        "netmgrd 退出，已冲刷透明牵引规则（L2 网桥 fail-open）",
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
	}
}

// SetBridges 更新当前期望/托管网桥集合。若有网桥被移除且已安装过透明规则，
// 会立即同步清理被移除网桥的牵引规则（供 Supervisor 在拆除网桥前调用）。
func (m *TransparentManager) SetBridges(ctx context.Context, bridges []string) {
	clean := normalizeBridgeNames(bridges)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	removed := hasRemovedBridge(m.bridges, clean)
	m.bridges = clean
	if !removed {
		return
	}
	m.probeExistingChainsLocked(ctx)
	if !m.preInstalled && !m.inInstalled && !m.fwdInstalled {
		return
	}
	if len(clean) == 0 {
		m.flushInterceptLocked(ctx)
		m.flushFwdLocked(ctx)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateInactive,
			Enabled:        false,
			RedirectActive: false,
			Message:        "托管网桥已全部移除，已清空透明牵引规则",
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}
	// 部分网桥移除：立即冲刷 PREROUTING/INPUT（由下一轮 cycle 按剩余桥重建），并同步收敛 FORWARD 链
	m.flushInterceptLocked(ctx)
	_ = m.ensureFwdLocked(ctx, clean)
}

// probeExistingChainsLocked 进程启动后执行一次只读内核链探测（-L -n），
// 若发现上次进程 SIGKILL 崩溃遗留的活动规则，标记为已安装以便 fail-open / disabled / 删配置路径可靠冲刷。
func (m *TransparentManager) probeExistingChainsLocked(ctx context.Context) {
	if m.probedExisting {
		return
	}
	m.probedExisting = true
	if m.Runner == nil {
		return
	}
	if out, err := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", "nat", "-L", tproxyChainPre, "-n"); err == nil && chainHasRules(out) {
		m.preInstalled = true
		m.preFromRecovery = true
		m.everActive = true
		log.Printf("[netmgrd/transparent] 启动探测到遗留 %s 活动规则，将按当前配置与探活结果收敛或冲刷", tproxyChainPre)
	}
	if out, err := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", "filter", "-L", tproxyChainIn, "-n"); err == nil && chainHasRules(out) {
		m.inInstalled = true
		m.everActive = true
	}
	if out, err := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", "filter", "-L", tproxyChainFwd, "-n"); err == nil && chainHasRules(out) {
		m.fwdInstalled = true
	}
}

// chainHasRules 判断 `iptables -L <chain> -n` 输出是否包含超过 2 行表头（Chain + target）的活动规则行。
func chainHasRules(out []byte) bool {
	lines := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		lines++
		if lines > 2 {
			return true
		}
	}
	return false
}

// cycle 推进一轮透明牵引收敛与 fail-open 探活（测试可直接调用）。
func (m *TransparentManager) cycle(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	if strings.TrimSpace(m.TproxydConfigPath) == "" {
		return
	}
	m.probeExistingChainsLocked(ctx)

	fc, listenPort, err := loadTproxydSidecar(m.TproxydConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		// 从未启用透明模式且无已装规则时保持静默零开销（不影响非透明部署与单测）
		if !m.everActive && !m.preInstalled && !m.inInstalled && !m.fwdInstalled {
			return
		}
		m.consecutiveFailures = 0
		m.flushInterceptLocked(ctx)
		if len(m.bridges) == 0 {
			m.flushFwdLocked(ctx)
		}
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateInactive,
			Enabled:        false,
			RedirectActive: false,
			Bridges:        append([]string(nil), m.bridges...),
			Message:        "tproxyd.json 不存在，已关闭透明牵引（fail-open）",
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}
	if err != nil {
		m.everActive = true
		m.consecutiveFailures = 0
		m.flushInterceptLocked(ctx)
		msg := fmt.Sprintf("tproxyd.json 解析/校验失败（已触发 fail-open）: %v", err)
		m.logOnce("bad-tproxyd-cfg:"+err.Error(), "%s", msg)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateDegraded,
			Enabled:        false,
			RedirectActive: false,
			Bridges:        append([]string(nil), m.bridges...),
			Message:        msg,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}

	m.everActive = true
	bridges := append([]string(nil), m.bridges...)

	// 1. 维护 filter/JIUZHANG_TPROXY_FWD：只要存在托管网桥即放行桥内 L2 转发（含 fail-open 与 disabled 态）
	if len(bridges) > 0 {
		if err := m.ensureFwdLocked(ctx, bridges); err != nil {
			m.flushInterceptLocked(ctx)
			msg := fmt.Sprintf("透明网桥 FORWARD 链配置失败（已降级，不阻塞进程）: %v", err)
			m.logOnce("fwd-err:"+err.Error(), "%s", msg)
			m.publishStatusLocked(&TransparentStatus{
				State:          TransparentStateDegraded,
				Enabled:        fc.Enabled,
				RedirectActive: false,
				ListenPort:     listenPort,
				Ports:          fc.Ports,
				Bridges:        bridges,
				Message:        msg,
				UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
			})
			return
		}
	} else if m.fwdInstalled {
		m.flushFwdLocked(ctx)
	}

	// 2. disabled / 无牵引端口 / 无托管网桥 → 立即冲刷 PREROUTING/INPUT 并进入 INACTIVE
	if !fc.Enabled || len(fc.Ports) == 0 || len(bridges) == 0 {
		m.consecutiveFailures = 0
		m.flushInterceptLocked(ctx)
		reason := "透明牵引未启用（tproxyd.json enabled=false）"
		if fc.Enabled && len(bridges) == 0 {
			reason = "未配置托管网桥，暂未安装透明牵引规则"
		} else if fc.Enabled && len(fc.Ports) == 0 {
			reason = "tproxyd.json 未声明牵引端口，暂未安装透明牵引规则"
		}
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateInactive,
			Enabled:        fc.Enabled,
			RedirectActive: false,
			ListenPort:     listenPort,
			Ports:          fc.Ports,
			Bridges:        bridges,
			Message:        reason,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}

	// 3. 检查并尝试启用 net.bridge.bridge-nf-call-iptables=1（只读优先，失败降级不崩溃）
	if err := ensureSysctl(ctx, m.Runner, "net.bridge.bridge-nf-call-iptables", "1"); err != nil {
		m.consecutiveFailures = 0
		m.flushInterceptLocked(ctx)
		msg := fmt.Sprintf("net.bridge.bridge-nf-call-iptables 未就绪（请加载 br_netfilter 并在宿主机设为 1）: %v", err)
		m.logOnce("brnf-err:"+err.Error(), "%s", msg)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateDegraded,
			Enabled:        true,
			RedirectActive: false,
			ListenPort:     listenPort,
			Ports:          fc.Ports,
			Bridges:        bridges,
			BridgeNFReady:  false,
			Message:        msg,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}

	// 4. 数据面探活（tproxyd /healthz listening=true + Caddy 可达）
	tproxydOK, tproxydErr := m.checkTproxyd(ctx)
	caddyErr := m.checkCaddy(ctx, fc.Target, fc.TargetTLS)
	caddyOK := caddyErr == nil

	if !tproxydOK || !caddyOK {
		m.consecutiveFailures++
		var reasons []string
		if !tproxydOK {
			reasons = append(reasons, fmt.Sprintf("tproxyd(%v)", tproxydErr))
		}
		if !caddyOK {
			reasons = append(reasons, fmt.Sprintf("caddy(%v)", caddyErr))
		}
		reasonStr := strings.Join(reasons, "; ")

		// 仅对本进程健康安装后的在运规则启用 2 次失败迟滞；
		// 若规则来自崩溃重启遗留探测（preFromRecovery），首轮探活失败即立刻 fail-open 冲刷。
		if m.preInstalled && !m.preFromRecovery && m.consecutiveFailures < transparentFailOpenThreshold {
			msg := fmt.Sprintf("数据面探活异常（第 %d/%d 次，达阈值将触发 fail-open）: %s",
				m.consecutiveFailures, transparentFailOpenThreshold, reasonStr)
			m.logOnce("probe-warn:"+reasonStr, "%s", msg)
			m.publishStatusLocked(&TransparentStatus{
				State:          TransparentStateDegraded,
				Enabled:        true,
				RedirectActive: true,
				ListenPort:     listenPort,
				Ports:          fc.Ports,
				Bridges:        bridges,
				TproxydHealthy: tproxydOK,
				CaddyHealthy:   caddyOK,
				BridgeNFReady:  true,
				Message:        msg,
				UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
			})
			return
		}

		// 已达连续 2 次失败阈值（或本就未安装）：冲刷 PREROUTING/INPUT 保证 L2 fail-open
		wasActive := m.preInstalled
		m.flushInterceptLocked(ctx)
		msg := "等待数据面就绪，暂未下发透明牵引规则: " + reasonStr
		if wasActive {
			msg = fmt.Sprintf("连续 %d 次探活失败，已触发 fail-open 冲刷 REDIRECT 规则: %s", m.consecutiveFailures, reasonStr)
		}
		m.logOnce("fail-open:"+reasonStr, "%s", msg)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateDegraded,
			Enabled:        true,
			RedirectActive: false,
			ListenPort:     listenPort,
			Ports:          fc.Ports,
			Bridges:        bridges,
			TproxydHealthy: tproxydOK,
			CaddyHealthy:   caddyOK,
			BridgeNFReady:  true,
			Message:        msg,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}

	// 5. 探活通过：安装/收敛 filter/JIUZHANG_TPROXY_IN 与 nat/JIUZHANG_TPROXY_PRE
	m.consecutiveFailures = 0
	if err := m.ensureInLocked(ctx, bridges, listenPort); err != nil {
		m.flushInterceptLocked(ctx)
		msg := fmt.Sprintf("透明牵引 INPUT 链配置失败（已回退 fail-open）: %v", err)
		m.logOnce("in-err:"+err.Error(), "%s", msg)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateDegraded,
			Enabled:        true,
			RedirectActive: false,
			ListenPort:     listenPort,
			Ports:          fc.Ports,
			Bridges:        bridges,
			TproxydHealthy: true,
			CaddyHealthy:   true,
			BridgeNFReady:  true,
			Message:        msg,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}
	if err := m.ensurePreLocked(ctx, bridges, listenPort, fc.Ports); err != nil {
		m.flushInterceptLocked(ctx)
		msg := fmt.Sprintf("透明牵引 PREROUTING REDIRECT 链配置失败（已回退 fail-open）: %v", err)
		m.logOnce("pre-err:"+err.Error(), "%s", msg)
		m.publishStatusLocked(&TransparentStatus{
			State:          TransparentStateDegraded,
			Enabled:        true,
			RedirectActive: false,
			ListenPort:     listenPort,
			Ports:          fc.Ports,
			Bridges:        bridges,
			TproxydHealthy: true,
			CaddyHealthy:   true,
			BridgeNFReady:  true,
			Message:        msg,
			UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
		})
		return
	}

	m.logOnce("active:"+m.appliedPreKey, "透明牵引规则已生效: bridges=%v ports=%v listen_port=%d", bridges, fc.Ports, listenPort)
	m.publishStatusLocked(&TransparentStatus{
		State:          TransparentStateActive,
		Enabled:        true,
		RedirectActive: true,
		ListenPort:     listenPort,
		Ports:          fc.Ports,
		Bridges:        bridges,
		TproxydHealthy: true,
		CaddyHealthy:   true,
		BridgeNFReady:  true,
		Message:        "透明牵引规则已生效",
		UpdatedAt:      m.nowTime().UTC().Format(time.RFC3339),
	})
}

func (m *TransparentManager) checkTproxyd(ctx context.Context) (bool, error) {
	fn := m.probeTproxyd
	if fn == nil {
		fn = m.defaultProbeTproxyd
	}
	resp, err := fn(ctx)
	if err != nil {
		return false, err
	}
	if !resp.OK {
		return false, errors.New("healthz ok=false")
	}
	if !resp.Listening {
		return false, errors.New("healthz listening=false")
	}
	return true, nil
}

func (m *TransparentManager) defaultProbeTproxyd(ctx context.Context) (tproxydHealthResp, error) {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.TproxydHealthURL, nil)
	if err != nil {
		return tproxydHealthResp{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return tproxydHealthResp{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return tproxydHealthResp{}, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var out tproxydHealthResp
	if err := json.Unmarshal(body, &out); err != nil {
		return tproxydHealthResp{}, fmt.Errorf("JSON 无效: %w", err)
	}
	return out, nil
}

func (m *TransparentManager) checkCaddy(ctx context.Context, fallbackTargets ...string) error {
	if m.probeCaddy != nil {
		return m.probeCaddy(ctx, fallbackTargets...)
	}
	return m.defaultProbeCaddy(ctx, fallbackTargets...)
}

func (m *TransparentManager) defaultProbeCaddy(ctx context.Context, fallbackTargets ...string) error {
	dialer := &net.Dialer{Timeout: 1500 * time.Millisecond}
	if sock := strings.TrimSpace(m.CaddySocket); sock != "" {
		if _, err := os.Stat(sock); err == nil {
			conn, derr := dialer.DialContext(ctx, "unix", sock)
			if derr != nil {
				return fmt.Errorf("admin socket %s 不可达: %w", sock, derr)
			}
			_ = conn.Close()
			return nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("检查 admin socket %s: %w", sock, err)
		}
	}
	// 当 admin.sock 未挂载时回退探测 tproxyd.json 中的回环下游端口
	for _, target := range fallbackTargets {
		t := strings.TrimSpace(target)
		if t == "" {
			continue
		}
		host, _, err := net.SplitHostPort(t)
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			continue
		}
		conn, derr := dialer.DialContext(ctx, "tcp", t)
		if derr == nil {
			_ = conn.Close()
			return nil
		}
	}
	return fmt.Errorf("admin socket %s 不存在且透明回环下游不可达", m.CaddySocket)
}

func (m *TransparentManager) ensureChainAndJump(ctx context.Context, table, chain, parent string) error {
	if _, err := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", table, "-L", chain, "-n"); err != nil {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", table, "-N", chain); err != nil {
			// 并发创建已存在时容错，仅当再次 -L 仍失败才报错
			if _, lerr := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", table, "-L", chain, "-n"); lerr != nil {
				return err
			}
		}
	}
	if _, err := m.Runner.Query(ctx, "iptables", "-w", "5", "-t", table, "-C", parent, "-j", chain); err != nil {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", table, "-I", parent, "1", "-j", chain); err != nil {
			return err
		}
	}
	return nil
}

func (m *TransparentManager) ensureFwdLocked(ctx context.Context, bridges []string) error {
	key := strings.Join(bridges, ",")
	if m.fwdInstalled && m.appliedFwdKey == key {
		return nil
	}
	if err := m.ensureChainAndJump(ctx, "filter", tproxyChainFwd, "FORWARD"); err != nil {
		return err
	}
	// 链已存在且即将写入规则：先标记脏态，避免中途失败时状态误判为未安装
	m.fwdInstalled = true
	m.appliedFwdKey = ""
	if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-F", tproxyChainFwd); err != nil {
		return err
	}
	for _, br := range bridges {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-A", tproxyChainFwd,
			"-i", br, "-o", br, "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	m.appliedFwdKey = key
	return nil
}

func (m *TransparentManager) ensureInLocked(ctx context.Context, bridges []string, listenPort uint16) error {
	key := fmt.Sprintf("%s|%d", strings.Join(bridges, ","), listenPort)
	if m.inInstalled && m.appliedInKey == key {
		return nil
	}
	if err := m.ensureChainAndJump(ctx, "filter", tproxyChainIn, "INPUT"); err != nil {
		return err
	}
	// 链已存在且即将写入规则：先置脏标记，确保后续任一条规则失败时 flushInterceptLocked 必然回滚冲刷
	m.inInstalled = true
	m.appliedInKey = ""
	if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-F", tproxyChainIn); err != nil {
		return err
	}
	portStr := strconv.Itoa(int(listenPort))
	for _, br := range bridges {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-A", tproxyChainIn,
			"-i", br, "-p", "tcp", "--dport", portStr, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	m.appliedInKey = key
	return nil
}

func (m *TransparentManager) ensurePreLocked(ctx context.Context, bridges []string, listenPort uint16, ports []uint16) error {
	key := fmt.Sprintf("%s|%d|%v", strings.Join(bridges, ","), listenPort, ports)
	if m.preInstalled && m.appliedPreKey == key {
		return nil
	}
	if err := m.ensureChainAndJump(ctx, "nat", tproxyChainPre, "PREROUTING"); err != nil {
		return err
	}
	// 链已存在且即将写入规则：先置脏标记，确保部分规则写入失败时调用方 flushInterceptLocked 立即完整回滚
	m.preInstalled = true
	m.appliedPreKey = ""
	if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "nat", "-F", tproxyChainPre); err != nil {
		return err
	}
	toPort := strconv.Itoa(int(listenPort))
	for _, br := range bridges {
		for _, p := range ports {
			pStr := strconv.Itoa(int(p))
			if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "nat", "-A", tproxyChainPre,
				"-i", br, "-m", "addrtype", "!", "--dst-type", "LOCAL",
				"-p", "tcp", "--dport", pStr, "-j", "REDIRECT", "--to-ports", toPort); err != nil {
				return err
			}
		}
	}
	m.appliedPreKey = key
	m.preFromRecovery = false
	return nil
}

// flushInterceptLocked 立即冲刷 PREROUTING 与 INPUT 链（保留 FORWARD 链以保证 L2 fail-open）。
func (m *TransparentManager) flushInterceptLocked(ctx context.Context) {
	if m.preInstalled {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "nat", "-F", tproxyChainPre); err != nil {
			log.Printf("[netmgrd/transparent] 冲刷 %s 失败: %v", tproxyChainPre, err)
		}
		m.preInstalled = false
		m.preFromRecovery = false
		m.appliedPreKey = ""
	}
	if m.inInstalled {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-F", tproxyChainIn); err != nil {
			log.Printf("[netmgrd/transparent] 冲刷 %s 失败: %v", tproxyChainIn, err)
		}
		m.inInstalled = false
		m.appliedInKey = ""
	}
}

func (m *TransparentManager) flushFwdLocked(ctx context.Context) {
	if m.fwdInstalled {
		if err := m.Runner.Exec(ctx, "iptables", "-w", "5", "-t", "filter", "-F", tproxyChainFwd); err != nil {
			log.Printf("[netmgrd/transparent] 冲刷 %s 失败: %v", tproxyChainFwd, err)
		}
		m.fwdInstalled = false
		m.appliedFwdKey = ""
	}
}

func (m *TransparentManager) publishStatusLocked(ts *TransparentStatus) {
	if m.StatusWriter == nil || ts == nil {
		return
	}
	// 仅在状态语义发生变化时写盘，避免每 2s 无意义重写 network-status.json
	key := fmt.Sprintf("%s|%v|%v|%d|%v|%v|%v|%v|%v|%s",
		ts.State, ts.Enabled, ts.RedirectActive, ts.ListenPort, ts.Ports, ts.Bridges,
		ts.TproxydHealthy, ts.CaddyHealthy, ts.BridgeNFReady, ts.Message)
	if key == m.lastStatusKey {
		return
	}
	if err := m.StatusWriter.WriteTransparent(ts); err != nil {
		m.logOnce("status-werr:"+err.Error(), "透明状态回写失败: %v", err)
		return
	}
	m.lastStatusKey = key
}

func loadTproxydSidecar(path string) (tproxydSidecarConfig, uint16, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tproxydSidecarConfig{}, 0, err
	}
	var fc tproxydSidecarConfig
	if err := json.Unmarshal(data, &fc); err != nil {
		return tproxydSidecarConfig{}, 0, fmt.Errorf("JSON 解析失败: %w", err)
	}
	listenPort := defaultTproxydListenPort
	if listen := strings.TrimSpace(fc.Listen); listen != "" {
		_, portStr, err := net.SplitHostPort(listen)
		if err != nil {
			return tproxydSidecarConfig{}, 0, fmt.Errorf("listen 地址非法 %q: %w", fc.Listen, err)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return tproxydSidecarConfig{}, 0, fmt.Errorf("listen 端口非法 %q", fc.Listen)
		}
		listenPort = uint16(p)
	}
	seen := make(map[uint16]struct{}, len(fc.Ports))
	ports := make([]uint16, 0, len(fc.Ports))
	for _, p := range fc.Ports {
		if p == 0 {
			return tproxydSidecarConfig{}, 0, errors.New("ports 含非法端口 0")
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	fc.Ports = ports
	return fc, listenPort, nil
}

func normalizeBridgeNames(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, name := range in {
		name = strings.TrimSpace(name)
		if !ifNameRE.MatchString(name) {
			continue
		}
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func hasRemovedBridge(prev, next []string) bool {
	nextSet := make(map[string]struct{}, len(next))
	for _, b := range next {
		nextSet[b] = struct{}{}
	}
	for _, b := range prev {
		if _, ok := nextSet[b]; !ok {
			return true
		}
	}
	return false
}
