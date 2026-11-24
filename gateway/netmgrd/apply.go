// 期望配置 → 执行计划 → 幂等执行（核心 reconcile 逻辑）。
//
// 每项独立成败：单桥/单条路由失败不影响其他项；单桥内部原子（校验失败或
// 首个变更失败即放弃该桥本轮其余变更，绝不半拉子改桥）。
package netmgrd

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// linkEntry `ip -j -d addr show` 单条链路快照（只取本组件关心的字段）。
type linkEntry struct {
	IfName   string   `json:"ifname"`
	Master   string   `json:"master"` // 已入桥时为桥名，未入桥为空
	Flags    []string `json:"flags"`
	LinkInfo *struct {
		InfoKind string `json:"info_kind"` // bridge/veth/vlan/...
	} `json:"linkinfo"`
	AddrInfo []struct {
		Family string `json:"family"` // inet / inet6
		Local  string `json:"local"`
		Scope  string `json:"scope"` // global / link / host
	} `json:"addr_info"`
}

// hasIP 安全红线判定：口上是否已配 IP 地址。inet(IPv4) 地址一律计入；
// inet6 仅计入非 link scope（fe80::/10 链路本地地址是接口 up 后内核自动
// 分配，不代表该口承载业务，不计入——否则所有 up 口都会被误拒）。
func (e linkEntry) hasIP() bool {
	for _, a := range e.AddrInfo {
		if a.Family == "inet" {
			return true
		}
		if a.Family == "inet6" && a.Scope != "link" {
			return true
		}
	}
	return false
}

// isAdminUp 判断接口 flags 是否包含管理态 UP（与物理链路 LOWER_UP 独立）。
func (e linkEntry) isAdminUp() bool {
	for _, f := range e.Flags {
		if f == "UP" {
			return true
		}
	}
	return false
}

// hasLowerUp 判断接口 flags 是否包含物理载波 LOWER_UP。
func (e linkEntry) hasLowerUp() bool {
	for _, f := range e.Flags {
		if f == "LOWER_UP" {
			return true
		}
	}
	return false
}

// ApplyOptions ApplyWithOptions 的可选运行时上下文。
type ApplyOptions struct {
	// HeldDownPorts 由 LinkPairMonitor 持有 PROPAGATED_DOWN 标记的端口集合；
	// Apply 拉起网桥成员口时必须跳过这些端口，避免与端口联动状态机冲突。
	HeldDownPorts map[string]bool
	// ManagedBridges 此前由 netmgrd 创建/纳管的网桥列表；若不再出现在期望配置中，
	// ApplyWithOptions 会对其执行受控拆除（摘除成员 nomaster → down → del）。
	ManagedBridges []string
}

// ensureSysctl 先尝试只读检查 /proc/sys/<key>；若当前值已等于 want，直接视为成功，
// 跳过 sysctl -w（规避非特权容器只读 /proc/sys 导致的 EROFS 误报）。
func ensureSysctl(ctx context.Context, r Runner, key, want string) error {
	if pr, ok := r.(ProcSysReader); ok {
		if cur, err := pr.ReadProcSys(key); err == nil && cur == want {
			return nil
		}
	}
	return r.Exec(ctx, "sysctl", "-w", key+"="+want)
}

// Apply 把期望配置幂等收敛到主机网络状态，返回执行状态（不写文件，由调用方
// 决定落盘/打印）。各项独立成败；快照查询失败时网桥项全部记 error，但
// ip_forward 与 routes 不依赖快照，照常执行（独立性）。
func Apply(ctx context.Context, cfg Config, r Runner, now time.Time) Status {
	return ApplyWithOptions(ctx, cfg, r, now, ApplyOptions{})
}

// ApplyWithOptions 带运行时上下文（联动持有口、已纳管网桥清单）的幂等收敛。
func ApplyWithOptions(ctx context.Context, cfg Config, r Runner, now time.Time, opts ApplyOptions) Status {
	st := Status{
		AppliedAt: now.UTC().Format(time.RFC3339),
		OK:        true,
		Bridges:   make([]BridgeStatus, 0, len(cfg.Bridges)),
		Routes:    make([]RouteStatus, 0, len(cfg.Routes)),
	}
	var failures []string

	// 1. 网桥 reconcile（先取一次链路快照，全桥共用）
	snap, snapErr := queryLinks(ctx, r)
	desiredBridges := make(map[string]struct{}, len(cfg.Bridges))
	managedSet := make(map[string]struct{}, len(cfg.Bridges))
	for _, b := range cfg.Bridges {
		desiredBridges[b.Name] = struct{}{}
		var bs BridgeStatus
		if snapErr != nil {
			bs = BridgeStatus{Name: b.Name, State: StateError,
				Message: fmt.Sprintf("链路快照查询失败: %v", snapErr)}
		} else {
			bs = reconcileBridge(ctx, r, snap, b, opts.HeldDownPorts)
		}
		if bs.State != StateOK {
			st.OK = false
			failures = append(failures, fmt.Sprintf("bridge/%s: %s", b.Name, bs.Message))
		} else {
			managedSet[b.Name] = struct{}{}
		}
		st.Bridges = append(st.Bridges, bs)
	}

	// 1b. 受控拆除：仅拆除此前由 netmgrd 纳管且已从期望配置移除的网桥
	prevManaged := append([]string(nil), opts.ManagedBridges...)
	sort.Strings(prevManaged)
	seenPrev := make(map[string]struct{}, len(prevManaged))
	for _, name := range prevManaged {
		if name == "" || !ifNameRE.MatchString(name) {
			continue
		}
		if _, dup := seenPrev[name]; dup {
			continue
		}
		seenPrev[name] = struct{}{}
		if _, stillWanted := desiredBridges[name]; stillWanted {
			managedSet[name] = struct{}{} // 保留纳管身份（即便本轮暂失败也不丢失）
			continue
		}
		if snapErr != nil {
			st.OK = false
			managedSet[name] = struct{}{}
			failures = append(failures, fmt.Sprintf("bridge/%s teardown: 链路快照查询失败: %v", name, snapErr))
			continue
		}
		if err := teardownBridge(ctx, r, snap, name); err != nil {
			st.OK = false
			managedSet[name] = struct{}{} // 拆除失败保留托管记录，下周期重试
			failures = append(failures, fmt.Sprintf("bridge/%s teardown: %v", name, err))
		}
	}
	if len(managedSet) > 0 {
		managed := make([]string, 0, len(managedSet))
		for name := range managedSet {
			managed = append(managed, name)
		}
		sort.Strings(managed)
		st.ManagedBridges = managed
	}

	// 2. ip_forward：false → skipped，不主动关闭——同一主机上可能有其他组件
	//    （容器网络/NAT/其他命名空间转发）依赖 ip_forward=1，期望关闭不代表
	//    授权本组件替全机关转发；true → 先读 /proc/sys 已是 1 则跳过写入，否则置 1。
	if !cfg.IPForward {
		st.IPForward = StateSkipped
	} else if err := ensureSysctl(ctx, r, "net.ipv4.ip_forward", "1"); err != nil {
		st.IPForward = StateError
		st.OK = false
		failures = append(failures, fmt.Sprintf("ip_forward: %v", err))
	} else {
		st.IPForward = StateOK
	}

	// 3. 静态路由：replace 幂等覆盖同名路由；只增不删（最小实现）——期望外
	//    路由可能由运维手工配置或其他组件管理，本组件不清理，status 注明。
	for _, rt := range cfg.Routes {
		rs := RouteStatus{Dst: rt.Dst, Via: rt.Via, State: StateOK}
		if err := r.Exec(ctx, "ip", "route", "replace", rt.Dst, "via", rt.Via); err != nil {
			rs.State = StateError
			rs.Message = err.Error()
			st.OK = false
			failures = append(failures, fmt.Sprintf("route %s via %s: %v", rt.Dst, rt.Via, err))
		}
		st.Routes = append(st.Routes, rs)
	}

	// 4. DNS/NTP 落地（可选字段，未下发不触碰；UNSUPPORTED 不计入整体失败，
	//    FAILED 计入整体失败按周期重试自愈；dry-run 只标注不执行——与
	//    ip/sysctl 的 dry-run 语义一致，绝不在计划模式变更主机）
	_, dryRun := r.(*DryRunner)
	if cfg.DNSServers != nil {
		if dryRun {
			st.DNS = &ServiceStatus{State: StateUnsupported, Message: "dry-run：DNS 落地未执行（仅计划模式）"}
		} else {
			st.DNS = applyDNS(ctx, cfg.DNSServers, hostTools)
			if st.DNS.State == StateFailed {
				st.OK = false
				failures = append(failures, "dns: "+st.DNS.Message)
			}
		}
	}
	if cfg.NTPServers != nil {
		if dryRun {
			st.NTP = &ServiceStatus{State: StateUnsupported, Message: "dry-run：NTP 落地未执行（仅计划模式）"}
		} else {
			st.NTP = applyNTP(ctx, cfg.NTPServers, hostTools)
			if st.NTP.State == StateFailed {
				st.OK = false
				failures = append(failures, "ntp: "+st.NTP.Message)
			}
		}
	}

	// 5. 汇总
	switch {
	case len(failures) > 0:
		st.Message = "部分失败: " + strings.Join(failures, "; ")
	case len(cfg.Routes) > 0:
		st.Message = "applied；路由只增不删（最小实现，期望外路由由运维清理）"
	default:
		st.Message = "applied"
	}
	return st
}

// queryLinks 一次查询全机链路快照（`ip -j -d addr show`：含 ifname/master/
// flags/linkinfo.info_kind/addr_info，网桥 reconcile 所需的全部事实）。
func queryLinks(ctx context.Context, r Runner) (map[string]linkEntry, error) {
	out, err := r.Query(ctx, "ip", "-j", "-d", "addr", "show")
	if err != nil {
		return nil, err
	}
	var links []linkEntry
	if err := json.Unmarshal(out, &links); err != nil {
		return nil, fmt.Errorf("解析 ip -j addr show 输出: %w", err)
	}
	snap := make(map[string]linkEntry, len(links))
	for _, l := range links {
		snap[l.IfName] = l
	}
	return snap, nil
}

// reconcileBridge 单桥 reconcile。安全红线先行：任一待入桥成员口校验不过
// （不存在/已配 IP/已隶属其他主设备），整桥记 error 且本轮零变更。
func reconcileBridge(ctx context.Context, r Runner, snap map[string]linkEntry, b BridgeSpec, heldDown map[string]bool) BridgeStatus {
	bs := BridgeStatus{Name: b.Name, State: StateOK}

	// ---- 校验阶段（纯读，零变更）----
	br, brExists := snap[b.Name]
	if brExists {
		// 同名设备已存在但不是桥：不接管（防误改 vlan/bond 等设备）
		kind := ""
		if br.LinkInfo != nil {
			kind = br.LinkInfo.InfoKind
		}
		if kind != "bridge" {
			bs.State = StateError
			bs.Message = fmt.Sprintf("已存在同名非桥设备 %s（type=%s），拒绝接管", b.Name, kindOrUnknown(kind))
			return bs
		}
	}
	current := map[string]bool{} // 当前成员口
	for _, l := range snap {
		if l.Master == b.Name {
			current[l.IfName] = true
		}
	}
	for _, p := range b.Ports {
		port, ok := snap[p]
		if !ok {
			bs.State = StateError
			bs.Message = fmt.Sprintf("成员口 %s 不存在", p)
			return bs
		}
		if port.Master != "" && port.Master != b.Name {
			// 安全红线：已隶属于其他主设备（如 bond0 / docker0 / 其他桥）拒绝抢占
			bs.State = StateError
			bs.Message = fmt.Sprintf("成员口 %s 已隶属于其他主设备 %s，拒绝抢占收入桥 %s（请先从 %s 解除绑定）",
				p, port.Master, b.Name, port.Master)
			return bs
		}
		if port.Master != b.Name && port.hasIP() {
			// 安全红线：带 IP 的口（管理口/业务口）拒绝收入桥。
			// 已是本桥成员的口不算「收入」，不在此拦截。
			bs.State = StateError
			bs.Message = fmt.Sprintf("成员口 %s 已配置 IP 地址，拒绝收入桥 %s（防误拉管理口/业务口）；如确需桥接请先移除该口 IP", p, b.Name)
			return bs
		}
	}

	// ---- 变更阶段（首个失败即放弃该桥本轮其余变更）----
	execOrFail := func(name string, args ...string) bool {
		if err := r.Exec(ctx, name, args...); err != nil {
			bs.State = StateError
			bs.Message = err.Error()
			return false
		}
		return true
	}
	if !brExists {
		// 透明网桥显式关闭 STP 与 15s 转发延迟（stp_state 0 forward_delay 0）
		if !execOrFail("ip", "link", "add", b.Name, "type", "bridge", "stp_state", "0", "forward_delay", "0") {
			return bs
		}
	}
	// 补缺失成员，并拉起处于管理 DOWN 的成员口（跳过 LinkPairMonitor 持有 PROPAGATED_DOWN 的口）
	for _, p := range b.Ports {
		if !current[p] {
			if !execOrFail("ip", "link", "set", p, "master", b.Name) {
				return bs
			}
		}
		if !heldDown[p] && !snap[p].isAdminUp() {
			if !execOrFail("ip", "link", "set", p, "up") {
				return bs
			}
		}
	}
	// 摘除期望外成员（nomaster 只解除桥接关系，不删除接口，可逆；排序保确定性）
	want := map[string]bool{}
	for _, p := range b.Ports {
		want[p] = true
	}
	extra := make([]string, 0)
	for m := range current {
		if !want[m] {
			extra = append(extra, m)
		}
	}
	sort.Strings(extra)
	for _, m := range extra {
		if !execOrFail("ip", "link", "set", m, "nomaster") {
			return bs
		}
	}
	// 最后拉起桥（幂等：已 up 重设无副作用）
	execOrFail("ip", "link", "set", b.Name, "up")
	return bs
}

// teardownBridge 受控拆除此前由 netmgrd 纳管且已从配置移除的网桥：
// 仅在同名设备存在且确为 bridge 时先摘除全部成员口（nomaster），再 down 并 del。
func teardownBridge(ctx context.Context, r Runner, snap map[string]linkEntry, name string) error {
	br, exists := snap[name]
	if !exists {
		return nil // 已被外部拆除，视为清理完成
	}
	kind := ""
	if br.LinkInfo != nil {
		kind = br.LinkInfo.InfoKind
	}
	if kind != "bridge" {
		return fmt.Errorf("设备 %s 非网桥（type=%s），拒绝拆除", name, kindOrUnknown(kind))
	}
	members := make([]string, 0)
	for _, l := range snap {
		if l.Master == name {
			members = append(members, l.IfName)
		}
	}
	sort.Strings(members)
	for _, m := range members {
		if err := r.Exec(ctx, "ip", "link", "set", m, "nomaster"); err != nil {
			return fmt.Errorf("摘除成员口 %s: %w", m, err)
		}
	}
	if err := r.Exec(ctx, "ip", "link", "set", name, "down"); err != nil {
		return fmt.Errorf("关闭网桥 %s: %w", name, err)
	}
	if err := r.Exec(ctx, "ip", "link", "del", name); err != nil {
		return fmt.Errorf("删除网桥 %s: %w", name, err)
	}
	return nil
}

func kindOrUnknown(kind string) string {
	if kind == "" {
		return "unknown"
	}
	return kind
}
