// 端口联动（Link-Pair）监控器：网桥成员口 carrier 轮询 + 状态机 + 联动执行。
//
// 设计依据 docs/HA_ACTIVE_STANDBY_DESIGN.md §6：
//   - 状态机：BOTH_UP →（任一口 carrier 丢失持续 hold_down）→ PROPAGATED_DOWN
//     （配对口 set down + 联动标记）→（故障口恢复持续 hold_up）→ BOTH_UP；
//     任意态联动频率超限 → SUPPRESSED（冻结动作，配置变更/进程重启复位）；
//   - 安全红线：只 set down/up 配对口本身；配对口带 IP 地址（管理口/业务口）
//     拒绝联动；只恢复带本组件联动标记的口，运维手工 down 的口绝不动；
//   - 重启对齐：进程重启后按 network-status.json 中的联动标记恢复状态机，
//     无标记的一 up 一 down 仅如实上送，不动作；
//   - 执行纪律同 netmgrd：动作经 Runner（exec 参数数组、单动作超时），幂等
//     （先读快照已是目标态则跳过），失败保留进程按周期重试。
//
// 并发模型：Supervisor 经 SetConfig 更新期望（配置轮询线程）；监控循环经
// Run/cycle 推进状态机（独立 ticker 线程）；两者由 mu 串行化，无重入。
package netmgrd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultLinkPairInterval 联动监控轮询周期（carrier 轮询，非配置轮询）。
const DefaultLinkPairInterval = 500 * time.Millisecond

// pairRuntime 单桥联动运行态（期望 + 状态机 + 防抖/抑制窗口）。
type pairRuntime struct {
	spec      BridgeSpec
	state     string // LinkPairBothUp / LinkPairPropagatedDown / LinkPairSuppressed
	specKey   string // 期望指纹（端口+参数）：变化则重置运行态（含 SUPPRESSED 复位）
	configVer string // 最近配置版本戳（updated_at）：SUPPRESSED 复位判定用

	downSince map[string]time.Time // 每端口独立记录物理掉载波起点（避免双口同时掉载波时互相覆盖活锁）
	downPort  string               // 已认定故障口（PROPAGATED_DOWN 期间）
	propPort  string               // 被联动 down 的配对口
	upSince   time.Time            // 故障口恢复候选起点（PROPAGATED_DOWN 期间防抖）
	flaps     []time.Time

	lastEventAt time.Time
	message     string
}

// LinkPairMonitor 端口联动监控器（零联动配置时空转，零开销）。
type LinkPairMonitor struct {
	// Runner 命令执行器（生产 ExecRunner；测试注入桩）。
	Runner Runner
	// StatusPath network-status.json 路径（独立构造时使用；Supervisor 下优先经 StatusWriter）。
	StatusPath string
	// StatusWriter 跨组件共享的互斥状态写入器（可选；空时按 StatusPath 构造默认写入器）。
	StatusWriter *StatusWriter
	// Interval carrier 轮询周期（<=0 取 DefaultLinkPairInterval）。
	Interval time.Duration

	mu       sync.Mutex
	pairs    map[string]*pairRuntime // bridge name → 运行态
	restored bool                    // 首轮 SetConfig 时已按 status 文件做过重启对齐
	stopCh   chan struct{}
	started  bool
	closed   bool

	now     func() time.Time // 时钟（测试注入；默认 time.Now）
	lastLog string           // 防刷屏日志键
	dirty   bool             // 运行态自上次回写后有变化
}

// NewLinkPairMonitor 创建监控器。
func NewLinkPairMonitor(statusPath string, r Runner) *LinkPairMonitor {
	return &LinkPairMonitor{
		Runner:       r,
		StatusPath:   statusPath,
		StatusWriter: NewStatusWriter(statusPath),
		pairs:        map[string]*pairRuntime{},
		stopCh:       make(chan struct{}),
		now:          time.Now,
	}
}

// statusWriter 返回有效的共享状态写入器。
func (m *LinkPairMonitor) statusWriter() *StatusWriter {
	if m.StatusWriter != nil {
		return m.StatusWriter
	}
	return NewStatusWriter(m.StatusPath)
}

// HeldDownPorts 返回当前处于 PROPAGATED_DOWN 且由本组件联动标记持有的配对口集合，
// 供 Apply 拉起网桥成员口时跳过这些口。
func (m *LinkPairMonitor) HeldDownPorts() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	var held map[string]bool
	for _, rt := range m.pairs {
		if rt.state == LinkPairPropagatedDown && rt.propPort != "" {
			if held == nil {
				held = map[string]bool{}
			}
			held[rt.propPort] = true
		}
	}
	return held
}

// interval 轮询周期（零值取默认）。
func (m *LinkPairMonitor) interval() time.Duration {
	if m.Interval <= 0 {
		return DefaultLinkPairInterval
	}
	return m.Interval
}

// logOnce 同一键日志只打一次（防 500ms 轮询刷屏）。
func (m *LinkPairMonitor) logOnce(key, format string, args ...any) {
	if m.lastLog == key {
		return
	}
	m.lastLog = key
	log.Printf("[netmgrd/linkpair] "+format, args...)
}

// Run 阻塞运行监控循环：每 Interval 推进一轮，直到 Close（由 Supervisor 以
// goroutine 启动；进程退出不拆除任何联动状态）。
func (m *LinkPairMonitor) Run() {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return
	}
	m.started = true
	m.mu.Unlock()

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

// Close 停止监控（幂等；已执行的联动状态保留——拆除属高危变更，运维显式处理）。
func (m *LinkPairMonitor) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	close(m.stopCh)
}

// SetConfig 更新联动期望（Supervisor 配置轮询线程调用，入参为最近一次成功
// 解析的配置与其 updated_at 版本戳）。首次调用按 status 文件做重启对齐；此后：
// 新增桥初始化、期望指纹变化的桥重置运行态（含 SUPPRESSED 复位）、配置版本戳
// 变化且处于 SUPPRESSED 的桥复位（「重新保存配置即复位抑制」语义——运维在页面
// 原样保存一次配置即可复位，无需改参数）、配置移除的桥停止监控（不动接口现状——
// 恢复属高危变更，运维显式处理）。
func (m *LinkPairMonitor) SetConfig(bridges []BridgeSpec, configVer string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := map[string]BridgeSpec{}
	for _, b := range bridges {
		if b.LinkPair != nil && b.LinkPair.Enabled {
			want[b.Name] = b
		}
	}

	// 重启对齐（仅首轮）：按 status 文件中的联动标记恢复 PROPAGATED_DOWN 运行态。
	if !m.restored {
		m.restored = true
		m.restoreFromStatusLocked(want)
	}

	for name, b := range want {
		key := pairSpecKey(b)
		if rt, ok := m.pairs[name]; ok && rt.specKey == key {
			// 同指纹：参数未变。SUPPRESSED 且配置版本戳变化（重新保存）→ 复位。
			if rt.state == LinkPairSuppressed && configVer != "" && configVer != rt.configVer {
				rt.state = LinkPairBothUp
				rt.flaps = nil
				rt.message = "配置已重新保存，抑制复位"
				rt.lastEventAt = m.now()
				m.dirty = true
				log.Printf("[netmgrd/linkpair] 桥 %s 配置重新保存，抑制复位", name)
			}
			rt.spec = b
			rt.configVer = configVer
			continue
		}
		if _, existed := m.pairs[name]; existed {
			log.Printf("[netmgrd/linkpair] 桥 %s 联动期望变更，重置运行态（含抑制复位）", name)
		}
		m.pairs[name] = &pairRuntime{spec: b, specKey: key, configVer: configVer, state: LinkPairBothUp}
		m.dirty = true
	}
	for name := range m.pairs {
		if _, ok := want[name]; !ok {
			delete(m.pairs, name)
			m.dirty = true
			log.Printf("[netmgrd/linkpair] 桥 %s 联动配置已移除，停止监控（接口现状保持，恢复由运维处理）", name)
		}
	}
}

// pairSpecKey 期望指纹：端口集合 + 联动参数（变化 = 重置运行态）。
func pairSpecKey(b BridgeSpec) string {
	ports := append([]string(nil), b.Ports...)
	sort.Strings(ports)
	return fmt.Sprintf("%s|%d|%d|%d", strings.Join(ports, ","),
		b.LinkPair.HoldDownMs, b.LinkPair.HoldUpMs, b.LinkPair.MaxFlapsPerHour)
}

// restoreFromStatusLocked 重启对齐：读 status 文件，带联动标记且仍
// PROPAGATED_DOWN 的桥恢复对应运行态（downPort/propPort 以 status 为准；
// 无标记的一 up 一 down 不动作，仅由首个监控周期如实上送）。
func (m *LinkPairMonitor) restoreFromStatusLocked(want map[string]BridgeSpec) {
	st := m.statusWriter().Read()
	if st == nil {
		return // 无历史状态：全新启动
	}
	for _, lp := range st.LinkPairs {
		b, ok := want[lp.Bridge]
		if !ok || !lp.PropagatedByLinkpair || lp.State != LinkPairPropagatedDown {
			continue
		}
		if !containsPort(b.Ports, lp.DownPort) || !containsPort(b.Ports, lp.PropagatedPort) {
			continue // 历史状态与现期望不符：按全新处理（保守）
		}
		m.pairs[lp.Bridge] = &pairRuntime{
			spec: b, specKey: pairSpecKey(b),
			state: LinkPairPropagatedDown, downPort: lp.DownPort, propPort: lp.PropagatedPort,
			message: "进程重启：按联动标记恢复 PROPAGATED_DOWN 运行态",
		}
		m.dirty = true
		log.Printf("[netmgrd/linkpair] 桥 %s 重启对齐：恢复 PROPAGATED_DOWN（故障口 %s / 配对口 %s）",
			lp.Bridge, lp.DownPort, lp.PropagatedPort)
	}
}

// cycle 推进一轮监控（ticker 线程；测试直接调用并以 now 注入时钟）。
func (m *LinkPairMonitor) cycle(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	// 即使最后一个联动桥已被移除（len==0），仍须把 m.dirty 刷盘以清除遗留 link_pairs 状态。
	if len(m.pairs) == 0 {
		if m.dirty {
			if werr := m.writeStatusLocked(); werr != nil {
				m.logOnce("werr", "联动状态回写失败（下周期重试）: %v", werr)
				return
			}
			m.dirty = false
		}
		return
	}

	snap, err := queryLinks(ctx, m.Runner)
	if err != nil {
		m.logOnce("snaperr", "链路快照查询失败（本轮跳过，下周期重试）: %v", err)
		return
	}
	now := m.now()
	changed := false
	for _, name := range sortedKeys(m.pairs) {
		if m.evaluateLocked(ctx, m.pairs[name], snap, now) {
			changed = true
		}
	}
	if changed || m.dirty {
		if werr := m.writeStatusLocked(); werr != nil {
			m.logOnce("werr", "联动状态回写失败（下周期重试）: %v", werr)
			return
		}
		m.dirty = false
	}
}

// evaluateLocked 单桥状态机推进一轮；返回是否有状态/信息变化。
func (m *LinkPairMonitor) evaluateLocked(ctx context.Context, rt *pairRuntime, snap map[string]linkEntry, now time.Time) bool {
	switch rt.state {
	case LinkPairBothUp:
		return m.evalBothUpLocked(ctx, rt, snap, now)
	case LinkPairPropagatedDown:
		return m.evalPropagatedLocked(ctx, rt, snap, now)
	case LinkPairSuppressed:
		return false // 冻结：配置变更（specKey 变化）或进程重启才复位
	}
	return false
}

// evalBothUpLocked BOTH_UP：每端口独立跟踪物理载波丢失时长（管理 UP 且无 LOWER_UP），
// 避免双口同时掉载波时的单候选覆盖活锁，也绝不从运维手工管理 DOWN 的口触发联动。
func (m *LinkPairMonitor) evalBothUpLocked(ctx context.Context, rt *pairRuntime, snap map[string]linkEntry, now time.Time) bool {
	if rt.downSince == nil {
		rt.downSince = map[string]time.Time{}
	}
	p0, p1 := rt.spec.Ports[0], rt.spec.Ports[1]
	var triggered string
	for _, p := range [2]string{p0, p1} {
		if physicalCarrierLost(snap, p) {
			since, ok := rt.downSince[p]
			if !ok {
				rt.downSince[p] = now
				continue
			}
			if now.Sub(since) >= time.Duration(rt.spec.LinkPair.HoldDownMs)*time.Millisecond && triggered == "" {
				triggered = p
			}
		} else {
			delete(rt.downSince, p)
		}
	}
	if triggered != "" {
		return m.propagateLocked(ctx, rt, triggered, peerOf(p0, p1, triggered), snap, now)
	}
	return false
}

// propagateLocked 执行联动 down（BOTH_UP → PROPAGATED_DOWN 的唯一入口）：
// 抑制判定 → 安全红线（配对口缺失 / 带 IP / 已被运维管理 DOWN 均拒绝接管）→ 执行 → 打标记 + 计 flap。
func (m *LinkPairMonitor) propagateLocked(ctx context.Context, rt *pairRuntime, downPort, propPort string, snap map[string]linkEntry, now time.Time) bool {
	// 抑制判定：近 1 小时联动次数超限 → SUPPRESSED（冻结，如实记录）。
	rt.flaps = pruneFlaps(rt.flaps, now)
	if rt.spec.LinkPair.MaxFlapsPerHour > 0 && len(rt.flaps) >= rt.spec.LinkPair.MaxFlapsPerHour {
		rt.state = LinkPairSuppressed
		rt.downSince = nil
		rt.lastEventAt = now
		rt.message = fmt.Sprintf("联动频率超限（1h 内 %d 次 ≥ 上限 %d），进入抑制态；请检查物理链路后保存一次网络配置或重启 netmgrd 复位",
			len(rt.flaps), rt.spec.LinkPair.MaxFlapsPerHour)
		log.Printf("[netmgrd/linkpair] 桥 %s %s", rt.spec.Name, rt.message)
		return true
	}

	e, ok := snap[propPort]
	if !ok {
		return m.setMessageLocked(rt, now,
			fmt.Sprintf("安全红线：配对口 %s 不存在，无法执行联动 down", propPort))
	}
	// 安全红线：配对口带 IP 地址（管理口/业务口）拒绝联动 down。
	if e.hasIP() {
		return m.setMessageLocked(rt, now,
			fmt.Sprintf("安全红线：配对口 %s 已配置 IP 地址，拒绝联动 down（防误断管理/业务通道）", propPort))
	}
	// 安全红线：配对口已处于管理 DOWN（运维手工 down），绝不执行联动或认领联动标记
	// （否则后续故障口恢复时会把运维手工 down 的口错误拉 UP）。
	if !e.isAdminUp() {
		return m.setMessageLocked(rt, now,
			fmt.Sprintf("安全红线：配对口 %s 已处于管理 DOWN（非本组件联动），拒绝认领联动标记", propPort))
	}

	if err := m.Runner.Exec(ctx, "ip", "link", "set", propPort, "down"); err != nil {
		// 执行失败：保持 BOTH_UP，撤销候选避免每周期重试，下一个 hold_down 周期再试
		delete(rt.downSince, downPort)
		return m.setMessageLocked(rt, now, fmt.Sprintf("联动 down %s 执行失败（按周期重试）: %v", propPort, err))
	}

	rt.state = LinkPairPropagatedDown
	rt.downPort, rt.propPort = downPort, propPort
	rt.downSince = nil
	rt.upSince = time.Time{}
	rt.flaps = append(rt.flaps, now)
	rt.lastEventAt = now
	rt.message = fmt.Sprintf("%s 链路故障持续 %dms，配对口 %s 已联动 down（等待上游切路）",
		downPort, rt.spec.LinkPair.HoldDownMs, propPort)
	log.Printf("[netmgrd/linkpair] 桥 %s %s", rt.spec.Name, rt.message)
	return true
}

// evalPropagatedLocked PROPAGATED_DOWN：故障口恢复（管理 UP 且有 LOWER_UP）持续 hold_up → 配对口回 up。
func (m *LinkPairMonitor) evalPropagatedLocked(ctx context.Context, rt *pairRuntime, snap map[string]linkEntry, now time.Time) bool {
	if !carrierHealthy(snap, rt.downPort) {
		rt.upSince = time.Time{} // 仍故障或已被管理 DOWN：撤销恢复候选
		return false
	}
	if rt.upSince.IsZero() {
		rt.upSince = now
		return false
	}
	if now.Sub(rt.upSince) < time.Duration(rt.spec.LinkPair.HoldUpMs)*time.Millisecond {
		return false // 恢复防抖窗口内
	}
	if err := m.Runner.Exec(ctx, "ip", "link", "set", rt.propPort, "up"); err != nil {
		rt.upSince = time.Time{} // 执行失败：重新计时，避免每周期重试
		return m.setMessageLocked(rt, now, fmt.Sprintf("配对口 %s 恢复 up 执行失败（按周期重试）: %v", rt.propPort, err))
	}
	msg := fmt.Sprintf("故障口 %s 链路恢复持续 %dms，配对口 %s 已回 up", rt.downPort, rt.spec.LinkPair.HoldUpMs, rt.propPort)
	rt.state = LinkPairBothUp
	rt.downPort, rt.propPort = "", ""
	rt.upSince = time.Time{}
	rt.lastEventAt = now
	rt.message = msg
	log.Printf("[netmgrd/linkpair] 桥 %s %s", rt.spec.Name, msg)
	return true
}

// setMessageLocked 更新信息（内容变化才算变更，防每周期重写 status）。
func (m *LinkPairMonitor) setMessageLocked(rt *pairRuntime, now time.Time, msg string) bool {
	if rt.message == msg {
		return false
	}
	rt.message = msg
	rt.lastEventAt = now
	log.Printf("[netmgrd/linkpair] 桥 %s %s", rt.spec.Name, msg)
	return true
}

// physicalCarrierLost 判定物理链路掉载波：接口存在、处于管理 UP 且无 LOWER_UP。
// 接口不存在或被运维手工管理 DOWN（无 UP 标志）均返回 false，绝不误触发联动。
func physicalCarrierLost(snap map[string]linkEntry, ifname string) bool {
	e, ok := snap[ifname]
	if !ok {
		return false
	}
	return e.isAdminUp() && !e.hasLowerUp()
}

// carrierHealthy 判定接口已恢复正常：存在、管理 UP 且具备物理载波 LOWER_UP。
func carrierHealthy(snap map[string]linkEntry, ifname string) bool {
	e, ok := snap[ifname]
	if !ok {
		return false
	}
	return e.isAdminUp() && e.hasLowerUp()
}

// peerOf 返回配对口。
func peerOf(p0, p1, p string) string {
	if p == p0 {
		return p1
	}
	return p0
}

// pruneFlaps 裁剪 1 小时窗口外的 flap 记录。
func pruneFlaps(flaps []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-time.Hour)
	kept := flaps[:0]
	for _, t := range flaps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

func sortedKeys(m map[string]*pairRuntime) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func containsPort(ports []string, p string) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// loadStatusFile 读 status 文件（不存在/解析失败返回 nil——联动回写以
// 「可合并则合并」为原则，不放大既有文件问题）。
func loadStatusFile(path string) *Status {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // 不存在即无历史，非错误
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		return nil // 解析失败：保留原文，不接管
	}
	return &st
}

// writeStatusLocked 经共享 StatusWriter 互斥合并回写 link_pairs 段。
func (m *LinkPairMonitor) writeStatusLocked() error {
	pairs := make([]LinkPairStatus, 0, len(m.pairs))
	for _, name := range sortedKeys(m.pairs) {
		rt := m.pairs[name]
		ls := LinkPairStatus{
			Bridge:               name,
			State:                rt.state,
			DownPort:             rt.downPort,
			PropagatedPort:       rt.propPort,
			PropagatedByLinkpair: rt.state == LinkPairPropagatedDown,
			FlapCountHour:        len(pruneFlaps(rt.flaps, m.now())),
			Message:              rt.message,
		}
		if !rt.lastEventAt.IsZero() {
			ls.LastEventAt = rt.lastEventAt.UTC().Format(time.RFC3339)
		}
		pairs = append(pairs, ls)
	}
	return m.statusWriter().WriteLinkPairs(pairs)
}
