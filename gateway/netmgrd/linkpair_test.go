// 端口联动（Link-Pair）测试：配置校验、状态机全迁移、防抖、安全红线、
// 频率抑制、重启对齐、status 合并回写。时钟与 Runner 均注入，不依赖真实主机。
package netmgrd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 测试基础设施 ----------

// lpNow 可控假时钟。
type lpClock struct{ t time.Time }

func (c *lpClock) now() time.Time          { return c.t }
func (c *lpClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// lpSnapshot 构造 `ip -j -d addr show` 输出：ports 中每个口一组 flags；
// carrier=false 的口不带 LOWER_UP；withIP 的口带 inet 地址（安全红线测试）。
func lpSnapshot(ports map[string]bool, withIP ...string) []byte {
	ipSet := map[string]bool{}
	for _, p := range withIP {
		ipSet[p] = true
	}
	entries := make([]map[string]any, 0, len(ports))
	for name, carrier := range ports {
		flags := []string{"BROADCAST", "MULTICAST", "UP"}
		if carrier {
			flags = append(flags, "LOWER_UP")
		}
		addr := []map[string]string{}
		if ipSet[name] {
			addr = append(addr, map[string]string{"family": "inet", "local": "10.0.0.1", "scope": "global"})
		}
		entries = append(entries, map[string]any{
			"ifname": name, "flags": flags, "addr_info": addr,
		})
	}
	data, _ := json.Marshal(entries)
	return data
}

// lpSpec 构造已归一化的联动桥期望（等价 LoadConfig 产物）。
func lpSpec(holdDown, holdUp, maxFlaps int) BridgeSpec {
	return BridgeSpec{
		Name:  "br0",
		Ports: []string{"eth2", "eth3"},
		LinkPair: &LinkPairSpec{
			Enabled: true, HoldDownMs: holdDown, HoldUpMs: holdUp, MaxFlapsPerHour: maxFlaps,
		},
	}
}

// newTestMonitor 构建注入假时钟与桩 Runner 的监控器。
func newTestMonitor(t *testing.T, fr *fakeRunner) (*LinkPairMonitor, *lpClock) {
	t.Helper()
	clk := &lpClock{t: testNow}
	m := NewLinkPairMonitor(filepath.Join(t.TempDir(), "network-status.json"), fr)
	m.now = clk.now
	return m, clk
}

// pairOf 取运行态（测试断言用）。
func (m *LinkPairMonitor) pairOf(name string) *pairRuntime {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pairs[name]
}

func readStatusFile(t *testing.T, path string) Status {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 status 文件: %v", err)
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("解析 status 文件: %v", err)
	}
	return st
}

// ---------- 配置校验 ----------

func TestLinkPairConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantErr string
		check   func(t *testing.T, cfg Config)
	}{
		{
			name:    "启用联动但成员口不是2个",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3","eth4"],"link_pair":{"enabled":true}}]}`,
			wantErr: "恰好 2 个",
		},
		{
			name:    "hold_down_ms 越界",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_down_ms":50}}]}`,
			wantErr: "hold_down_ms 越界",
		},
		{
			name:    "hold_up_ms 越界",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_up_ms":999999}}]}`,
			wantErr: "hold_up_ms 越界",
		},
		{
			name:    "max_flaps 越界",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"max_flaps_per_hour":999}}]}`,
			wantErr: "max_flaps_per_hour 越界",
		},
		{
			name:    "合法配置零值落缺省",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true}}]}`,
			check: func(t *testing.T, cfg Config) {
				lp := cfg.Bridges[0].LinkPair
				if lp.HoldDownMs != DefaultLinkPairHoldDownMs ||
					lp.HoldUpMs != DefaultLinkPairHoldUpMs ||
					lp.MaxFlapsPerHour != DefaultLinkPairMaxFlaps {
					t.Fatalf("缺省值未生效: %+v", lp)
				}
			},
		},
		{
			name:    "enabled=false 不校验成员数",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3","eth4"],"link_pair":{"enabled":false}}]}`,
		},
		{
			name:    "未配置 link_pair 行为不变",
			content: `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}]}`,
			check: func(t *testing.T, cfg Config) {
				if cfg.Bridges[0].LinkPair != nil {
					t.Fatal("未配置时 LinkPair 应为 nil")
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadConfig(writeOnly(t, tc.content))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("期望错误含 %q，实际: %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("不应报错: %v", err)
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

// ---------- 状态机：正常联动与恢复 ----------

func TestLinkPairPropagateAndRecover(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	ctx := context.Background()

	// 双口正常：初始 BOTH_UP，无任何动作
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("初始应 BOTH_UP: %s", rt.state)
	}
	if len(fr.execLog()) != 0 {
		t.Fatalf("双口正常不应有动作: %v", fr.execLog())
	}

	// eth2 掉 carrier：防抖窗口内不动作
	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(500 * time.Millisecond)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("防抖窗口内应保持 BOTH_UP: %s", rt.state)
	}

	// 持续丢失达 hold_down：联动 down eth3
	clk.advance(600 * time.Millisecond) // 累计 1.1s > 1000ms
	m.cycle(ctx)
	rt := m.pairOf("br0")
	if rt.state != LinkPairPropagatedDown || rt.downPort != "eth2" || rt.propPort != "eth3" {
		t.Fatalf("应 PROPAGATED_DOWN(down=eth2 prop=eth3): %+v", rt)
	}
	execs := fr.execLog()
	if len(execs) != 1 || execs[0] != "ip link set eth3 down" {
		t.Fatalf("联动命令不符: %v", execs)
	}
	// status 回写带联动标记
	st := readStatusFile(t, m.StatusPath)
	if len(st.LinkPairs) != 1 || !st.LinkPairs[0].PropagatedByLinkpair ||
		st.LinkPairs[0].State != LinkPairPropagatedDown || st.LinkPairs[0].FlapCountHour != 1 {
		t.Fatalf("status 回写不符: %+v", st.LinkPairs)
	}

	// 故障口恢复：hold_up 窗口内不回 up
	fr.dump = lpSnapshot(map[string]bool{"eth2": true, "eth3": true})
	m.cycle(ctx)
	clk.advance(4 * time.Second)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairPropagatedDown {
		t.Fatalf("hold_up 窗口内应保持 PROPAGATED_DOWN: %s", rt.state)
	}

	// 持续恢复达 hold_up：配对口回 up，状态归位
	clk.advance(1500 * time.Millisecond) // 累计 5.5s > 5000ms
	m.cycle(ctx)
	rt = m.pairOf("br0")
	if rt.state != LinkPairBothUp || rt.downPort != "" || rt.propPort != "" {
		t.Fatalf("应恢复 BOTH_UP: %+v", rt)
	}
	execs = fr.execLog()
	if len(execs) != 2 || execs[1] != "ip link set eth3 up" {
		t.Fatalf("恢复命令不符: %v", execs)
	}
	st = readStatusFile(t, m.StatusPath)
	if st.LinkPairs[0].State != LinkPairBothUp || st.LinkPairs[0].PropagatedByLinkpair {
		t.Fatalf("恢复后 status 不符: %+v", st.LinkPairs[0])
	}
}

// ---------- 安全红线 ----------

func TestLinkPairRefusePeerWithIP(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true}, "eth3")}
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	ctx := context.Background()

	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true}, "eth3")
	m.cycle(ctx)
	clk.advance(2 * time.Second)
	m.cycle(ctx)

	rt := m.pairOf("br0")
	if rt.state != LinkPairBothUp {
		t.Fatalf("带 IP 配对口应拒绝联动: %s", rt.state)
	}
	if !strings.Contains(rt.message, "安全红线") {
		t.Fatalf("应记录安全红线信息: %s", rt.message)
	}
	if len(fr.execLog()) != 0 {
		t.Fatalf("拒绝联动不应有动作: %v", fr.execLog())
	}
}

// ---------- 执行失败重试 ----------

func TestLinkPairExecFailureRetry(t *testing.T) {
	fr := &fakeRunner{
		dump:     lpSnapshot(map[string]bool{"eth2": true, "eth3": true}),
		failExec: map[string]string{"ip link set eth3 down": "设备或资源忙"},
	}
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	ctx := context.Background()

	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(2 * time.Second)
	m.cycle(ctx)

	rt := m.pairOf("br0")
	if rt.state != LinkPairBothUp {
		t.Fatalf("执行失败应保持 BOTH_UP: %s", rt.state)
	}
	if !strings.Contains(rt.message, "执行失败") {
		t.Fatalf("应记录失败信息: %s", rt.message)
	}
	// 失败撤销候选：下一个完整 hold_down 周期后重试
	m.cycle(ctx)
	clk.advance(2 * time.Second)
	m.cycle(ctx)
	if got := len(fr.execLog()); got != 2 {
		t.Fatalf("应按周期重试联动，实际命令数 %d: %v", got, fr.execLog())
	}
}

// ---------- 缺失口不误动作 ----------

func TestLinkPairMissingPortNoAction(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth3": true})} // eth2 未插入
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	ctx := context.Background()

	m.cycle(ctx)
	clk.advance(3 * time.Second)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("成员口缺失属无法判定，不应联动: %s", rt.state)
	}
	if len(fr.execLog()) != 0 {
		t.Fatalf("缺失口不应有动作: %v", fr.execLog())
	}
}

// ---------- 频率抑制与复位 ----------

func TestLinkPairSuppression(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(100, 100, 2)}, "v1") // 上限 2 次/小时，窗口缩短便于测试
	ctx := context.Background()

	// 制造 2 次联动（每次：故障→联动→恢复→再故障）
	for i := 0; i < 2; i++ {
		fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
		m.cycle(ctx)
		clk.advance(200 * time.Millisecond)
		m.cycle(ctx)
		if rt := m.pairOf("br0"); rt.state != LinkPairPropagatedDown {
			t.Fatalf("第 %d 次应联动: %s", i+1, rt.state)
		}
		fr.dump = lpSnapshot(map[string]bool{"eth2": true, "eth3": true})
		m.cycle(ctx)
		clk.advance(200 * time.Millisecond)
		m.cycle(ctx)
		if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
			t.Fatalf("第 %d 次应恢复: %s", i+1, rt.state)
		}
	}

	// 第 3 次故障：超限 → SUPPRESSED，且不再有动作
	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(200 * time.Millisecond)
	m.cycle(ctx)
	rt := m.pairOf("br0")
	if rt.state != LinkPairSuppressed {
		t.Fatalf("超限应 SUPPRESSED: %s", rt.state)
	}
	execBefore := len(fr.execLog())
	clk.advance(10 * time.Second)
	m.cycle(ctx)
	if len(fr.execLog()) != execBefore {
		t.Fatalf("抑制态不应再有动作: %v", fr.execLog())
	}

	// 期望指纹变化（参数调整）→ 复位回 BOTH_UP
	changed := lpSpec(200, 100, 2)
	m.SetConfig([]BridgeSpec{changed}, "v2")
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("配置变更应复位抑制: %s", rt.state)
	}
}

// ---------- 抑制复位：重新保存（版本戳变化） ----------

func TestLinkPairSuppressionResetByResave(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, clk := newTestMonitor(t, fr)
	spec := lpSpec(100, 100, 1) // 上限 1 次，快速进入抑制
	ctx := context.Background()
	m.SetConfig([]BridgeSpec{spec}, "v1")

	// 制造 1 次联动即达上限；第 2 次故障进入 SUPPRESSED
	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(200 * time.Millisecond)
	m.cycle(ctx)
	fr.dump = lpSnapshot(map[string]bool{"eth2": true, "eth3": true})
	m.cycle(ctx)
	clk.advance(200 * time.Millisecond)
	m.cycle(ctx)
	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(200 * time.Millisecond)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairSuppressed {
		t.Fatalf("应进入 SUPPRESSED: %s", rt.state)
	}

	// 参数不变的重新保存（版本戳 v1→v2）→ 复位 BOTH_UP
	m.SetConfig([]BridgeSpec{spec}, "v2")
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("重新保存应复位抑制: %s", rt.state)
	}
	// 复位后联动能力恢复（重新走一轮完整防抖窗口）
	m.cycle(ctx)
	clk.advance(200 * time.Millisecond)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairPropagatedDown {
		t.Fatalf("复位后应能再次联动: %s", rt.state)
	}
}

// ---------- 重启对齐 ----------

func TestLinkPairRestartAlignment(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, clk := newTestMonitor(t, fr)
	spec := lpSpec(1000, 5000, 20)
	ctx := context.Background()

	// 先制造一次 PROPAGATED_DOWN 并落盘
	m.SetConfig([]BridgeSpec{spec}, "v1")
	fr.dump = lpSnapshot(map[string]bool{"eth2": false, "eth3": true})
	m.cycle(ctx)
	clk.advance(2 * time.Second)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairPropagatedDown {
		t.Fatalf("前置应联动: %s", rt.state)
	}

	// 模拟进程重启：新监控器读同一 status 文件
	m2 := NewLinkPairMonitor(m.StatusPath, fr)
	clk2 := &lpClock{t: clk.t}
	m2.now = clk2.now
	m2.SetConfig([]BridgeSpec{spec}, "v1")
	rt := m2.pairOf("br0")
	if rt == nil || rt.state != LinkPairPropagatedDown || rt.downPort != "eth2" || rt.propPort != "eth3" {
		t.Fatalf("重启后应按标记恢复 PROPAGATED_DOWN: %+v", rt)
	}

	// 重启后故障口恢复，可正常完成回 up
	fr.dump = lpSnapshot(map[string]bool{"eth2": true, "eth3": true})
	m2.cycle(ctx)
	clk2.advance(6 * time.Second)
	m2.cycle(ctx)
	if rt := m2.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("重启对齐后应能恢复 BOTH_UP: %s", rt.state)
	}
}

// ---------- status 合并回写（Apply 侧内容不被覆盖） ----------

func TestLinkPairStatusMergePreservesApply(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, _ := newTestMonitor(t, fr)

	// 预置一份 Apply 侧 status（含 bridges/routes 内容）
	existing := Status{
		AppliedAt: testNow.UTC().Format(time.RFC3339),
		OK:        true,
		Bridges:   []BridgeStatus{{Name: "br0", State: StateOK}},
		IPForward: StateOK,
		Routes:    []RouteStatus{{Dst: "10.9.0.0/24", Via: "192.168.50.1", State: StateOK}},
		Message:   "applied",
	}
	if err := WriteStatusAtomic(m.StatusPath, existing); err != nil {
		t.Fatalf("预置 status: %v", err)
	}

	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	m.cycle(context.Background())

	st := readStatusFile(t, m.StatusPath)
	if st.AppliedAt != existing.AppliedAt || st.IPForward != StateOK ||
		len(st.Bridges) != 1 || len(st.Routes) != 1 || st.Message != "applied" {
		t.Fatalf("Apply 侧内容被覆盖: %+v", st)
	}
	if len(st.LinkPairs) != 1 || st.LinkPairs[0].Bridge != "br0" || st.LinkPairs[0].State != LinkPairBothUp {
		t.Fatalf("link_pairs 段未写入: %+v", st.LinkPairs)
	}
}

// ---------- Supervisor 接线 ----------

func TestSupervisorWiresLinkPairMonitor(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	content := `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true}}],"ip_forward":true,"routes":[]}`
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	sv := NewSupervisor(cfgPath, stPath, time.Hour, fr)
	defer sv.Close()

	sv.tick()
	rt := sv.LinkPairs.pairOf("br0")
	if rt == nil || rt.state != LinkPairBothUp {
		t.Fatalf("tick 后监控器应跟踪联动配置: %+v", rt)
	}
	// 监控器经 cycle 回写 link_pairs 段（生产由 ticker 驱动，测试手动推进）
	sv.LinkPairs.cycle(context.Background())
	st := readStatusFile(t, stPath)
	if len(st.LinkPairs) != 1 {
		t.Fatalf("status 应含 link_pairs 段: %+v", st.LinkPairs)
	}
}

// ---------- P1-3: 双口同时掉载波无活锁 ----------

func TestLinkPairDualPortCarrierLossNoLivelock(t *testing.T) {
	// eth2 与 eth3 均处于管理 UP 但同时失去 LOWER_UP：每口独立计时，达 hold_down 后完成联动而非互相覆盖活锁。
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": false, "eth3": false})}
	m, clk := newTestMonitor(t, fr)
	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	ctx := context.Background()

	m.cycle(ctx)
	clk.advance(500 * time.Millisecond)
	m.cycle(ctx)
	if rt := m.pairOf("br0"); rt.state != LinkPairBothUp {
		t.Fatalf("防抖窗口内应保持 BOTH_UP: %s", rt.state)
	}
	clk.advance(600 * time.Millisecond) // 累计 1.1s >= 1000ms
	m.cycle(ctx)
	rt := m.pairOf("br0")
	if rt.state != LinkPairPropagatedDown || rt.downPort != "eth2" || rt.propPort != "eth3" {
		t.Fatalf("双口掉载波达 hold_down 应进入 PROPAGATED_DOWN（无活锁）: %+v", rt)
	}
}

// ---------- P1-3: 运维管理 DOWN 安全红线 ----------

func lpSnapshotCustomFlags(flagsByPort map[string][]string) []byte {
	entries := make([]map[string]any, 0, len(flagsByPort))
	for name, flags := range flagsByPort {
		entries = append(entries, map[string]any{
			"ifname": name, "flags": flags, "addr_info": []map[string]string{},
		})
	}
	data, _ := json.Marshal(entries)
	return data
}

func TestLinkPairIgnoresOperatorAdminDown(t *testing.T) {
	ctx := context.Background()

	// 场景1：运维手工 ip link set eth2 down（无 UP 标志）→ 绝不触发联动 down eth3。
	fr1 := &fakeRunner{dump: lpSnapshotCustomFlags(map[string][]string{
		"eth2": {"BROADCAST", "MULTICAST"},              // admin DOWN
		"eth3": {"BROADCAST", "MULTICAST", "UP", "LOWER_UP"},
	})}
	m1, clk1 := newTestMonitor(t, fr1)
	m1.SetConfig([]BridgeSpec{lpSpec(500, 1000, 20)}, "v1")
	m1.cycle(ctx)
	clk1.advance(2 * time.Second)
	m1.cycle(ctx)
	if rt := m1.pairOf("br0"); rt.state != LinkPairBothUp || len(fr1.execLog()) != 0 {
		t.Fatalf("运维管理 DOWN 端口不得触发联动: state=%s execs=%v", rt.state, fr1.execLog())
	}

	// 场景2：eth2 物理掉载波（UP 无 LOWER_UP），而配对口 eth3 已被运维管理 DOWN →
	// 不执行 down 也不认领 PropagatedByLinkpair 标记（避免后续把运维手工 down 的口拉 UP）。
	fr2 := &fakeRunner{dump: lpSnapshotCustomFlags(map[string][]string{
		"eth2": {"NO-CARRIER", "BROADCAST", "MULTICAST", "UP"}, // physical carrier lost
		"eth3": {"BROADCAST", "MULTICAST"},                     // operator admin DOWN
	})}
	m2, clk2 := newTestMonitor(t, fr2)
	m2.SetConfig([]BridgeSpec{lpSpec(500, 1000, 20)}, "v1")
	m2.cycle(ctx)
	clk2.advance(1 * time.Second)
	m2.cycle(ctx)
	if rt := m2.pairOf("br0"); rt.state != LinkPairBothUp || len(fr2.execLog()) != 0 {
		t.Fatalf("已管理 DOWN 的配对口不得被联动接管: state=%s msg=%q execs=%v", rt.state, rt.message, fr2.execLog())
	}
	if !strings.Contains(m2.pairOf("br0").message, "管理 DOWN") {
		t.Fatalf("应记录拒绝接管说明: %q", m2.pairOf("br0").message)
	}
}

// ---------- P1-3: 移除最后一个联动桥刷新 status ----------

func TestLinkPairRemovingLastPairFlushesStatus(t *testing.T) {
	fr := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": true, "eth3": true})}
	m, _ := newTestMonitor(t, fr)
	ctx := context.Background()

	m.SetConfig([]BridgeSpec{lpSpec(1000, 5000, 20)}, "v1")
	m.cycle(ctx)
	st := readStatusFile(t, m.StatusPath)
	if len(st.LinkPairs) != 1 {
		t.Fatalf("应写入 1 条 link_pairs: %+v", st.LinkPairs)
	}

	// 移除最后一个联动配置后，cycle 必须即使 len(pairs)==0 也刷盘清空 link_pairs。
	m.SetConfig(nil, "v2")
	m.cycle(ctx)
	st = readStatusFile(t, m.StatusPath)
	if len(st.LinkPairs) != 0 {
		t.Fatalf("移除最后一个联动桥后应清空 status.link_pairs, got %+v", st.LinkPairs)
	}
}

var _ = fmt.Sprintf // 保持 fmt 引用（调试输出备用）
