package netmgrd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitFor 轮询等待条件成立（轮询间隔 10ms，超时失败）。
func waitFor(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// readStatus 读取状态文件；不存在返回 ok=false。
func readStatus(t *testing.T, path string) (Status, bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return Status{}, false
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("状态文件应为完整 JSON（原子写）: %v", err)
	}
	return st, true
}

const daemonDump = `[
	{"ifindex":2,"ifname":"eth2","flags":["UP"],"addr_info":[]},
	{"ifindex":3,"ifname":"eth3","flags":["UP"],"addr_info":[]}
]`

func TestSupervisorLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	f := &fakeRunner{dump: []byte(daemonDump)}
	sup := NewSupervisor(cfgPath, stPath, 20*time.Millisecond, f)

	done := make(chan struct{})
	go func() { sup.Run(); close(done) }()
	defer func() {
		sup.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("Close 后 Run 未及时返回")
		}
	}()

	// 1. 无配置：空转等待，不写 status
	time.Sleep(100 * time.Millisecond)
	if _, exists := readStatus(t, stPath); exists {
		t.Fatal("配置未下发前不应写 status")
	}

	// 2. 下发配置：执行并回写 status
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t1"}`)
	waitFor(t, "首次执行回写 status", 2*time.Second, func() bool {
		st, ok := readStatus(t, stPath)
		return ok && st.OK
	})
	execsAfterFirst := len(f.execLog())
	if execsAfterFirst == 0 {
		t.Fatal("应有变更命令")
	}

	// 3. 同语义重发（仅 updated_at 变化）：幂等跳过，不重复执行
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t2-仅时间戳变化"}`)
	time.Sleep(100 * time.Millisecond)
	if got := len(f.execLog()); got != execsAfterFirst {
		t.Fatalf("指纹不变且上次成功应跳过执行: 前=%d 后=%d", execsAfterFirst, got)
	}

	// 4. 配置变化（新增路由）：再次执行
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,
		"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.254"}],"updated_at":"t3"}`)
	waitFor(t, "配置变化后再次执行", 2*time.Second, func() bool {
		st, ok := readStatus(t, stPath)
		return ok && st.OK && strings.Contains(st.Message, "只增不删")
	})
	if got := len(f.execLog()); got <= execsAfterFirst {
		t.Fatal("配置变化应触发执行")
	}

	// 5. 配置损坏：整份拒绝，status 显式报错，保留 last-good（不再执行变更）
	writeNetmgrCfg(t, cfgPath, `{"bridges": [broken`)
	waitFor(t, "配置损坏写错误 status", 2*time.Second, func() bool {
		st, ok := readStatus(t, stPath)
		return ok && !st.OK && strings.Contains(st.Message, "配置不可用")
	})
	execsAtBroken := len(f.execLog())
	time.Sleep(100 * time.Millisecond)
	if got := len(f.execLog()); got != execsAtBroken {
		t.Fatalf("配置损坏期间不得执行任何变更（last-good）: 前=%d 后=%d", execsAtBroken, got)
	}

	// 6. 恢复合法配置：恢复正常执行
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t4-恢复"}`)
	waitFor(t, "恢复合法配置后 ok", 2*time.Second, func() bool {
		st, ok := readStatus(t, stPath)
		return ok && st.OK
	})

	// 7. 收回配置（删除文件）：保留主机状态，不拆除（无 nomaster/无新变更）、
	//    不覆盖 status
	time.Sleep(60 * time.Millisecond) // 等恢复后的 tick 稳定
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	stBefore, _ := readStatus(t, stPath)
	execsBeforeDelete := len(f.execLog())
	time.Sleep(100 * time.Millisecond)
	stAfter, _ := readStatus(t, stPath)
	if stAfter.AppliedAt != stBefore.AppliedAt {
		t.Fatal("配置收回后不应重写 status")
	}
	for _, cmd := range f.execLog()[execsBeforeDelete:] {
		if strings.Contains(cmd, "nomaster") || strings.Contains(cmd, "del") {
			t.Fatalf("配置收回后不得拆除网络状态: %s", cmd)
		}
	}
}

func TestSupervisorRetriesFailedApply(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	f := &fakeRunner{
		dump:     []byte(daemonDump),
		failExec: map[string]string{"ip route replace": "Nexthop has invalid gateway"},
	}
	sup := NewSupervisor(cfgPath, stPath, 20*time.Millisecond, f)
	done := make(chan struct{})
	go func() { sup.Run(); close(done) }()
	defer func() { sup.Close(); <-done }()

	writeNetmgrCfg(t, cfgPath, `{"routes":[{"dst":"10.9.0.0/24","via":"203.0.113.1"}],"updated_at":"t1"}`)
	// 存在失败项 → 按周期重试（不 crash-loop：进程驻留、失败计入 status）
	waitFor(t, "失败项按周期重试", 2*time.Second, func() bool {
		n := 0
		for _, cmd := range f.execLog() {
			if strings.HasPrefix(cmd, "ip route replace") {
				n++
			}
		}
		return n >= 2
	})
	st, ok := readStatus(t, stPath)
	if !ok || st.OK {
		t.Fatal("失败应计入 status 且 ok=false")
	}
}

func TestSupervisorCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	sup := NewSupervisor(filepath.Join(dir, "network.json"), filepath.Join(dir, "network-status.json"),
		20*time.Millisecond, &fakeRunner{dump: []byte(`[]`)})
	done := make(chan struct{})
	go func() { sup.Run(); close(done) }()
	sup.Close()
	sup.Close() // 幂等
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close 后 Run 未及时返回")
	}
}

// P1-2: Supervisor.tick() 回写 Apply 结果时不得覆盖 LinkPairMonitor 已持久化的 link_pairs 与 transparent 段。
func TestSupervisorPreservesLinkPairsAndTransparentOnApply(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	f := &fakeRunner{dump: lpSnapshot(map[string]bool{"eth2": false, "eth3": true})}
	sup := NewSupervisor(cfgPath, stPath, time.Hour, f)
	defer sup.Close()

	clk := &lpClock{t: testNow}
	sup.LinkPairs.now = clk.now

	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_down_ms":500,"hold_up_ms":1000}}],"ip_forward":true,"updated_at":"v1"}`)
	sup.tick()
	sup.LinkPairs.cycle(t.Context())
	clk.advance(time.Second)
	sup.LinkPairs.cycle(t.Context())

	// 同时写入一条透明状态
	if err := sup.StatusWriter.WriteTransparent(&TransparentStatus{
		State: TransparentStateActive, Enabled: true, RedirectActive: true, ListenPort: 15000, Ports: []uint16{80}, Bridges: []string{"br0"},
	}); err != nil {
		t.Fatal(err)
	}

	// 修改非桥字段（新增静态路由）触发 Supervisor.tick() 重新 Apply 写 status
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2","eth3"],"link_pair":{"enabled":true,"hold_down_ms":500,"hold_up_ms":1000}}],"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.1"}],"updated_at":"v2"}`)
	sup.tick()

	st, ok := readStatus(t, stPath)
	if !ok || !st.OK {
		t.Fatalf("新配置 Apply 应成功: %+v", st)
	}
	if len(st.LinkPairs) != 1 || st.LinkPairs[0].State != LinkPairPropagatedDown || !st.LinkPairs[0].PropagatedByLinkpair {
		t.Fatalf("Supervisor.tick 不得擦除 link_pairs 联动标记: %+v", st.LinkPairs)
	}
	if st.Transparent == nil || st.Transparent.State != TransparentStateActive || !st.Transparent.RedirectActive {
		t.Fatalf("Supervisor.tick 不得擦除 transparent 状态: %+v", st.Transparent)
	}
}

// P1-4: 合法配置 A -> 坏配置（ok:false）-> 恢复回完全相同的合法配置 A（指纹不变）→ 必须重写健康状态 ok:true。
func TestSupervisorRecoversSameConfigAfterBadConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	f := &fakeRunner{dump: []byte(daemonDump)}
	sup := NewSupervisor(cfgPath, stPath, time.Hour, f)
	defer sup.Close()

	validA := `{"bridges":[{"name":"br0","ports":["eth2"]}],"ip_forward":true,"updated_at":"t1"}`
	writeNetmgrCfg(t, cfgPath, validA)
	sup.tick()
	st, ok := readStatus(t, stPath)
	if !ok || !st.OK {
		t.Fatalf("初始配置 A 应成功: %+v", st)
	}

	// 写入非法 JSON → status 变 ok:false
	writeNetmgrCfg(t, cfgPath, `{"bridges": [broken`)
	sup.tick()
	st, ok = readStatus(t, stPath)
	if !ok || st.OK {
		t.Fatalf("坏配置应写入 ok=false: %+v", st)
	}

	// 原样恢复到配置 A（指纹与上次成功一致）→ 必须将 status 恢复为 ok=true
	writeNetmgrCfg(t, cfgPath, validA)
	sup.tick()
	st, ok = readStatus(t, stPath)
	if !ok || !st.OK || strings.Contains(st.Message, "配置不可用") {
		t.Fatalf("恢复回同指纹合法配置 A 后 status 不得卡在 ok=false: %+v", st)
	}
	if err := sup.Readiness(); err != nil {
		t.Fatalf("恢复后 Readiness 应健康: %v", err)
	}
}

// P1-8 + P0-2: 从 network.json 移除已纳管网桥 br0 时，Supervisor 必须先冲刷透明牵引链再执行 nomaster/down/del。
func TestSupervisorTearsDownManagedBridgeAndFlushesTransparent(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "network.json")
	stPath := filepath.Join(dir, "network-status.json")
	tpPath := filepath.Join(dir, "tproxyd.json")

	f, _ := newIptablesFakeRunner()
	f.dump = []byte(`[
		{"ifindex":2,"ifname":"eth2","flags":["UP"],"addr_info":[]},
		{"ifindex":3,"ifname":"eth3","flags":["UP"],"addr_info":[]}
	]`)
	sup := NewSupervisor(cfgPath, stPath, time.Hour, f)
	defer sup.Close()
	sup.Transparent.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true, Listen: "0.0.0.0:15000"}, nil
	}
	sup.Transparent.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }

	// 1. 创建 br0 并激活透明牵引规则
	writeNetmgrCfg(t, cfgPath, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true,"updated_at":"t1"}`)
	writeNetmgrCfg(t, tpPath, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)
	sup.tick()
	sup.Transparent.cycle(t.Context())

	st, ok := readStatus(t, stPath)
	if !ok || !st.OK || len(st.ManagedBridges) != 1 || st.ManagedBridges[0] != "br0" {
		t.Fatalf("br0 应记录在 managed_bridges: %+v", st)
	}
	if st.Transparent == nil || st.Transparent.State != TransparentStateActive {
		t.Fatalf("透明牵引应处于 ACTIVE: %+v", st.Transparent)
	}

	// 2. 从 network.json 移除 br0（模拟关闭透明网桥）→ 先冲刷 iptables 链，再拆除 br0
	f.mu.Lock()
	f.dump = []byte(`[
		{"ifindex":10,"ifname":"br0","flags":["UP"],"linkinfo":{"info_kind":"bridge"},"addr_info":[]},
		{"ifindex":2,"ifname":"eth2","flags":["UP"],"master":"br0","addr_info":[]},
		{"ifindex":3,"ifname":"eth3","flags":["UP"],"master":"br0","addr_info":[]}
	]`)
	f.mu.Unlock()
	beforeRemove := len(f.execLog())
	writeNetmgrCfg(t, cfgPath, `{"bridges":[],"ip_forward":true,"updated_at":"t2"}`)
	sup.tick()

	after := f.execLog()[beforeRemove:]
	flushIdx, delIdx := -1, -1
	for i, cmd := range after {
		if strings.Contains(cmd, "-F JIUZHANG_TPROXY_PRE") && flushIdx == -1 {
			flushIdx = i
		}
		if cmd == "ip link del br0" && delIdx == -1 {
			delIdx = i
		}
	}
	if flushIdx == -1 || delIdx == -1 || flushIdx > delIdx {
		t.Fatalf("必须先冲刷 JIUZHANG_TPROXY_PRE 再删除 br0: flushIdx=%d delIdx=%d cmds=%v", flushIdx, delIdx, after)
	}
}

func writeNetmgrCfg(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写配置: %v", err)
	}
}
