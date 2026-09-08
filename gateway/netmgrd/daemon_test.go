package netmgrd

import (
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

func writeNetmgrCfg(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("写配置: %v", err)
	}
}
