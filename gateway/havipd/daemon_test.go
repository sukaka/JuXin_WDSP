// havipd 测试：契约校验、keepalived 配置生成、监督器全生命周期
// （应用/重载/收回/DISABLED/非本节点/启动失败）、状态推导与漂移事件。
package havipd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ---------- 测试基础设施 ----------

// fakeRunner 脚本化命令桩：ip 查询返回预置地址输出；keepalived 启动按注入成败；
// 记录全部命令。
type fakeRunner struct {
	addrDump []byte // `ip -j addr show` 输出
	addrErr  error
	startErr error // keepalived 启动注入失败
	failPref map[string]string
	cmds     []string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := name + " " + strings.Join(args, " ")
	f.cmds = append(f.cmds, cmd)
	if name == "ip" {
		return f.addrDump, f.addrErr
	}
	for pref, msg := range f.failPref {
		if strings.HasPrefix(cmd, pref) {
			return nil, &CmdError{Name: name, Args: args, Stderr: msg, Err: fmt.Errorf("exit status 1")}
		}
	}
	if name == "keepalived" && f.startErr != nil {
		return nil, f.startErr
	}
	return nil, nil
}

// fakeProc 进程桩：存活集合与信号记录。
type fakeProc struct {
	alive      map[int]bool
	signals    []string
	ignoreTERM bool
	ignoreKILL bool
}

func (f *fakeProc) Alive(pid int) bool { return f.alive[pid] }
func (f *fakeProc) Signal(pid int, sig os.Signal) error {
	f.signals = append(f.signals, fmt.Sprintf("%d:%v", pid, sig))
	if !f.alive[pid] {
		return fmt.Errorf("no such process")
	}
	if sig == syscall.SIGTERM && !f.ignoreTERM {
		f.alive[pid] = false // 模拟退出
	}
	if sig == syscall.SIGKILL && !f.ignoreKILL {
		f.alive[pid] = false // 模拟强制终止
	}
	return nil
}

// addrDump 构造 `ip -j addr show` 输出（全部全局 IPv4）。
func addrDump(ips ...string) []byte {
	infos := make([]map[string]string, 0, len(ips))
	for _, ip := range ips {
		infos = append(infos, map[string]string{"family": "inet", "local": ip, "scope": "global"})
	}
	data, _ := json.Marshal([]map[string]any{{"addr_info": infos}})
	return data
}

const testNode = "gw-a"

// validConfigJSON 合法配置（gw-a 优先级 120 > gw-b 100；VIP 192.168.31.100/24）。
func validConfigJSON(state string) string {
	return fmt.Sprintf(`{
  "group": "ha-main",
  "state": "%s",
  "members": [{"node":"gw-a","priority":120},{"node":"gw-b","priority":100}],
  "vrrp": {"vrid":51,"vips":["192.168.31.100/24"],"iface":"eth0",
    "preempt":false,"advert_int_ms":1000,"auth_pass":"v1psecr8","unicast_peers":["192.168.31.61","192.168.31.62"]},
  "updated_at": "test"
}`, state)
}

// newTestSupervisor 装配测试监督器：临时目录 + 桩 Runner/Proc；并预置 keepalived
// 二进制存在（execLookPath 注入）。
func newTestSupervisor(t *testing.T, fr *fakeRunner, fp *fakeProc) (*Supervisor, string) {
	t.Helper()
	dir := t.TempDir()
	orig := execLookPath
	execLookPath = func(name string) (string, error) { return "/usr/sbin/keepalived", nil }
	t.Cleanup(func() { execLookPath = orig })
	sv := NewSupervisor(testNode,
		filepath.Join(dir, "ha-vip.json"),
		filepath.Join(dir, "ha-vip-status.json"),
		filepath.Join(dir, "keepalived"),
		fr, fp)
	return sv, dir
}

func writeCfg(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "ha-vip.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readStatus(t *testing.T, path string) Status {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读 status: %v", err)
	}
	var st Status
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("解析 status: %v", err)
	}
	return st
}

// simulateKeepalivedRunning 模拟 keepalived 运行：写 pidfile 并标记存活。
func simulateKeepalivedRunning(t *testing.T, sv *Supervisor, fp *fakeProc, pid int) {
	t.Helper()
	sv.mu.Lock()
	defer sv.mu.Unlock()
	if sv.cfg == nil {
		t.Fatal("无配置，无法模拟实例")
	}
	pf := pathsFor(sv.WorkDir, sv.cfg.Group).PidFile
	if err := os.MkdirAll(filepath.Dir(pf), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pf, []byte(fmt.Sprintf("%d\n", pid)), 0o644); err != nil {
		t.Fatal(err)
	}
	fp.alive[pid] = true
}

// ---------- 契约校验 ----------

func TestConfigValidation(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name    string
		mutate  func(string) string
		wantErr string
	}{
		{"合法 ENABLED", func(s string) string { return s }, ""},
		{"合法 DISABLED", func(s string) string {
			return strings.Replace(s, `"ENABLED"`, `"DISABLED"`, 1)
		}, ""},
		{"组名非法", func(s string) string {
			return strings.Replace(s, `"ha-main"`, `"bad name!"`, 1)
		}, "组名非法"},
		{"state 非法", func(s string) string {
			return strings.Replace(s, `"ENABLED"`, `"PAUSED"`, 1)
		}, "state 取值非法"},
		{"成员不是 2 个", func(s string) string {
			return strings.Replace(s, `,{"node":"gw-b","priority":100}`, ``, 1)
		}, "恰好 2 个"},
		{"优先级重复", func(s string) string {
			return strings.Replace(s, `"priority":100`, `"priority":120`, 1)
		}, "优先级重复"},
		{"vrid 越界", func(s string) string {
			return strings.Replace(s, `"vrid":51`, `"vrid":999`, 1)
		}, "vrid 越界"},
		{"vips 为空", func(s string) string {
			return strings.Replace(s, `["192.168.31.100/24"]`, `[]`, 1)
		}, "至少 1 个"},
		{"vip 非 CIDR", func(s string) string {
			return strings.Replace(s, `"192.168.31.100/24"`, `"192.168.31.100"`, 1)
		}, "需 CIDR"},
		{"advert 越界", func(s string) string {
			return strings.Replace(s, `"advert_int_ms":1000`, `"advert_int_ms":10`, 1)
		}, "advert_int_ms 越界"},
		{"认证串超长", func(s string) string {
			return strings.Replace(s, `"v1psecr8"`, `"123456789"`, 1)
		}, "上限 8 字符"},
		{"认证串含换行（注入配置行）", func(s string) string {
			return strings.Replace(s, `"v1psecr8"`, `"abcd\npx"`, 1)
		}, "可打印非空白 ASCII"},
		{"认证串含空格", func(s string) string {
			return strings.Replace(s, `"v1psecr8"`, `"ab cd"`, 1)
		}, "可打印非空白 ASCII"},
		{"认证串含制表符", func(s string) string {
			return strings.Replace(s, `"v1psecr8"`, `"ab\tcd"`, 1)
		}, "可打印非空白 ASCII"},
		{"认证串含非 ASCII", func(s string) string {
			return strings.Replace(s, `"v1psecr8"`, `"密码ab"`, 1)
		}, "可打印非空白 ASCII"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, "c.json")
			if err := os.WriteFile(p, []byte(tc.mutate(validConfigJSON("ENABLED"))), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadConfig(p)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("不应报错: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("期望错误含 %q: %v", tc.wantErr, err)
			}
		})
	}
}

// ---------- keepalived 配置生成 ----------

func TestRenderConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(validConfigJSON("ENABLED")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	self, _ := cfg.selfMember("gw-a")
	out := renderConfig(cfg, self, "192.168.31.61")
	for _, want := range []string{
		"vrrp_instance ha-main {",
		"  interface eth0",
		"  virtual_router_id 51",
		"  priority 120",
		"  nopreempt",
		"    auth_pass v1psecr8",
		"  unicast_src_ip 192.168.31.61",
		"    192.168.31.62", // 对端（自身地址被过滤）
		"    192.168.31.100/24 dev eth0",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("生成配置缺 %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "    192.168.31.61\n") {
		t.Fatalf("自身地址不应写入 unicast_peer:\n%s", out)
	}
	// 组名消毒
	if !strings.Contains(out, "router_id JZ_HA_ha-main") {
		t.Fatalf("router_id 未生成:\n%s", out)
	}
}

// ---------- 监督器生命周期 ----------

func TestSupervisorApplyStartReloadStop(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	// 等待下发：STOPPED
	sv.configTick()
	if sv.state != StateStopped {
		t.Fatalf("无配置应 STOPPED: %s", sv.state)
	}

	// 下发 ENABLED：生成配置 + 启动 keepalived
	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	confRaw, err := os.ReadFile(pathsFor(sv.WorkDir, "ha-main").Conf)
	if err != nil {
		t.Fatalf("keepalived 配置未生成: %v", err)
	}
	if !strings.Contains(string(confRaw), "priority 120") {
		t.Fatalf("配置内容不符: %s", confRaw)
	}
	if fi, _ := os.Stat(pathsFor(sv.WorkDir, "ha-main").Conf); fi.Mode().Perm() != 0o600 {
		t.Fatalf("含认证串配置必须 0600: %v", fi.Mode())
	}
	if len(fr.cmds) == 0 || !strings.HasPrefix(fr.cmds[len(fr.cmds)-1], "keepalived -f ") {
		t.Fatalf("应发起 keepalived 启动: %v", fr.cmds)
	}

	// 模拟实例运行后：指纹不变重复 tick 不重载
	simulateKeepalivedRunning(t, sv, fp, 4321)
	cmdsBefore := len(fr.cmds)
	sv.configTick()
	if len(fr.cmds) != cmdsBefore {
		t.Fatalf("指纹不变不应有动作: %v", fr.cmds)
	}

	// 配置变化（advert 调整 → 指纹变化）：SIGHUP 重载而非重启
	writeCfg(t, dir, strings.Replace(validConfigJSON("ENABLED"), `"advert_int_ms":1000`, `"advert_int_ms":2000`, 1))
	sv.configTick()
	foundHUP := false
	for _, s := range fp.signals {
		if s == fmt.Sprintf("%d:%v", 4321, syscall.SIGHUP) {
			foundHUP = true
		}
	}
	if !foundHUP {
		t.Fatalf("运行中配置变化应 SIGHUP 重载: %v", fp.signals)
	}

	// DISABLED：SIGTERM 停止
	writeCfg(t, dir, validConfigJSON("DISABLED"))
	sv.configTick()
	foundTERM := false
	for _, s := range fp.signals {
		if s == fmt.Sprintf("%d:%v", 4321, syscall.SIGTERM) {
			foundTERM = true
		}
	}
	if !foundTERM {
		t.Fatalf("DISABLED 应 SIGTERM 停止: %v", fp.signals)
	}
	if sv.state != StateDisabled {
		t.Fatalf("DISABLED 后状态: %s", sv.state)
	}
}

func TestSupervisorNotMyGroup(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, strings.Replace(validConfigJSON("ENABLED"), `"gw-a"`, `"gw-c"`, 1))
	sv.configTick()
	if sv.state != StateStopped {
		t.Fatalf("非本节点配置应 STOPPED: %s", sv.state)
	}
	if !strings.Contains(sv.message, "不含本节点") {
		t.Fatalf("应显式报错: %s", sv.message)
	}
	for _, c := range fr.cmds {
		if strings.HasPrefix(c, "keepalived") {
			t.Fatalf("非本节点不应启动 keepalived: %v", fr.cmds)
		}
	}
}

func TestSupervisorStartFailure(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61"), startErr: fmt.Errorf("exit status 1")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	if sv.state != StateFault {
		t.Fatalf("启动失败应 FAULT: %s", sv.state)
	}
	if !strings.Contains(sv.message, "启动失败") {
		t.Fatalf("应记录启动失败: %s", sv.message)
	}
}

func TestSupervisorConfigRemovedReleasesVIP(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	simulateKeepalivedRunning(t, sv, fp, 4321)

	// 删除配置 = 收回：SIGTERM 停止并回 STOPPED
	if err := os.Remove(filepath.Join(dir, "ha-vip.json")); err != nil {
		t.Fatal(err)
	}
	sv.configTick()
	if sv.state != StateStopped {
		t.Fatalf("收回后应 STOPPED: %s", sv.state)
	}
	foundTERM := false
	for _, s := range fp.signals {
		if s == fmt.Sprintf("%d:%v", 4321, syscall.SIGTERM) {
			foundTERM = true
		}
	}
	if !foundTERM {
		t.Fatalf("收回应停止实例: %v", fp.signals)
	}
}

// H-13 回归：指纹未变但 keepalived 意外死亡进入 FAULT 后，下轮 configTick 必须拉起恢复。
func TestSupervisorRestartsDeadKeepalivedWithSameFingerprint(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	simulateKeepalivedRunning(t, sv, fp, 4321)
	sv.stateTick()
	if sv.state != StateBackup {
		t.Fatalf("正常启动后应为 BACKUP: %s", sv.state)
	}

	// keepalived 意外崩溃 → stateTick 落 FAULT
	fp.alive[4321] = false
	sv.stateTick()
	if sv.state != StateFault {
		t.Fatalf("进程死亡后应为 FAULT: %s", sv.state)
	}

	// 配置内容完全未变（同指纹）→ configTick 仍应检测到进程死亡并重新拉起 keepalived
	cmdsBefore := len(fr.cmds)
	sv.configTick()
	restarted := false
	for _, cmd := range fr.cmds[cmdsBefore:] {
		if strings.HasPrefix(cmd, "keepalived -f ") {
			restarted = true
			break
		}
	}
	if !restarted {
		t.Fatalf("keepalived 死亡后同指纹 configTick 未拉起恢复: cmds=%v", fr.cmds[cmdsBefore:])
	}

	// 新实例运行后 stateTick 应从 FAULT 恢复
	simulateKeepalivedRunning(t, sv, fp, 5678)
	sv.stateTick()
	if sv.state != StateBackup {
		t.Fatalf("拉起恢复后应退出 FAULT: %s", sv.state)
	}
}

// H-13 回归：配置组名变更时必须先停止旧组 keepalived（防双实例脑裂），再切换新组配置。
func TestSupervisorGroupRenameStopsOldInstanceBeforeStartingNew(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	simulateKeepalivedRunning(t, sv, fp, 4321)
	oldPidFile := pathsFor(sv.WorkDir, "ha-main").PidFile

	// 改组名为 ha-next（ENABLED）
	writeCfg(t, dir, strings.Replace(validConfigJSON("ENABLED"), `"ha-main"`, `"ha-next"`, 1))
	cmdsBefore := len(fr.cmds)
	sv.configTick()

	foundOldTerm := false
	for _, sig := range fp.signals {
		if sig == fmt.Sprintf("%d:%v", 4321, syscall.SIGTERM) {
			foundOldTerm = true
			break
		}
	}
	if !foundOldTerm {
		t.Fatalf("组名变更未停止旧组实例 4321: signals=%v", fp.signals)
	}
	if _, err := os.Stat(oldPidFile); !os.IsNotExist(err) {
		t.Fatalf("旧组 pidfile 未清理: %v", err)
	}
	startedNew := false
	for _, cmd := range fr.cmds[cmdsBefore:] {
		if strings.Contains(cmd, "ha-next.conf") && strings.Contains(cmd, "ha-next.pid") {
			startedNew = true
			break
		}
	}
	if !startedNew {
		t.Fatalf("新组 ha-next 未启动: cmds=%v", fr.cmds[cmdsBefore:])
	}

	// 再次改组名并切 DISABLED：仍必须先停 ha-next 实例
	simulateKeepalivedRunning(t, sv, fp, 5678)
	writeCfg(t, dir, strings.Replace(validConfigJSON("DISABLED"), `"ha-main"`, `"ha-off"`, 1))
	sv.configTick()
	foundNextTerm := false
	for _, sig := range fp.signals {
		if sig == fmt.Sprintf("%d:%v", 5678, syscall.SIGTERM) {
			foundNextTerm = true
			break
		}
	}
	if !foundNextTerm {
		t.Fatalf("改组名并 DISABLED 未停止旧组实例 5678: signals=%v", fp.signals)
	}
	if sv.state != StateDisabled {
		t.Fatalf("期望 StateDisabled, got %s", sv.state)
	}
}

// H-13 回归：SIGTERM 宽限后实例仍存活时必须升级 SIGKILL，且仅在确认退出后清理 pidfile。
func TestSupervisorStopEscalatesToSIGKILL(t *testing.T) {
	origInterval, origTerm, origKill := stopPollInterval, stopTermMaxPolls, stopKillMaxPolls
	stopPollInterval = time.Millisecond
	stopTermMaxPolls = 3
	stopKillMaxPolls = 3
	t.Cleanup(func() {
		stopPollInterval = origInterval
		stopTermMaxPolls = origTerm
		stopKillMaxPolls = origKill
	})

	t.Run("升级SIGKILL并清理pidfile", func(t *testing.T) {
		fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
		fp := &fakeProc{alive: map[int]bool{}, ignoreTERM: true}
		sv, dir := newTestSupervisor(t, fr, fp)
		defer sv.CloseWithoutStop()

		writeCfg(t, dir, validConfigJSON("ENABLED"))
		sv.configTick()
		simulateKeepalivedRunning(t, sv, fp, 7001)
		pidFile := pathsFor(sv.WorkDir, "ha-main").PidFile

		writeCfg(t, dir, validConfigJSON("DISABLED"))
		sv.configTick()

		want := []string{
			fmt.Sprintf("%d:%v", 7001, syscall.SIGTERM),
			fmt.Sprintf("%d:%v", 7001, syscall.SIGKILL),
		}
		if strings.Join(fp.signals, ",") != strings.Join(want, ",") {
			t.Fatalf("期望先 SIGTERM 再升级 SIGKILL: got=%v want=%v", fp.signals, want)
		}
		if fp.alive[7001] {
			t.Fatal("SIGKILL 后进程应已终止")
		}
		if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
			t.Fatalf("进程已退出，pidfile 应被清理: %v", err)
		}
	})

	t.Run("SIGKILL后仍存活不删除pidfile", func(t *testing.T) {
		fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
		fp := &fakeProc{alive: map[int]bool{}, ignoreTERM: true, ignoreKILL: true}
		sv, dir := newTestSupervisor(t, fr, fp)
		defer sv.CloseWithoutStop()

		writeCfg(t, dir, validConfigJSON("ENABLED"))
		sv.configTick()
		simulateKeepalivedRunning(t, sv, fp, 7002)
		pidFile := pathsFor(sv.WorkDir, "ha-main").PidFile

		writeCfg(t, dir, validConfigJSON("DISABLED"))
		sv.configTick()

		if _, err := os.Stat(pidFile); err != nil {
			t.Fatalf("进程仍存活时不应删除 pidfile（保留追踪）: %v", err)
		}
	})
}

// ---------- 状态推导与漂移事件 ----------

func TestStateTransitionsAndEvents(t *testing.T) {
	fr := &fakeRunner{addrDump: addrDump("192.168.31.61")}
	fp := &fakeProc{alive: map[int]bool{}}
	sv, dir := newTestSupervisor(t, fr, fp)
	defer sv.CloseWithoutStop()

	writeCfg(t, dir, validConfigJSON("ENABLED"))
	sv.configTick()
	simulateKeepalivedRunning(t, sv, fp, 4321)

	// 未持有 VIP → BACKUP
	sv.stateTick()
	if sv.state != StateBackup {
		t.Fatalf("未持有 VIP 应 BACKUP: %s", sv.state)
	}

	// 持有 VIP → MASTER（漂移事件 BACKUP→MASTER）
	fr.addrDump = addrDump("192.168.31.61", "192.168.31.100")
	sv.stateTick()
	if sv.state != StateMaster {
		t.Fatalf("持有 VIP 应 MASTER: %s", sv.state)
	}
	if len(sv.events) == 0 || sv.events[0].From != StateBackup || sv.events[0].To != StateMaster {
		t.Fatalf("应记录漂移事件: %+v", sv.events)
	}
	if !strings.Contains(sv.events[0].Detail, "192.168.31.100") {
		t.Fatalf("事件应含 VIP 明细: %+v", sv.events[0])
	}

	// keepalived 死亡 → FAULT
	fp.alive[4321] = false
	sv.stateTick()
	if sv.state != StateFault {
		t.Fatalf("进程死亡应 FAULT: %s", sv.state)
	}

	// status 文件内容齐备
	st := readStatus(t, sv.StatusPath)
	if st.Group != "ha-main" || st.Node != "gw-a" || st.Priority != 120 ||
		st.State != StateFault || st.LastTransitionAt == "" || len(st.Events) < 2 {
		t.Fatalf("status 不齐备: %+v", st)
	}
	if strings.Contains(string(mustReadFile(t, sv.StatusPath)), "v1psecr8") {
		t.Fatal("status 不得包含认证串")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// ---------- 地址解析与 VIP 判定 ----------

func TestParseAddrDumpAndVIPPresent(t *testing.T) {
	src, addrs, err := parseAddrDump(addrDump("192.168.31.61", "192.168.31.100"))
	if err != nil {
		t.Fatal(err)
	}
	if src != "192.168.31.61" || len(addrs) != 2 {
		t.Fatalf("解析不符: src=%s addrs=%v", src, addrs)
	}
	if !vipPresent([]string{"192.168.31.100/24"}, addrs) {
		t.Fatal("VIP 应判定在位")
	}
	if vipPresent([]string{"192.168.31.101/24"}, addrs) {
		t.Fatal("不存在的 VIP 不应判定在位")
	}
}
