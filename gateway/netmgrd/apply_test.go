package netmgrd

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRunner 脚本化执行桩：Query 返回预置的 `ip -j -d addr show` 输出，
// Exec 按命令前缀注入失败并记录全部变更命令。
type fakeRunner struct {
	mu       sync.Mutex
	dump     []byte
	dumpErr  error
	failExec map[string]string // 命令前缀 → 错误信息
	execs    []string
}

func (f *fakeRunner) Query(_ context.Context, name string, args ...string) ([]byte, error) {
	want := []string{"ip", "-j", "-d", "addr", "show"}
	got := append([]string{name}, args...)
	if !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("未预期的查询命令: %s", strings.Join(got, " "))
	}
	return f.dump, f.dumpErr
}

func (f *fakeRunner) Exec(_ context.Context, name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.execs = append(f.execs, cmd)
	f.mu.Unlock()
	for prefix, msg := range f.failExec {
		if strings.HasPrefix(cmd, prefix) {
			return &CmdError{Name: name, Args: args, Stderr: msg, Err: fmt.Errorf("exit status 1")}
		}
	}
	return nil
}

func (f *fakeRunner) execLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.execs...)
}

var testNow = time.Date(2026, 8, 19, 6, 0, 0, 0, time.UTC)

// applyCfg 便捷构造已校验配置（测试语义等价于 LoadConfig 产物）。
func applyCfg(t *testing.T, content string) Config {
	t.Helper()
	cfg, err := LoadConfig(writeOnly(t, content))
	if err != nil {
		t.Fatalf("测试配置应通过校验: %v", err)
	}
	return cfg
}

func TestApplyFreshSystemFullSequence(t *testing.T) {
	// eth2 仅带 inet6 link-scope 地址（接口 up 后内核自动分配，不算「已配 IP」）
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"eth2","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
		 "addr_info":[{"family":"inet6","local":"fe80::a","prefixlen":64,"scope":"link"}]},
		{"ifindex":3,"ifname":"eth3","flags":["BROADCAST","MULTICAST"],"addr_info":[]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],
		"ip_forward":true,
		"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.254"}]}`)

	st := Apply(context.Background(), cfg, f, testNow)

	wantExecs := []string{
		"ip link add br0 type bridge",
		"ip link set eth2 master br0",
		"ip link set eth3 master br0",
		"ip link set br0 up",
		"sysctl -w net.ipv4.ip_forward=1",
		"ip route replace 10.9.0.0/24 via 192.168.50.254",
	}
	if got := f.execLog(); !reflect.DeepEqual(got, wantExecs) {
		t.Fatalf("命令序列不符:\n got=%v\nwant=%v", got, wantExecs)
	}
	if !st.OK {
		t.Fatalf("应全项成功: %+v", st)
	}
	if st.AppliedAt != "2026-08-19T06:00:00Z" {
		t.Fatalf("applied_at 错误: %s", st.AppliedAt)
	}
	if len(st.Bridges) != 1 || st.Bridges[0].State != StateOK || st.Bridges[0].Name != "br0" {
		t.Fatalf("桥状态错误: %+v", st.Bridges)
	}
	if st.IPForward != StateOK {
		t.Fatalf("ip_forward 状态错误: %s", st.IPForward)
	}
	if len(st.Routes) != 1 || st.Routes[0].State != StateOK ||
		st.Routes[0].Dst != "10.9.0.0/24" || st.Routes[0].Via != "192.168.50.254" {
		t.Fatalf("路由状态错误: %+v", st.Routes)
	}
	if !strings.Contains(st.Message, "只增不删") {
		t.Fatalf("有路由时 status 应注明只增不删: %s", st.Message)
	}
}

func TestApplyIdempotentNoChanges(t *testing.T) {
	// 桥已存在且成员正确：不重建桥、不重挂成员；仅幂等 set up（sysctl/route 按配置项）
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"br0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],
		 "linkinfo":{"info_kind":"bridge"},"addr_info":[]},
		{"ifindex":3,"ifname":"eth2","flags":["UP","LOWER_UP"],"master":"br0","addr_info":[]},
		{"ifindex":4,"ifname":"eth3","flags":["UP","LOWER_UP"],"master":"br0","addr_info":[]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true}`)

	st := Apply(context.Background(), cfg, f, testNow)

	wantExecs := []string{
		"ip link set br0 up",
		"sysctl -w net.ipv4.ip_forward=1",
	}
	if got := f.execLog(); !reflect.DeepEqual(got, wantExecs) {
		t.Fatalf("幂等重放不应有桥结构变更:\n got=%v\nwant=%v", got, wantExecs)
	}
	if !st.OK || st.Message != "applied" {
		t.Fatalf("应全项成功: %+v", st)
	}
}

func TestApplyReconcileMembers(t *testing.T) {
	// eth3 缺失（应补挂）；eth4 多余（应 nomaster）
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"br0","flags":["UP"],"linkinfo":{"info_kind":"bridge"},"addr_info":[]},
		{"ifindex":3,"ifname":"eth2","flags":["UP"],"master":"br0","addr_info":[]},
		{"ifindex":4,"ifname":"eth3","flags":["UP"],"addr_info":[]},
		{"ifindex":5,"ifname":"eth4","flags":["UP"],"master":"br0","addr_info":[]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}]}`)

	st := Apply(context.Background(), cfg, f, testNow)

	wantExecs := []string{
		"ip link set eth3 master br0",
		"ip link set eth4 nomaster",
		"ip link set br0 up",
	}
	if got := f.execLog(); !reflect.DeepEqual(got, wantExecs) {
		t.Fatalf("reconcile 序列不符:\n got=%v\nwant=%v", got, wantExecs)
	}
	if !st.OK {
		t.Fatalf("应成功: %+v", st)
	}
	if st.IPForward != StateSkipped {
		t.Fatalf("ip_forward=false 应为 skipped: %s", st.IPForward)
	}
}

func TestApplyRefusePortWithIPv4(t *testing.T) {
	// 安全红线：mgmt0 已配 IPv4（管理口），拒绝收入桥；整桥零变更（连桥都不创建）
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"eth2","flags":["UP"],"addr_info":[]},
		{"ifindex":3,"ifname":"mgmt0","flags":["UP","LOWER_UP"],"addr_info":[
			{"family":"inet","local":"192.168.50.1","prefixlen":24,"scope":"global"},
			{"family":"inet6","local":"fe80::b","prefixlen":64,"scope":"link"}]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2","mgmt0"]}],"ip_forward":true}`)

	st := Apply(context.Background(), cfg, f, testNow)

	if got := f.execLog(); len(got) != 1 || got[0] != "sysctl -w net.ipv4.ip_forward=1" {
		t.Fatalf("安全红线触发时该桥应零变更（仅独立的 sysctl 可执行）: %v", got)
	}
	if st.OK {
		t.Fatal("应整体失败")
	}
	if len(st.Bridges) != 1 || st.Bridges[0].State != StateError {
		t.Fatalf("桥应记 error: %+v", st.Bridges)
	}
	if msg := st.Bridges[0].Message; !strings.Contains(msg, "mgmt0") || !strings.Contains(msg, "IP") {
		t.Fatalf("错误应指明被拒绝的口与原因: %s", msg)
	}
	if !strings.Contains(st.Message, "bridge/br0") {
		t.Fatalf("汇总信息应含桥失败项: %s", st.Message)
	}
}

func TestApplyRefuseIPv6Global(t *testing.T) {
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"eth5","flags":["UP"],"addr_info":[
			{"family":"inet6","local":"2001:db8::1","prefixlen":64,"scope":"global"}]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth5"]}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if st.OK || st.Bridges[0].State != StateError || !strings.Contains(st.Bridges[0].Message, "eth5") {
		t.Fatalf("inet6 global 地址同样触发安全红线: %+v", st.Bridges)
	}
	if got := f.execLog(); len(got) != 0 {
		t.Fatalf("应零变更: %v", got)
	}
}

func TestApplyAlreadyMemberWithIPIsNotBlocked(t *testing.T) {
	// 已是本桥成员的口不算「收入桥」：安全红线只拦截入桥动作，
	// 不因此类存量状态阻塞整桥 reconcile（避免状态锁死）
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"br0","flags":["UP"],"linkinfo":{"info_kind":"bridge"},"addr_info":[]},
		{"ifindex":3,"ifname":"eth2","flags":["UP"],"master":"br0","addr_info":[
			{"family":"inet","local":"192.168.50.5","prefixlen":24,"scope":"global"}]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2"]}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if !st.OK {
		t.Fatalf("存量成员不触发红线: %+v", st)
	}
	if got := f.execLog(); !reflect.DeepEqual(got, []string{"ip link set br0 up"}) {
		t.Fatalf("无需成员变更: %v", got)
	}
}

func TestApplyNonBridgeNameConflict(t *testing.T) {
	f := &fakeRunner{dump: []byte(`[
		{"ifindex":2,"ifname":"br0","flags":["UP"],"linkinfo":{"info_kind":"vlan"},"addr_info":[]}
	]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":[]}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if st.OK || st.Bridges[0].State != StateError || !strings.Contains(st.Bridges[0].Message, "非桥设备") {
		t.Fatalf("同名非桥设备应拒绝接管: %+v", st.Bridges)
	}
	if got := f.execLog(); len(got) != 0 {
		t.Fatalf("应零变更: %v", got)
	}
}

func TestApplyPortMissing(t *testing.T) {
	f := &fakeRunner{dump: []byte(`[]`)}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth9"]}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if st.OK || st.Bridges[0].State != StateError || !strings.Contains(st.Bridges[0].Message, "不存在") {
		t.Fatalf("缺失成员口应记 error: %+v", st.Bridges)
	}
	if got := f.execLog(); len(got) != 0 {
		t.Fatalf("应零变更: %v", got)
	}
}

func TestApplyIPForwardSkippedWhenFalse(t *testing.T) {
	f := &fakeRunner{dump: []byte(`[]`)}
	cfg := applyCfg(t, `{"ip_forward":false}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if !st.OK || st.IPForward != StateSkipped {
		t.Fatalf("ip_forward=false → skipped 且不算失败: %+v", st)
	}
	for _, cmd := range f.execLog() {
		if strings.Contains(cmd, "sysctl") {
			t.Fatalf("ip_forward=false 不得触碰 sysctl: %v", f.execLog())
		}
	}
	// 空配置：bridges/routes 必须序列化为 [] 而非 null
	if st.Bridges == nil || st.Routes == nil {
		t.Fatal("空集合应初始化为非 nil（JSON 输出 []）")
	}
}

func TestApplyRouteErrorIsolated(t *testing.T) {
	f := &fakeRunner{
		dump:     []byte(`[]`),
		failExec: map[string]string{"ip route replace": "Nexthop has invalid gateway"},
	}
	cfg := applyCfg(t, `{"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"203.0.113.1"}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if st.OK {
		t.Fatal("路由失败应整体不 ok")
	}
	if st.Routes[0].State != StateError || !strings.Contains(st.Routes[0].Message, "Nexthop") {
		t.Fatalf("路由错误应记入该项: %+v", st.Routes)
	}
	// 独立性：sysctl 不受影响照常执行
	if st.IPForward != StateOK {
		t.Fatalf("ip_forward 应不受路由失败影响: %s", st.IPForward)
	}
	if !strings.Contains(st.Message, "10.9.0.0/24") {
		t.Fatalf("汇总应含失败路由: %s", st.Message)
	}
}

func TestApplySnapshotErrorIsolated(t *testing.T) {
	f := &fakeRunner{dumpErr: fmt.Errorf("ip 命令不存在")}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2"]}],
		"ip_forward":true,"routes":[{"dst":"10.9.0.0/24","via":"192.168.50.254"}]}`)

	st := Apply(context.Background(), cfg, f, testNow)
	if st.OK {
		t.Fatal("快照失败应整体不 ok")
	}
	if st.Bridges[0].State != StateError || !strings.Contains(st.Bridges[0].Message, "快照") {
		t.Fatalf("桥应记快照错误: %+v", st.Bridges)
	}
	// ip_forward 与 routes 不依赖快照，照常执行
	if st.IPForward != StateOK || st.Routes[0].State != StateOK {
		t.Fatalf("独立项不应受快照失败影响: %+v", st)
	}
}

func TestApplyMutationErrorAbortsBridge(t *testing.T) {
	f := &fakeRunner{
		dump: []byte(`[
			{"ifindex":2,"ifname":"eth2","flags":["UP"],"addr_info":[]},
			{"ifindex":3,"ifname":"eth3","flags":["UP"],"addr_info":[]}
		]`),
		failExec: map[string]string{"ip link set eth2 master": "operation not permitted"},
	}
	cfg := applyCfg(t, `{"bridges":[{"name":"br0","ports":["eth2","eth3"]}],"ip_forward":true}`)

	st := Apply(context.Background(), cfg, f, testNow)
	// 桥创建成功 → 挂 eth2 失败 → 放弃该桥其余变更（不挂 eth3、不 set up）；
	// 独立的 sysctl 照常执行
	wantExecs := []string{
		"ip link add br0 type bridge",
		"ip link set eth2 master br0",
		"sysctl -w net.ipv4.ip_forward=1",
	}
	if got := f.execLog(); !reflect.DeepEqual(got, wantExecs) {
		t.Fatalf("桥内首个变更失败应放弃该桥其余变更:\n got=%v\nwant=%v", got, wantExecs)
	}
	if st.Bridges[0].State != StateError || !strings.Contains(st.Bridges[0].Message, "operation not permitted") {
		t.Fatalf("桥应记 error 且含 stderr: %+v", st.Bridges)
	}
	if st.OK {
		t.Fatal("应整体不 ok")
	}
}
