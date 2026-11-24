package netmgrd

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// iptablesFakeRunner 模拟 iptables 链存在性与跳转规则查询（-L / -C）及变更记录。
func newIptablesFakeRunner() (*fakeRunner, map[string]bool) {
	chains := map[string]bool{}
	jumps := map[string]bool{}
	f := &fakeRunner{
		procSys: map[string]string{"net.bridge.bridge-nf-call-iptables": "1"},
	}
	f.queryHook = func(name string, args ...string) ([]byte, error) {
		if name == "ip" {
			return f.dump, f.dumpErr
		}
		if name == "iptables" && len(args) >= 7 {
			// iptables -w 5 -t <table> -L <chain> -n
			if args[4] == "-L" {
				key := args[3] + "/" + args[5]
				if chains[key] {
					return []byte("Chain " + args[5]), nil
				}
				return nil, errors.New("No chain/target/match by that name")
			}
			// iptables -w 5 -t <table> -C <parent> -j <chain>
			if args[4] == "-C" && len(args) >= 8 {
				key := args[3] + "/" + args[5] + "->" + args[7]
				if jumps[key] {
					return nil, nil
				}
				return nil, errors.New("Bad rule")
			}
		}
		return nil, errors.New("unexpected query")
	}
	return f, chains
}

func TestTransparentInstallIdempotentAndExactRules(t *testing.T) {
	dir := t.TempDir()
	tpCfg := filepath.Join(dir, "tproxyd.json")
	stPath := filepath.Join(dir, "network-status.json")
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[443,80,80]}`)

	f, _ := newIptablesFakeRunner()
	sw := NewStatusWriter(stPath)
	tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, sw)
	tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true, Listen: "0.0.0.0:15000"}, nil
	}
	tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
	tm.SetBridges(context.Background(), []string{"br0"})

	tm.cycle(context.Background())

	execs := f.execLog()
	// 必须包含 3 条专用链的 -w 5 规则（FWD/IN/PRE），且不含 shell 语法
	wantContains := []string{
		"iptables -w 5 -t filter -N JIUZHANG_TPROXY_FWD",
		"iptables -w 5 -t filter -I FORWARD 1 -j JIUZHANG_TPROXY_FWD",
		"iptables -w 5 -t filter -A JIUZHANG_TPROXY_FWD -i br0 -o br0 -j ACCEPT",
		"iptables -w 5 -t filter -N JIUZHANG_TPROXY_IN",
		"iptables -w 5 -t filter -I INPUT 1 -j JIUZHANG_TPROXY_IN",
		"iptables -w 5 -t filter -A JIUZHANG_TPROXY_IN -i br0 -p tcp --dport 15000 -m conntrack --ctstate DNAT -j ACCEPT",
		"iptables -w 5 -t nat -N JIUZHANG_TPROXY_PRE",
		"iptables -w 5 -t nat -I PREROUTING 1 -j JIUZHANG_TPROXY_PRE",
		"iptables -w 5 -t nat -A JIUZHANG_TPROXY_PRE -i br0 -m addrtype ! --dst-type LOCAL -p tcp --dport 80 -j REDIRECT --to-ports 15000",
		"iptables -w 5 -t nat -A JIUZHANG_TPROXY_PRE -i br0 -m addrtype ! --dst-type LOCAL -p tcp --dport 443 -j REDIRECT --to-ports 15000",
	}
	joined := strings.Join(execs, "\n")
	for _, want := range wantContains {
		if !strings.Contains(joined, want) {
			t.Errorf("缺少预期 iptables 命令 %q\n实际执行:\n%s", want, joined)
		}
	}
	// bridge-nf-call-iptables 已是 1，不应调用 sysctl -w
	if strings.Contains(joined, "sysctl -w") {
		t.Fatalf("bridge-nf-call-iptables 已为 1 时不应调用 sysctl -w:\n%s", joined)
	}

	st, ok := readStatus(t, stPath)
	if !ok || st.Transparent == nil {
		t.Fatalf("应回写 transparent 状态: %+v", st)
	}
	if st.Transparent.State != TransparentStateActive || !st.Transparent.RedirectActive ||
		!st.Transparent.TproxydHealthy || !st.Transparent.CaddyHealthy || !st.Transparent.BridgeNFReady {
		t.Fatalf("transparent 状态应为 ACTIVE: %+v", st.Transparent)
	}

	// 幂等：第二轮无变化不重复执行 iptables
	countBefore := len(f.execLog())
	tm.cycle(context.Background())
	if len(f.execLog()) != countBefore {
		t.Fatalf("稳态重复 cycle 不应再执行 iptables: before=%d after=%d", countBefore, len(f.execLog()))
	}
}

func TestTransparentFailOpenWatchdogTwoConsecutiveFailuresAndRecovery(t *testing.T) {
	dir := t.TempDir()
	tpCfg := filepath.Join(dir, "tproxyd.json")
	stPath := filepath.Join(dir, "network-status.json")
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)

	f, _ := newIptablesFakeRunner()
	sw := NewStatusWriter(stPath)
	tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, sw)
	tproxydUp := true
	tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		if !tproxydUp {
			return tproxydHealthResp{}, errors.New("connection refused")
		}
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true, Listen: "0.0.0.0:15000"}, nil
	}
	tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
	tm.SetBridges(context.Background(), []string{"br0"})

	// 初始激活
	tm.cycle(context.Background())
	st, _ := readStatus(t, stPath)
	if st.Transparent.State != TransparentStateActive || !st.Transparent.RedirectActive {
		t.Fatalf("初始应 ACTIVE: %+v", st.Transparent)
	}

	// 连续第 1 次探活失败：记告警但暂不冲刷 PRE（避免瞬态抖动）
	tproxydUp = false
	beforeFail1 := len(f.execLog())
	tm.cycle(context.Background())
	if len(f.execLog()) != beforeFail1 {
		t.Fatalf("第 1 次失败不应提前冲刷规则: %v", f.execLog()[beforeFail1:])
	}
	st, _ = readStatus(t, stPath)
	if !st.Transparent.RedirectActive || st.Transparent.State != TransparentStateDegraded {
		t.Fatalf("第 1 次失败应保留 RedirectActive 并报 DEGRADED: %+v", st.Transparent)
	}

	// 连续第 2 次探活失败：立即冲刷 nat/JIUZHANG_TPROXY_PRE 与 filter/JIUZHANG_TPROXY_IN，保留 FORWARD！
	tm.cycle(context.Background())
	fail2Execs := strings.Join(f.execLog()[beforeFail1:], "\n")
	if !strings.Contains(fail2Execs, "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE") {
		t.Fatalf("连续 2 次失败必须立即冲刷 JIUZHANG_TPROXY_PRE:\n%s", fail2Execs)
	}
	if strings.Contains(fail2Execs, "-F JIUZHANG_TPROXY_FWD") {
		t.Fatalf("fail-open 必须保留 JIUZHANG_TPROXY_FWD 以保障 L2 透传:\n%s", fail2Execs)
	}
	st, _ = readStatus(t, stPath)
	if st.Transparent.State != TransparentStateDegraded || st.Transparent.RedirectActive {
		t.Fatalf("fail-open 后应为 DEGRADED 且 redirect_active=false: %+v", st.Transparent)
	}

	// 数据面恢复：自动重新安装 REDIRECT 规则并恢复 ACTIVE
	tproxydUp = true
	beforeRecover := len(f.execLog())
	tm.cycle(context.Background())
	recoverExecs := strings.Join(f.execLog()[beforeRecover:], "\n")
	if !strings.Contains(recoverExecs, "-A JIUZHANG_TPROXY_PRE") {
		t.Fatalf("探活恢复后应重建 JIUZHANG_TPROXY_PRE:\n%s", recoverExecs)
	}
	st, _ = readStatus(t, stPath)
	if st.Transparent.State != TransparentStateActive || !st.Transparent.RedirectActive {
		t.Fatalf("恢复后应回到 ACTIVE: %+v", st.Transparent)
	}

	// 退出 Close()：立即冲刷 PRE（保留 FWD）
	beforeClose := len(f.execLog())
	tm.Close()
	closeExecs := strings.Join(f.execLog()[beforeClose:], "\n")
	if !strings.Contains(closeExecs, "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE") {
		t.Fatalf("Close 退出时必须立即冲刷 JIUZHANG_TPROXY_PRE:\n%s", closeExecs)
	}
	if strings.Contains(closeExecs, "-F JIUZHANG_TPROXY_FWD") {
		t.Fatalf("Close 退出时必须保留 JIUZHANG_TPROXY_FWD 以 fail-open:\n%s", closeExecs)
	}
}

func TestTransparentBridgeNFCallIptablesDegradedWithoutCrash(t *testing.T) {
	dir := t.TempDir()
	tpCfg := filepath.Join(dir, "tproxyd.json")
	stPath := filepath.Join(dir, "network-status.json")
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)

	f, _ := newIptablesFakeRunner()
	f.procSys = map[string]string{"net.bridge.bridge-nf-call-iptables": "0"}
	f.failExec = map[string]string{"sysctl -w": "Read-only file system"}

	sw := NewStatusWriter(stPath)
	tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, sw)
	tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true}, nil
	}
	tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
	tm.SetBridges(context.Background(), []string{"br0"})

	tm.cycle(context.Background())

	st, ok := readStatus(t, stPath)
	if !ok || st.Transparent == nil {
		t.Fatal("应回写降级透明状态")
	}
	if st.Transparent.State != TransparentStateDegraded || st.Transparent.RedirectActive || st.Transparent.BridgeNFReady {
		t.Fatalf("bridge-nf-call-iptables 不可用应降级 DEGRADED: %+v", st.Transparent)
	}
	if strings.Contains(strings.Join(f.execLog(), "\n"), "-A JIUZHANG_TPROXY_PRE") {
		t.Fatalf("bridge-nf-call-iptables 未就绪时不应安装 REDIRECT 规则: %v", f.execLog())
	}
}

func TestTransparentImmediateFlushOnDisableAndBridgeRemoval(t *testing.T) {
	dir := t.TempDir()
	tpCfg := filepath.Join(dir, "tproxyd.json")
	stPath := filepath.Join(dir, "network-status.json")
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)

	f, _ := newIptablesFakeRunner()
	sw := NewStatusWriter(stPath)
	tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, sw)
	tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true}, nil
	}
	tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
	tm.SetBridges(context.Background(), []string{"br0"})
	tm.cycle(context.Background())

	// 1. enabled=false → 立即冲刷 PRE/IN，保留 FWD
	beforeDisable := len(f.execLog())
	writeNetmgrCfg(t, tpCfg, `{"enabled":false,"listen":"0.0.0.0:15000","ports":[80]}`)
	tm.cycle(context.Background())
	disableExecs := strings.Join(f.execLog()[beforeDisable:], "\n")
	if !strings.Contains(disableExecs, "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE") {
		t.Fatalf("enabled=false 应立即冲刷 PRE:\n%s", disableExecs)
	}
	if strings.Contains(disableExecs, "-F JIUZHANG_TPROXY_FWD") {
		t.Fatalf("桥仍存在时 disabled 应保留 FWD:\n%s", disableExecs)
	}

	// 重新激活后再移除网桥 → 立即同步冲刷 PRE/IN/FWD
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)
	tm.cycle(context.Background())
	beforeRemove := len(f.execLog())
	tm.SetBridges(context.Background(), nil)
	rmExecs := strings.Join(f.execLog()[beforeRemove:], "\n")
	for _, want := range []string{
		"iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE",
		"iptables -w 5 -t filter -F JIUZHANG_TPROXY_IN",
		"iptables -w 5 -t filter -F JIUZHANG_TPROXY_FWD",
	} {
		if !strings.Contains(rmExecs, want) {
			t.Fatalf("全部网桥移除应冲刷 %q:\n%s", want, rmExecs)
		}
	}
}

func TestTransparentRealProbesHTTPAndUnixSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tproxydHealthResp{
			OK: true, Enabled: true, Listening: true, Listen: "0.0.0.0:15000",
		})
	}))
	defer srv.Close()

	sockDir, err := os.MkdirTemp("", "nm-caddy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	sockPath := filepath.Join(sockDir, "admin.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	tm := NewTransparentManager("", srv.URL, sockPath, &fakeRunner{}, nil)
	ok, err := tm.checkTproxyd(context.Background())
	if err != nil || !ok {
		t.Fatalf("defaultProbeTproxyd failed: ok=%v err=%v", ok, err)
	}
	if err := tm.checkCaddy(context.Background()); err != nil {
		t.Fatalf("defaultProbeCaddy failed: %v", err)
	}
}

// Blocking #3-1: 部分 REDIRECT 规则写入失败（如端口 80 成功、端口 443 失败）时，必须回滚冲刷 PRE 与 IN 链。
func TestTransparentPartialRuleInstallRollsBackAndFlushes(t *testing.T) {
	dir := t.TempDir()
	tpCfg := filepath.Join(dir, "tproxyd.json")
	stPath := filepath.Join(dir, "network-status.json")
	writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80,443]}`)

	f, _ := newIptablesFakeRunner()
	// 放行第一条 --dport 80，注入第二条 --dport 443 写入失败
	f.failExec = map[string]string{
		"iptables -w 5 -t nat -A JIUZHANG_TPROXY_PRE -i br0 -m addrtype ! --dst-type LOCAL -p tcp --dport 443": "iptables: Target problem",
	}
	sw := NewStatusWriter(stPath)
	tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, sw)
	tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
		return tproxydHealthResp{OK: true, Enabled: true, Listening: true, Listen: "0.0.0.0:15000"}, nil
	}
	tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
	tm.SetBridges(context.Background(), []string{"br0"})

	tm.cycle(context.Background())

	execs := f.execLog()
	failIdx, flushPreIdx, flushInIdx := -1, -1, -1
	for i, cmd := range execs {
		if strings.Contains(cmd, "--dport 443") {
			failIdx = i
		}
		if failIdx >= 0 && i > failIdx {
			if cmd == "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE" {
				flushPreIdx = i
			}
			if cmd == "iptables -w 5 -t filter -F JIUZHANG_TPROXY_IN" {
				flushInIdx = i
			}
		}
	}
	if failIdx == -1 || flushPreIdx == -1 || flushInIdx == -1 {
		t.Fatalf("部分规则失败后必须回滚冲刷 PRE 与 IN: failIdx=%d flushPreIdx=%d flushInIdx=%d\ncmds:\n%s",
			failIdx, flushPreIdx, flushInIdx, strings.Join(execs, "\n"))
	}
	st, ok := readStatus(t, stPath)
	if !ok || st.Transparent == nil || st.Transparent.State != TransparentStateDegraded || st.Transparent.RedirectActive {
		t.Fatalf("部分失败回滚后应为 DEGRADED 且 redirect_active=false: %+v", st.Transparent)
	}
}

// Blocking #3-2: SIGKILL 崩溃重启后内核存在遗留活动规则时，新进程必须通过启动只读探测识别并可靠 fail-open 冲刷。
func TestTransparentPostCrashRestartFlushesOrphanedKernelRules(t *testing.T) {
	orphanPreOut := []byte("Chain JIUZHANG_TPROXY_PRE (1 references)\ntarget prot opt source destination\nREDIRECT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:80 redir ports 15000\n")
	orphanInOut := []byte("Chain JIUZHANG_TPROXY_IN (1 references)\ntarget prot opt source destination\nACCEPT tcp -- 0.0.0.0/0 0.0.0.0/0 tcp dpt:15000 ctstate DNAT\n")
	orphanFwdOut := []byte("Chain JIUZHANG_TPROXY_FWD (1 references)\ntarget prot opt source destination\nACCEPT all -- 0.0.0.0/0 0.0.0.0/0\n")

	newOrphanRunner := func() *fakeRunner {
		f := &fakeRunner{
			procSys: map[string]string{"net.bridge.bridge-nf-call-iptables": "1"},
		}
		f.queryHook = func(name string, args ...string) ([]byte, error) {
			if name == "iptables" && len(args) >= 7 && args[4] == "-L" {
				switch args[3] + "/" + args[5] {
				case "nat/" + tproxyChainPre:
					return orphanPreOut, nil
				case "filter/" + tproxyChainIn:
					return orphanInOut, nil
				case "filter/" + tproxyChainFwd:
					return orphanFwdOut, nil
				}
			}
			if name == "iptables" && len(args) >= 8 && args[4] == "-C" {
				return nil, nil
			}
			return nil, errors.New("unexpected query")
		}
		return f
	}

	t.Run("重启时tproxyd宕机首轮立刻冲刷遗留PRE并保留FWD", func(t *testing.T) {
		dir := t.TempDir()
		tpCfg := filepath.Join(dir, "tproxyd.json")
		stPath := filepath.Join(dir, "network-status.json")
		writeNetmgrCfg(t, tpCfg, `{"enabled":true,"listen":"0.0.0.0:15000","ports":[80]}`)

		f := newOrphanRunner()
		tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, NewStatusWriter(stPath))
		tm.probeTproxyd = func(ctx context.Context) (tproxydHealthResp, error) {
			return tproxydHealthResp{}, errors.New("connection refused")
		}
		tm.probeCaddy = func(ctx context.Context, _ ...string) error { return nil }
		tm.SetBridges(context.Background(), []string{"br0"})

		// 首轮 cycle（不等 2 次失败）必须立刻冲刷崩溃遗留的 PRE 与 IN，同时保留 FWD
		tm.cycle(context.Background())
		joined := strings.Join(f.execLog(), "\n")
		if !strings.Contains(joined, "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE") ||
			!strings.Contains(joined, "iptables -w 5 -t filter -F JIUZHANG_TPROXY_IN") {
			t.Fatalf("崩溃重启且数据面不可用时首轮必须立刻冲刷遗留 PRE/IN:\n%s", joined)
		}
		st, _ := readStatus(t, stPath)
		if st.Transparent == nil || st.Transparent.RedirectActive || st.Transparent.State != TransparentStateDegraded {
			t.Fatalf("应报 DEGRADED 且 redirect_active=false: %+v", st.Transparent)
		}
	})

	t.Run("重启时tproxyd.json已disabled立刻冲刷遗留PRE并保留FWD", func(t *testing.T) {
		dir := t.TempDir()
		tpCfg := filepath.Join(dir, "tproxyd.json")
		stPath := filepath.Join(dir, "network-status.json")
		writeNetmgrCfg(t, tpCfg, `{"enabled":false,"listen":"0.0.0.0:15000","ports":[80]}`)

		f := newOrphanRunner()
		tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, NewStatusWriter(stPath))
		tm.SetBridges(context.Background(), []string{"br0"})

		tm.cycle(context.Background())
		joined := strings.Join(f.execLog(), "\n")
		if !strings.Contains(joined, "iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE") ||
			!strings.Contains(joined, "iptables -w 5 -t filter -F JIUZHANG_TPROXY_IN") {
			t.Fatalf("enabled=false 重启必须冲刷遗留 PRE/IN:\n%s", joined)
		}
		st, _ := readStatus(t, stPath)
		if st.Transparent == nil || st.Transparent.State != TransparentStateInactive || st.Transparent.RedirectActive {
			t.Fatalf("应报 INACTIVE 且 redirect_active=false: %+v", st.Transparent)
		}
	})

	t.Run("重启时tproxyd.json已删除且无托管桥立刻清空遗留PRE/IN/FWD", func(t *testing.T) {
		dir := t.TempDir()
		tpCfg := filepath.Join(dir, "tproxyd.json") // 不创建文件
		stPath := filepath.Join(dir, "network-status.json")

		f := newOrphanRunner()
		tm := NewTransparentManager(tpCfg, DefaultTproxydHealthURL, DefaultCaddyAdminSocket, f, NewStatusWriter(stPath))

		tm.cycle(context.Background())
		joined := strings.Join(f.execLog(), "\n")
		for _, want := range []string{
			"iptables -w 5 -t nat -F JIUZHANG_TPROXY_PRE",
			"iptables -w 5 -t filter -F JIUZHANG_TPROXY_IN",
			"iptables -w 5 -t filter -F JIUZHANG_TPROXY_FWD",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("文件已删且无桥时必须清空遗留链 %q:\n%s", want, joined)
			}
		}
	})
}
