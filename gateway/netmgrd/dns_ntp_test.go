package netmgrd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fakeSys 主机交互桩：映射到 sysTools，覆盖 DNS/NTP 落地全部分支。
type fakeSys struct {
	binaries   map[string]bool   // 可执行文件存在性
	activeUnit map[string]bool   // systemctl is-active 结果
	routeJSON  string            // ip -j route show default 输出
	writable   map[string]bool   // 路径可写性
	links      map[string]string // EvalSymlinks 结果（缺省返回自身）
	mounts     map[string]bool   // 挂载点判定
	runErr     map[string]string // 命令前缀 → 错误
	writeErr   map[string]string // 路径 → 错误
	mkdirErr   map[string]string // 路径 → 错误

	runs   []string          // 已执行命令记录
	writes map[string]string // 已写文件 path → content
	mkdirs []string          // 已建目录
}

func newFakeSys() *fakeSys {
	return &fakeSys{
		binaries: map[string]bool{}, activeUnit: map[string]bool{},
		writable: map[string]bool{}, links: map[string]string{},
		mounts: map[string]bool{}, runErr: map[string]string{},
		writeErr: map[string]string{}, mkdirErr: map[string]string{},
		writes: map[string]string{},
	}
}

func (f *fakeSys) tools() sysTools {
	return sysTools{
		lookPath: func(name string) bool { return f.binaries[name] },
		run: func(_ context.Context, name string, args ...string) (string, error) {
			cmd := name + " " + strings.Join(args, " ")
			f.runs = append(f.runs, cmd)
			for prefix, msg := range f.runErr {
				if strings.HasPrefix(cmd, prefix) {
					return "", fmt.Errorf("%s", msg)
				}
			}
			if name == "systemctl" && len(args) >= 2 && args[0] == "is-active" {
				if f.activeUnit[args[1]] {
					return "active\n", nil
				}
				return "inactive\n", fmt.Errorf("exit status 3")
			}
			if name == "ip" {
				return f.routeJSON, nil
			}
			return "", nil
		},
		writable: func(path string) bool { return f.writable[path] },
		resolveLink: func(path string) (string, error) {
			if target, ok := f.links[path]; ok {
				return target, nil
			}
			return path, nil
		},
		mountPoint: func(path string) bool { return f.mounts[path] },
		mkdirAll: func(path string, _ os.FileMode) error {
			if msg, ok := f.mkdirErr[path]; ok {
				return fmt.Errorf("%s", msg)
			}
			f.mkdirs = append(f.mkdirs, path)
			return nil
		},
		writeAtomic: func(path string, data []byte, _ os.FileMode) error {
			if msg, ok := f.writeErr[path]; ok {
				return fmt.Errorf("%s", msg)
			}
			f.writes[path] = string(data)
			return nil
		},
	}
}

// withHostTools 替换包级 hostTools 并在用例结束恢复（包内测试不并行）。
func withHostTools(t *testing.T, f *fakeSys) {
	t.Helper()
	orig := hostTools
	hostTools = f.tools()
	t.Cleanup(func() { hostTools = orig })
}

func (f *fakeSys) ranCmd(prefix string) bool {
	for _, cmd := range f.runs {
		if strings.HasPrefix(cmd, prefix) {
			return true
		}
	}
	return false
}

// ---- 契约校验（config normalize）----

func TestNormalizeServersValid(t *testing.T) {
	cfg := applyCfg(t, `{"dns_servers":["223.5.5.5"," dns.example.com ","223.5.5.5"],
		"ntp_servers":["ntp.aliyun.com","2001:db8::1"]}`)
	if len(cfg.DNSServers) != 2 || cfg.DNSServers[0] != "223.5.5.5" || cfg.DNSServers[1] != "dns.example.com" {
		t.Fatalf("dns_servers 应去空白去重保序: %v", cfg.DNSServers)
	}
	if len(cfg.NTPServers) != 2 || cfg.NTPServers[1] != "2001:db8::1" {
		t.Fatalf("ntp_servers 应支持主机名与 IPv6: %v", cfg.NTPServers)
	}
}

func TestNormalizeServersRejectInvalid(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{"dns 超上限", `{"dns_servers":["1.1.1.1","2.2.2.2","3.3.3.3","4.4.4.4","5.5.5.5"]}`},
		{"ntp 超上限", `{"ntp_servers":["a","b","c","d","e"]}`},
		{"dns 非法项", `{"dns_servers":["10.0.0.1","bad;rm"]}`},
		{"ntp 以横杠开头", `{"ntp_servers":["-evil.example.com"]}`},
		{"dns 空串", `{"dns_servers":["  "]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := LoadConfig(writeOnly(t, tc.content)); err == nil {
				t.Fatalf("应整份拒绝: %s", tc.content)
			}
		})
	}
}

func TestNormalizeServersNilStaysNil(t *testing.T) {
	cfg := applyCfg(t, `{"ip_forward":false}`)
	if cfg.DNSServers != nil || cfg.NTPServers != nil {
		t.Fatalf("未下发字段应保持 nil（不触碰语义）: %v %v", cfg.DNSServers, cfg.NTPServers)
	}
}

func TestFingerprintCoversDNSNTP(t *testing.T) {
	base := applyCfg(t, `{"ip_forward":true,"updated_at":"t1"}`)
	withDNS := applyCfg(t, `{"ip_forward":true,"dns_servers":["223.5.5.5"],"updated_at":"t1"}`)
	if base.fingerprint() == withDNS.fingerprint() {
		t.Fatal("dns_servers 变化应改变指纹（触发重新执行）")
	}
}

// ---- DNS 落地 ----

func TestApplyDNSResolvectlPath(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true
	f.binaries["resolvectl"] = true
	f.activeUnit["systemd-resolved"] = true
	f.routeJSON = `[{"dst":"default","gateway":"192.168.50.1","dev":"eth0"}]`
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5","223.6.6.6"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.DNS == nil || st.DNS.State != StateApplied {
		t.Fatalf("resolvectl 路径应 APPLIED: %+v", st)
	}
	if !f.ranCmd("resolvectl dns eth0 223.5.5.5 223.6.6.6") {
		t.Fatalf("应按默认路由接口下发: %v", f.runs)
	}
}

func TestApplyDNSResolvectlNoDefaultRoute(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true
	f.binaries["resolvectl"] = true
	f.activeUnit["systemd-resolved"] = true
	f.routeJSON = `[]`
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if st.OK || st.DNS == nil || st.DNS.State != StateFailed || !strings.Contains(st.DNS.Message, "默认路由") {
		t.Fatalf("无默认路由应 FAILED: %+v", st)
	}
}

func TestApplyDNSResolvConfRewrite(t *testing.T) {
	f := newFakeSys() // 无 systemctl → 走 resolv.conf 路径
	f.writable["/etc/resolv.conf"] = true
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5","8.8.8.8"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.DNS == nil || st.DNS.State != StateApplied {
		t.Fatalf("resolv.conf 路径应 APPLIED: %+v", st)
	}
	content := f.writes["/etc/resolv.conf"]
	if !strings.Contains(content, "nameserver 223.5.5.5\nnameserver 8.8.8.8") {
		t.Fatalf("应原子重写 nameserver 行: %q", content)
	}
}

func TestApplyDNSStubSymlinkUnsupported(t *testing.T) {
	f := newFakeSys()
	f.links["/etc/resolv.conf"] = "/run/systemd/resolve/stub-resolv.conf"
	f.writable["/etc/resolv.conf"] = true // 可写也不应改写 stub
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.DNS == nil || st.DNS.State != StateUnsupported {
		t.Fatalf("stub 符号链接且 resolved 未活跃应 UNSUPPORTED 且不算失败: %+v", st)
	}
	if len(f.writes) != 0 {
		t.Fatalf("不应改写 stub 文件: %v", f.writes)
	}
}

func TestApplyDNSContainerUnsupported(t *testing.T) {
	// 容器环境：无 systemctl、resolv.conf 为运行时托管挂载 → UNSUPPORTED（预期行为）
	f := newFakeSys()
	f.writable["/etc/resolv.conf"] = true // 文件本身可写，但属独立挂载
	f.mounts["/etc/resolv.conf"] = true
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.DNS.State != StateUnsupported {
		t.Fatalf("托管挂载应 UNSUPPORTED: %+v", st)
	}

	f2 := newFakeSys() // resolv.conf 只读
	withHostTools(t, f2)
	st = Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)
	if !st.OK || st.DNS.State != StateUnsupported {
		t.Fatalf("只读 resolv.conf 应 UNSUPPORTED: %+v", st)
	}
}

func TestApplyDNSWriteFailureMarksFailed(t *testing.T) {
	f := newFakeSys()
	f.writable["/etc/resolv.conf"] = true
	f.writeErr["/etc/resolv.conf"] = "disk full"
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if st.OK || st.DNS.State != StateFailed || !strings.Contains(st.Message, "dns:") {
		t.Fatalf("写失败应 FAILED 且计入整体失败（触发周期重试）: %+v", st)
	}
}

// ---- NTP 落地 ----

func TestApplyNTPTimesyncdPath(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true
	f.activeUnit["systemd-timesyncd"] = true
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ntp_servers":["ntp.aliyun.com","2001:db8::1"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.NTP == nil || st.NTP.State != StateApplied {
		t.Fatalf("timesyncd 路径应 APPLIED: %+v", st)
	}
	conf := f.writes["/etc/systemd/timesyncd.conf.d/99-jiuzhang.conf"]
	if conf != "[Time]\nNTP=ntp.aliyun.com 2001:db8::1\n" {
		t.Fatalf("timesyncd drop-in 内容错误: %q", conf)
	}
	if !f.ranCmd("systemctl restart systemd-timesyncd") {
		t.Fatalf("应重启 systemd-timesyncd: %v", f.runs)
	}
}

func TestApplyNTPChronydPath(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true // timesyncd 未活跃
	f.binaries["chronyd"] = true
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ntp_servers":["ntp1.example.com","ntp2.example.com"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.NTP == nil || st.NTP.State != StateApplied {
		t.Fatalf("chronyd 路径应 APPLIED: %+v", st)
	}
	conf := f.writes["/etc/chrony/conf.d/99-jiuzhang.conf"]
	if !strings.Contains(conf, "server ntp1.example.com iburst\nserver ntp2.example.com iburst") {
		t.Fatalf("chrony drop-in 内容错误: %q", conf)
	}
	if !f.ranCmd("systemctl restart chronyd") {
		t.Fatalf("应重启 chronyd: %v", f.runs)
	}
}

func TestApplyNTPChronydWithoutSystemctl(t *testing.T) {
	f := newFakeSys() // 无 systemctl
	f.binaries["chronyd"] = true
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ntp_servers":["ntp1.example.com"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.NTP.State != StateApplied || !strings.Contains(st.NTP.Message, "手动重载") {
		t.Fatalf("无 systemctl 应 APPLIED 并注明手动重载: %+v", st.NTP)
	}
}

func TestApplyNTPUnsupported(t *testing.T) {
	f := newFakeSys() // 无 systemctl、无 chronyd（容器环境预期路径）
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ntp_servers":["ntp1.example.com"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if !st.OK || st.NTP == nil || st.NTP.State != StateUnsupported {
		t.Fatalf("无落地路径应 UNSUPPORTED 且不算失败: %+v", st)
	}
}

func TestApplyNTPRestartFailureMarksFailed(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true
	f.activeUnit["systemd-timesyncd"] = true
	f.runErr["systemctl restart"] = "Unit failed"
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ntp_servers":["ntp1.example.com"]}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if st.OK || st.NTP.State != StateFailed || !strings.Contains(st.Message, "ntp:") {
		t.Fatalf("restart 失败应 FAILED 且计入整体失败: %+v", st)
	}
}

func TestApplyDryRunDoesNotTouchDNSNTP(t *testing.T) {
	f := newFakeSys()
	f.binaries["systemctl"] = true
	f.activeUnit["systemd-resolved"] = true
	f.activeUnit["systemd-timesyncd"] = true
	withHostTools(t, f)

	dry := &DryRunner{Real: &fakeRunner{dump: []byte(`[]`)}}
	st := Apply(context.Background(), applyCfg(t,
		`{"dns_servers":["223.5.5.5"],"ntp_servers":["ntp1.example.com"]}`), dry, testNow)

	if st.DNS == nil || st.NTP == nil || !strings.Contains(st.DNS.Message, "dry-run") ||
		!strings.Contains(st.NTP.Message, "dry-run") {
		t.Fatalf("dry-run 应只标注不落地: %+v", st)
	}
	if len(f.runs) != 0 || len(f.writes) != 0 {
		t.Fatalf("dry-run 绝不得变更主机: runs=%v writes=%v", f.runs, f.writes)
	}
}

func TestApplyWithoutDNSNTPKeepsStatusClean(t *testing.T) {
	f := newFakeSys()
	withHostTools(t, f)

	st := Apply(context.Background(), applyCfg(t,
		`{"ip_forward":false}`), &fakeRunner{dump: []byte(`[]`)}, testNow)

	if st.DNS != nil || st.NTP != nil {
		t.Fatalf("未下发字段不应产生 dns_status/ntp_status: %+v", st)
	}
	if len(f.runs) != 0 || len(f.writes) != 0 {
		t.Fatalf("未下发字段不应有任何主机交互: runs=%v writes=%v", f.runs, f.writes)
	}
}
