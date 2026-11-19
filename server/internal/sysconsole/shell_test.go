// shell_test.go 受限命令 REPL 单测：白名单分发、参数校验、审计记录、passwd 流程。
package sysconsole

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner 记录调用并返回固定输出。
type fakeRunner struct {
	calls [][]string
	out   string
	err   error
}

func (f *fakeRunner) run(name string, args ...string) (string, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	return f.out, f.err
}

func newShell(t *testing.T, run Runner, p Prompter) *Shell {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{Username: "opsadmin", PasswordHash: "$2a$10$placeholder"}
	return &Shell{
		Cfg:     cfg,
		CfgPath: filepath.Join(dir, "console.yaml"),
		Audit:   NewAuditLogger("", filepath.Join(dir, "audit.log")),
		Run:     run,
		Prompt:  p,
	}
}

func TestHelpAndQuit(t *testing.T) {
	s := newShell(t, nil, nil)
	out, err := s.Execute("opsadmin", "help")
	if err != nil || !strings.Contains(out, "set mgmt-ip") {
		t.Errorf("help = %q, %v", out, err)
	}
	if _, err := s.Execute("opsadmin", "exit"); !errors.Is(err, ErrQuit) {
		t.Errorf("exit err = %v, want ErrQuit", err)
	}
	if _, err := s.Execute("opsadmin", "  "); err != nil {
		t.Errorf("空行 err = %v", err)
	}
}

func TestUnknownCommandRejected(t *testing.T) {
	s := newShell(t, nil, nil)
	if _, err := s.Execute("opsadmin", "rm -rf /"); err == nil || !strings.Contains(err.Error(), "未知命令") {
		t.Errorf("任意命令必须拒绝，got %v", err)
	}
	if _, err := s.Execute("opsadmin", "show routes"); err == nil {
		t.Errorf("未知 show 子命令必须拒绝")
	}
}

func TestSetMgmtIPValidation(t *testing.T) {
	f := &fakeRunner{out: "ok"}
	s := newShell(t, f.run, nil)

	// 合法：带网关
	if _, err := s.Execute("opsadmin", "set mgmt-ip eth0 192.168.1.10/24 192.168.1.1"); err != nil {
		t.Fatalf("合法 mgmt-ip 被拒：%v", err)
	}
	want := []string{"sudo", "-n", NetHelperPath(), "mgmt-ip", "eth0", "192.168.1.10/24", "192.168.1.1"}
	got := f.calls[len(f.calls)-1]
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("helper 调用 = %v, want %v", got, want)
	}

	// 非法参数一律不触达 helper
	before := len(f.calls)
	for _, bad := range []string{
		"set mgmt-ip eth0 999.1.1.1/24",
		"set mgmt-ip eth0 192.168.1.10/33",
		"set mgmt-ip eth0;rm 192.168.1.10/24",
		"set mgmt-ip `id` 192.168.1.10/24",
		"set mgmt-ip eth0 192.168.1.10/24 not-an-ip",
		"set mgmt-ip eth0",
	} {
		if _, err := s.Execute("opsadmin", bad); err == nil {
			t.Errorf("%q 应被拒绝", bad)
		}
	}
	if len(f.calls) != before {
		t.Errorf("非法参数触达了 helper：%v", f.calls[before:])
	}
}

func TestSetRouteAndDNS(t *testing.T) {
	f := &fakeRunner{}
	s := newShell(t, f.run, nil)

	if _, err := s.Execute("opsadmin", "set route add 10.0.0.0/8 via 192.168.1.1 dev eth0"); err != nil {
		t.Fatalf("route add：%v", err)
	}
	if _, err := s.Execute("opsadmin", "set route del 10.0.0.0/8"); err != nil {
		t.Fatalf("route del：%v", err)
	}
	if _, err := s.Execute("opsadmin", "set dns 223.5.5.5 8.8.8.8"); err != nil {
		t.Fatalf("dns：%v", err)
	}
	for _, bad := range []string{
		"set route add 10.0.0.0 via 192.168.1.1", // 缺前缀
		"set route add 10.0.0.0/8 through 192.168.1.1",
		"set route del 999.0.0.0/8",
		"set dns 300.0.0.1",
		"set dns fe80::1%eth0;id",
		"set dns",
	} {
		if _, err := s.Execute("opsadmin", bad); err == nil {
			t.Errorf("%q 应被拒绝", bad)
		}
	}
	if ValidHost("fe80::1%eth0;id") || ValidHost("fe80::1%eth0") {
		t.Error("ValidHost must reject IPv6 addresses with zone")
	}
	if _, err := ParseAddr("fe80::1%eth0"); err == nil {
		t.Error("ParseAddr must reject IPv6 addresses with zone")
	}
	// helper 失败要透传错误
	f.err = errors.New("sudo: a password is required")
	if _, err := s.Execute("opsadmin", "set dns 223.5.5.5"); err == nil || !strings.Contains(err.Error(), "网络变更失败") {
		t.Errorf("helper 失败未透传：%v", err)
	}
}

func TestPingValidation(t *testing.T) {
	f := &fakeRunner{}
	s := newShell(t, f.run, nil)
	if _, err := s.Execute("opsadmin", "ping 192.168.1.1"); err != nil {
		t.Fatalf("ping IP：%v", err)
	}
	if got := f.calls[0]; got[0] != "ping" || got[len(got)-1] != "192.168.1.1" {
		t.Errorf("ping 调用 = %v", got)
	}
	if _, err := s.Execute("opsadmin", "ping $(id)"); err == nil {
		t.Errorf("ping 注入应被拒绝")
	}
}

type fakePrompter struct{ pwds []string }

func (p *fakePrompter) PromptPassword(string) (string, error) {
	if len(p.pwds) == 0 {
		return "", errors.New("no more")
	}
	pw := p.pwds[0]
	p.pwds = p.pwds[1:]
	return pw, nil
}

func TestPasswdFlow(t *testing.T) {
	p := &fakePrompter{pwds: []string{"newpass123", "newpass123"}}
	s := newShell(t, nil, p)
	if _, err := s.Execute("opsadmin", "passwd"); err != nil {
		t.Fatalf("passwd：%v", err)
	}
	// 配置已写回且哈希可校验
	cfg, err := LoadConfig(s.CfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(cfg.PasswordHash, "newpass123") {
		t.Errorf("写回哈希无法校验新密码")
	}
	// 两次不一致 / 太短
	p.pwds = []string{"abcdefgh", "abcdefg1"}
	if _, err := s.Execute("opsadmin", "passwd"); err == nil {
		t.Errorf("不一致应失败")
	}
	p.pwds = []string{"short", "short"}
	if _, err := s.Execute("opsadmin", "passwd"); err == nil {
		t.Errorf("过短应失败")
	}
	// 无交互能力时明确报错
	s2 := newShell(t, nil, nil)
	if _, err := s2.Execute("opsadmin", "passwd"); err == nil {
		t.Errorf("无 Prompter 应失败")
	}
}

func TestAuditWritten(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	s := &Shell{
		Cfg:     &Config{Username: "opsadmin", PasswordHash: "x"},
		CfgPath: filepath.Join(dir, "c.yaml"),
		Audit:   NewAuditLogger("", logPath),
		Run:     (&fakeRunner{}).run,
	}
	_, _ = s.Execute("opsadmin", "help")
	_, _ = s.Execute("opsadmin", "bad-cmd")
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"success":true`) || !strings.Contains(string(raw), `"success":false`) {
		t.Errorf("审计应含成功与失败各一条：%s", raw)
	}
}

func TestValidateHelpers(t *testing.T) {
	if !ValidIfName("eth0") || !ValidIfName("enp3s0f0") || !ValidIfName("eth0.100") {
		t.Errorf("合法接口名被拒")
	}
	for _, bad := range []string{"0eth", "eth 0", "eth;0", strings.Repeat("a", 33), ""} {
		if ValidIfName(bad) {
			t.Errorf("非法接口名 %q 被放行", bad)
		}
	}
	if !ValidHost("example.com") || !ValidHost("8.8.8.8") || ValidHost("a;b") || ValidHost("-bad.com") {
		t.Errorf("ValidHost 判定异常")
	}
}
