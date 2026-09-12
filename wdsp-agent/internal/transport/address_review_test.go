// 代码审查回归测试（批次5-A）：
// MED-19 控制面地址非 https 拒绝（仅 loopback http 例外，防 Bearer credential
// 明文传输并固化进 agent.json）。
package transport

import (
	"strings"
	"testing"
)

func TestNewRejectsPlainHTTPNonLoopback(t *testing.T) {
	for _, bad := range []string{
		"http://192.168.1.10:8080",
		"http://10.0.0.5",
		"http://wdsp.internal.example.com",
		"http://0.0.0.0:8080",
	} {
		if _, err := New(bad, false, "test"); err == nil {
			t.Fatalf("非 loopback 的 http 地址应拒绝: %q", bad)
		} else if !strings.Contains(err.Error(), "https") {
			t.Fatalf("错误信息应指向 https 要求: %v", err)
		}
	}
}

func TestNewAllowsHTTPSAndLoopbackHTTP(t *testing.T) {
	for _, ok := range []string{
		"https://wdsp.example.com:8443",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"http://localhost:8080",
	} {
		c, err := New(ok, false, "test")
		if err != nil {
			t.Fatalf("%q 应允许: %v", ok, err)
		}
		if c == nil {
			t.Fatalf("%q 客户端为 nil", ok)
		}
	}
}
