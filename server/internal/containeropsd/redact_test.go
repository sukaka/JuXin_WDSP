// redact_test.go 日志脱敏与控制字符剥离测试。
package containeropsd

import (
	"strings"
	"testing"
)

func TestRedactLineSensitiveValues(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantSub string   // 必须出现的子串
		leaks   []string // 绝不能出现的子串
	}{
		{"key=value", `password=Sup3rSecret!`, "password=" + mask, []string{"Sup3rSecret"}},
		{"key: value", `token: abcdef123456`, "token: " + mask, []string{"abcdef123456"}},
		{"JSON 双引号", `{"password": "hunter2", "ok": true}`, `"password": ` + mask, []string{"hunter2"}},
		{"JSON 单引号", `{'api_key': 'AKIA1234567890'}`, "api_key", []string{"AKIA1234567890"}},
		{"Authorization 头", `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig`, "Authorization: " + mask, []string{"eyJhbGciOiJIUzI1NiJ9", "payload"}},
		{"Cookie 头", `Cookie: session=xyz789; theme=dark`, "Cookie: " + mask, []string{"xyz789"}},
		{"Set-Cookie 头", `Set-Cookie: sid=abc123; HttpOnly`, "Set-Cookie: " + mask, []string{"abc123"}},
		{"裸 Bearer", `auth scheme bearer  zzzaaa111 signed`, "bearer", []string{"zzzaaa111"}},
		{"secret", `secret=topsecret`, "secret=" + mask, []string{"topsecret"}},
		{"private_key", `private_key=-----BEGIN`, "private_key=" + mask, []string{"BEGIN"}},
	}
	for _, tc := range cases {
		got := redactLine(tc.in)
		if !strings.Contains(got, tc.wantSub) {
			t.Errorf("%s: 结果 %q 缺少 %q", tc.name, got, tc.wantSub)
		}
		for _, leak := range tc.leaks {
			if strings.Contains(got, leak) {
				t.Errorf("%s: 结果 %q 泄露了 %q", tc.name, got, leak)
			}
		}
	}
}

func TestRedactLineKeepsBenignText(t *testing.T) {
	in := `2026-10-19T01:02:03Z request completed status=200 duration=3ms`
	if got := redactLine(in); got != in {
		t.Fatalf("普通日志不应被改写: %q → %q", in, got)
	}
}

func TestStripControls(t *testing.T) {
	in := "hello\rworld\x00\x1b[31mred\x07\ttab\n"
	got := stripControls(in)
	if strings.ContainsAny(got, "\r\x00\x1b\x07") {
		t.Fatalf("控制字符未剥离: %q", got)
	}
	if !strings.Contains(got, "\t") {
		t.Fatalf("制表符应保留: %q", got)
	}
	if !strings.Contains(got, "helloworld") || !strings.Contains(got, "red") {
		t.Fatalf("可见内容被误删: %q", got)
	}
}
