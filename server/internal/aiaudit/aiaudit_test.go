package aiaudit

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// TestComputeHash 哈希链：确定性、长度、任一字段变化即变化。
func TestComputeHash(t *testing.T) {
	at := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	h1 := computeHash(at, "admin", "tool_call", "obj-1", "")
	h2 := computeHash(at, "admin", "tool_call", "obj-1", "")
	if h1 != h2 {
		t.Error("相同输入哈希应一致")
	}
	if len(h1) != 64 {
		t.Errorf("SHA-256 hex 长度 = %d, want 64", len(h1))
	}
	cases := []struct {
		name string
		at   time.Time
		user string
		act  string
		obj  string
		prev string
	}{
		{"前序哈希变化", at, "admin", "tool_call", "obj-1", "prev-hash"},
		{"用户名变化", at, "other", "tool_call", "obj-1", ""},
		{"动作变化", at, "admin", "model_call", "obj-1", ""},
		{"对象变化", at, "admin", "tool_call", "obj-2", ""},
		{"时间变化", at.Add(time.Second), "admin", "tool_call", "obj-1", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := computeHash(c.at, c.user, c.act, c.obj, c.prev); got == h1 {
				t.Error("字段变化应改变记录哈希（防篡改）")
			}
		})
	}
}

// TestMask 截断：短内容不变、超长按 rune 截断、多字节字符不破坏。
func TestMask(t *testing.T) {
	if got := mask("正常内容", 100); got != "正常内容" {
		t.Errorf("短内容不应变化: %q", got)
	}
	// 超长 ASCII 截断
	long := strings.Repeat("a", 600)
	got := mask(long, 500)
	if len([]rune(got)) != 503 || !strings.HasSuffix(got, "...") {
		t.Errorf("截断结果长度 = %d runes", len([]rune(got)))
	}
	// 中文多字节截断不产生非法 UTF-8
	cjk := strings.Repeat("安全事件", 200) // 800 runes
	got = mask(cjk, 100)
	if !utf8.ValidString(got) {
		t.Error("截断结果含非法 UTF-8")
	}
	if strings.ContainsRune(got, '\ufffd') {
		t.Error("截断破坏了多字节字符（含替换符）")
	}
	if len([]rune(got)) != 103 {
		t.Errorf("截断结果长度 = %d runes, want 103", len([]rune(got)))
	}
	// 字节数超限但 rune 数未超限 → 不截断
	if got := mask("你好", 5); got != "你好" {
		t.Errorf("rune 数未超限不应截断: %q", got)
	}
}

// TestMaskSensitive 敏感关键词触发长令牌遮蔽。
func TestMaskSensitive(t *testing.T) {
	// 含敏感关键词 + 长令牌 → 令牌被遮蔽
	secret := "api_key=sk-abcdefghijklmnopqrstuvwxyz0123456789"
	got := mask(secret, 500)
	if strings.Contains(got, "abcdefghijklmnopqrstuvwxyz") {
		t.Errorf("长令牌未被遮蔽: %q", got)
	}
	if !strings.Contains(got, "***") {
		t.Errorf("应包含遮蔽标记 ***: %q", got)
	}
	// 无敏感词的长内容只截断，不触发令牌遮蔽
	clean := strings.Repeat("normal ", 100)
	if strings.Contains(mask(clean, 100), "***") {
		t.Error("无敏感词不应触发令牌遮蔽")
	}
}
