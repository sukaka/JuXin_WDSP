package aiaudit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
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

// TestRecordJSONTags 校验 Record 含 id / prompt_version / confirm_result 且不暴露哈希链列。
func TestRecordJSONTags(t *testing.T) {
	id := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	uid := uuid.MustParse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
	rec := Record{
		ID:             id,
		OccurredAt:     time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC),
		UserID:         &uid,
		Username:       "secadmin",
		RoleCodes:      "SECURITY_ADMIN",
		Action:         "prompt_test",
		TaskType:       "EVENT_ANALYSIS",
		AgentCode:      "security_event",
		ToolCode:       "security_event.search",
		ModelCode:      "qwen2.5:3b",
		PromptVersion:  "v3",
		InputTokens:    120,
		OutputTokens:   45,
		DurationMs:     310,
		EstimatedCost:  0.002,
		RequestSummary: "test summary",
		ResultSummary:  "PASSED",
		DraftReference: "draft-1",
		ConfirmResult:  "CONFIRMED",
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("json.Marshal(Record) failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if m["id"] != id.String() {
		t.Errorf("id=%v want %s", m["id"], id.String())
	}
	if m["prompt_version"] != "v3" {
		t.Errorf("prompt_version=%v want v3", m["prompt_version"])
	}
	if m["confirm_result"] != "CONFIRMED" {
		t.Errorf("confirm_result=%v want CONFIRMED", m["confirm_result"])
	}
	for _, forbidden := range []string{"previous_hash", "record_hash"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("Record JSON must not contain %q", forbidden)
		}
	}
}
