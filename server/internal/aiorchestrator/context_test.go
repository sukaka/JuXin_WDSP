package aiorchestrator

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestDefaultThresholds 默认阈值 0.70/0.80/0.90。
func TestDefaultThresholds(t *testing.T) {
	th := DefaultThresholds()
	if th.Warn != 0.70 || th.Compress != 0.80 || th.ForceTrim != 0.90 {
		t.Errorf("DefaultThresholds() = %+v", th)
	}
}

// TestCheckBudget 阈值边界：预警 0.70、压缩 0.80、强制裁剪 0.90。
func TestCheckBudget(t *testing.T) {
	th := DefaultThresholds()
	cases := []struct {
		name                             string
		tokens, window                   int
		wantWarn, wantCompress, wantTrim bool
	}{
		{"idle", 0, 1000, false, false, false},
		{"below warn", 699, 1000, false, false, false},
		{"warn boundary", 700, 1000, true, false, false},
		{"compress boundary", 800, 1000, true, true, false},
		{"trim boundary", 900, 1000, true, true, true},
		{"over window", 1500, 1000, true, true, true},
		{"default window", 8192, 0, true, true, true}, // 非法窗口回退 8192，usage=1.0
		{"negative window", 100, -1, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := CheckBudget(c.tokens, c.window, th)
			if r.NeedWarn != c.wantWarn || r.NeedCompress != c.wantCompress || r.NeedTrim != c.wantTrim {
				t.Errorf("CheckBudget(%d,%d) = (%v,%v,%v), want (%v,%v,%v)",
					c.tokens, c.window, r.NeedWarn, r.NeedCompress, r.NeedTrim,
					c.wantWarn, c.wantCompress, c.wantTrim)
			}
		})
	}
	if r := CheckBudget(500, 1000, th); r.Usage != 0.5 {
		t.Errorf("Usage = %v, want 0.5", r.Usage)
	}
}

// TestEstimateTokens 中文按 ~1.5 字/token、英文按 4 字符/token 粗估，空串保底 1。
func TestEstimateTokens(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 1},
		{"abcd", 2},        // 4/4 + 1
		{"你好啊", 3},         // 3*2/3 + 1
		{"ab你好", 2},        // 2*2/3 + 2/4 + 1
		{"hello world", 3}, // 11/4 + 1
	}
	for _, c := range cases {
		if got := EstimateTokens(c.in); got != c.want {
			t.Errorf("EstimateTokens(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestCompressNoCompression 消息数不超过保留数时不压缩。
func TestCompressNoCompression(t *testing.T) {
	msgs := []ContextMessage{
		{Role: "user", Content: "问题一"},
		{Role: "assistant", Content: "回答一"},
	}
	res := Compress(msgs, 6, 500)
	if res.DroppedMessages != 0 || res.RetainedMessages != 2 {
		t.Errorf("Dropped=%d Retained=%d, want 0/2", res.DroppedMessages, res.RetainedMessages)
	}
	if res.Summary != "" {
		t.Errorf("未压缩不应生成摘要, got %q", res.Summary)
	}
	if res.BeforeTokens != res.AfterTokens {
		t.Errorf("未压缩前后 Token 应相等: before=%d after=%d", res.BeforeTokens, res.AfterTokens)
	}
}

// TestCompress 保留最近消息与证据引用，旧消息生成摘要。
func TestCompress(t *testing.T) {
	longContent := strings.Repeat("用户提问内容。", 30) // 210 字，保证压缩后 Token 下降
	msgs := make([]ContextMessage, 0, 12)
	for i := 0; i < 6; i++ {
		msgs = append(msgs,
			ContextMessage{Role: "user", Content: longContent + " 见 [E1] 与 [E2]"},
			ContextMessage{Role: "assistant", Content: longContent + " [E1]"})
	}
	res := Compress(msgs, 4, 500)
	if res.DroppedMessages != 8 || res.RetainedMessages != 4 {
		t.Errorf("Dropped=%d Retained=%d, want 8/4", res.DroppedMessages, res.RetainedMessages)
	}
	if !strings.Contains(res.Summary, "【此前会话摘要】") {
		t.Errorf("摘要缺少标识: %q", res.Summary)
	}
	if !strings.Contains(res.Summary, "用户问1：") {
		t.Errorf("摘要缺少用户问题: %q", res.Summary)
	}
	// 证据引用去重保留
	countE1, countE2 := 0, 0
	for _, r := range res.PreservedRefs {
		switch r {
		case "[E1]":
			countE1++
		case "[E2]":
			countE2++
		}
	}
	if countE1 != 1 || countE2 != 1 {
		t.Errorf("PreservedRefs 应去重保留 [E1]/[E2] 各一次, got %v", res.PreservedRefs)
	}
	if !utf8.ValidString(res.Summary) {
		t.Error("摘要含非法 UTF-8")
	}
	if res.AfterTokens >= res.BeforeTokens {
		t.Errorf("压缩后 Token 应下降: before=%d after=%d", res.BeforeTokens, res.AfterTokens)
	}
	// AfterTokens = 摘要 + 最近消息 Token
	want := EstimateTokens(res.Summary)
	for _, m := range msgs[len(msgs)-4:] {
		want += EstimateTokens(m.Content)
	}
	if res.AfterTokens != want {
		t.Errorf("AfterTokens = %d, want %d", res.AfterTokens, want)
	}
}

// TestCompressDefaultKeepRecent keepRecent 非法值回退默认 6。
func TestCompressDefaultKeepRecent(t *testing.T) {
	msgs := make([]ContextMessage, 0, 8)
	for i := 0; i < 8; i++ {
		msgs = append(msgs, ContextMessage{Role: "user", Content: "问题"})
	}
	res := Compress(msgs, 0, 500)
	if res.DroppedMessages != 2 || res.RetainedMessages != 6 {
		t.Errorf("Dropped=%d Retained=%d, want 2/6", res.DroppedMessages, res.RetainedMessages)
	}
}

// TestCompressSummaryTruncated 摘要长度受限且截断不破坏 UTF-8。
func TestCompressSummaryTruncated(t *testing.T) {
	msgs := make([]ContextMessage, 0, 10)
	for i := 0; i < 10; i++ {
		msgs = append(msgs, ContextMessage{Role: "user", Content: strings.Repeat("安全事件分析。", 20)})
	}
	res := Compress(msgs, 2, 50)
	if got := len([]rune(res.Summary)); got != 51 { // 50 字 + 省略号
		t.Errorf("摘要长度 = %d runes, want 51", got)
	}
	if !strings.HasSuffix(res.Summary, "…") {
		t.Errorf("摘要应以省略号结尾: %q", res.Summary)
	}
	if !utf8.ValidString(res.Summary) {
		t.Error("截断后摘要含非法 UTF-8")
	}
}

// TestTruncateRunes 按 rune 截断。
func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("你好世界", 2); got != "你好…" {
		t.Errorf("truncateRunes = %q", got)
	}
	if got := truncateRunes("短", 10); got != "短" {
		t.Errorf("短文本不应截断: %q", got)
	}
	if got := truncateRunes("hello", 5); got != "hello" {
		t.Errorf("恰好等长不应截断: %q", got)
	}
}

// TestItoa 内部整数转字符串。
func TestItoa(t *testing.T) {
	if itoa(0) != "0" || itoa(7) != "7" || itoa(42) != "42" {
		t.Errorf("itoa 错误: %s %s %s", itoa(0), itoa(7), itoa(42))
	}
}
