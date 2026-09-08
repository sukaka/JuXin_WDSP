package syslogfw

import (
	"regexp"
	"strings"
	"testing"
)

func TestSeverityFor(t *testing.T) {
	cases := []struct {
		kind Kind
		hint string
		want int
	}{
		{KindSecurityEvent, "HIGH", 3},
		{KindSecurityEvent, "high", 3},
		{KindSecurityEvent, "MEDIUM", 4},
		{KindSecurityEvent, "LOW", 5},
		{KindSecurityEvent, "CRITICAL", 6}, // 未映射等级 → info
		{KindSecurityEvent, "", 6},
		{KindAccessLog, "", 6},
		{KindAccessLog, "HIGH", 6}, // 非安全事件忽略 hint
		{KindAccessControlEvent, "", 6},
		{KindSystemAlert, "CRITICAL", 2},
		{KindSystemAlert, "HIGH", 3},
		{KindSystemAlert, "MEDIUM", 4},
		{KindSystemAlert, "LOW", 5},
		{KindSystemAlert, "INFO", 6},
		{KindSystemAlert, "", 6},
		{KindLoginLog, "warning", 4}, // 登录失败
		{KindLoginLog, "WARNING", 4},
		{KindLoginLog, "", 6},              // 登录成功 → info
		{KindOperationAudit, "warning", 4}, // 删除/禁用类操作
		{KindOperationAudit, "", 6},
		{KindOperationAudit, "HIGH", 6}, // 仅识别 warning 提示
		{KindTest, "", 6},
	}
	for _, c := range cases {
		if got := severityFor(c.kind, c.hint); got != c.want {
			t.Errorf("severityFor(%v, %q) = %d, want %d", c.kind, c.hint, got, c.want)
		}
	}
}

var tsPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`)

func TestBuildMessage(t *testing.T) {
	// facility=1, HIGH 安全事件 severity=3 → pri=1*8+3=11
	msg := BuildMessage(1, severityFor(KindSecurityEvent, "HIGH"), "gw-01", "1234",
		KindSecurityEvent, []byte(`{"attack_type":"XSS"}`))
	s := string(msg)
	if !strings.HasPrefix(s, "<11>1 ") {
		t.Fatalf("pri 头错误: %s", s)
	}
	parts := strings.SplitN(s, " ", 8)
	// <pri>1 ts host app procid msgid sd msg → 共 8 段
	if len(parts) != 8 {
		t.Fatalf("字段数错误: %q", s)
	}
	if !tsPattern.MatchString(parts[1]) {
		t.Errorf("时间戳格式错误: %q", parts[1])
	}
	if parts[2] != "gw-01" || parts[3] != "jiuzhang-waf" || parts[4] != "1234" {
		t.Errorf("头部字段错误: %q", s)
	}
	if parts[5] != "security-event" {
		t.Errorf("msgid 错误: %q", parts[5])
	}
	if parts[6] != "-" || parts[7] != `{"attack_type":"XSS"}` {
		t.Errorf("structured-data/msg 错误: %q", s)
	}
}

func TestBuildMessageKindsAndPri(t *testing.T) {
	// facility=2, access log severity=6 → pri=2*8+6=22
	msg := string(BuildMessage(2, severityFor(KindAccessLog, ""), "h", "1", KindAccessLog, []byte(`{}`)))
	if !strings.HasPrefix(msg, "<22>1 ") || !strings.Contains(msg, " access-log ") {
		t.Errorf("access log 消息错误: %s", msg)
	}
	msg = string(BuildMessage(1, 6, "h", "1", KindAccessControlEvent, []byte(`{}`)))
	if !strings.Contains(msg, " access-control-event ") {
		t.Errorf("access control 消息错误: %s", msg)
	}
	// 新增三类 msgid
	for k, want := range map[Kind]string{
		KindOperationAudit: "operation-audit",
		KindLoginLog:       "login-log",
		KindSystemAlert:    "system-alert",
	} {
		msg = string(BuildMessage(1, 6, "h", "1", k, []byte(`{}`)))
		if !strings.Contains(msg, " "+want+" ") {
			t.Errorf("kind %v msgid 错误: %s", k, msg)
		}
	}
	// 系统告警 CRITICAL → severity 2 → pri=1*8+2=10
	msg = string(BuildMessage(1, severityFor(KindSystemAlert, "CRITICAL"), "h", "1", KindSystemAlert, []byte(`{}`)))
	if !strings.HasPrefix(msg, "<10>1 ") {
		t.Errorf("CRITICAL 告警 pri 错误: %s", msg)
	}
	// facility 越界回退 1
	msg = string(BuildMessage(99, 6, "h", "1", KindTest, []byte(`{}`)))
	if !strings.HasPrefix(msg, "<14>1 ") {
		t.Errorf("facility 越界未回退: %s", msg)
	}
}

func TestBuildMessageSanitize(t *testing.T) {
	// hostname 含空格 → 替换；msg 含换行 → 替换为空格（保护 TCP 分帧）
	msg := string(BuildMessage(1, 6, "bad host", "1", KindTest, []byte("{\"a\":1}\n{\"b\":2}")))
	if strings.Contains(msg, "bad host") {
		t.Errorf("hostname 未清洗: %s", msg)
	}
	if strings.Contains(msg, "\n") {
		t.Errorf("消息包含换行: %q", msg)
	}
	// 空 hostname → NILVALUE
	msg = string(BuildMessage(1, 6, "", "", KindTest, []byte(`{}`)))
	parts := strings.SplitN(msg, " ", 8)
	if parts[2] != "-" || parts[4] != "-" {
		t.Errorf("空字段未用 NILVALUE: %q", msg)
	}
}
