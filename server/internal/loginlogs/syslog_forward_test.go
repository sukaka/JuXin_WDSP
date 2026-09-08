package loginlogs

import (
	"testing"
)

// TestSyslogSeverityHint 登录失败/锁定等失败事件 → warning，成功 → info（空提示）。
func TestSyslogSeverityHint(t *testing.T) {
	if got := syslogSeverityHint(ResultFailure); got != "warning" {
		t.Errorf("syslogSeverityHint(FAILURE) = %q, want warning", got)
	}
	if got := syslogSeverityHint(ResultSuccess); got != "" {
		t.Errorf("syslogSeverityHint(SUCCESS) = %q, want 空（info）", got)
	}
	if got := syslogSeverityHint(""); got != "" {
		t.Errorf("syslogSeverityHint(空) = %q, want 空（info）", got)
	}
}

// TestEnqueueSyslogNilSafe 未注入投递函数时安全跳过。
func TestEnqueueSyslogNilSafe(t *testing.T) {
	s := &Service{}
	s.enqueueSyslog("warning", map[string]interface{}{"k": "v"}) // 不应 panic
}

// TestEnqueueSyslogDelivers 注入投递函数时按提示与 payload 投递。
func TestEnqueueSyslogDelivers(t *testing.T) {
	var gotHint string
	calls := 0
	s := &Service{}
	s.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		calls++
		gotHint = severityHint
		if payload.(map[string]interface{})["event_type"] != EventLoginFailure {
			t.Errorf("payload 错误: %v", payload)
		}
	})
	s.enqueueSyslog(syslogSeverityHint(ResultFailure), map[string]interface{}{"event_type": EventLoginFailure})
	if calls != 1 || gotHint != "warning" {
		t.Fatalf("投递次数/提示错误: calls=%d hint=%q", calls, gotHint)
	}
}

// TestEnqueueSyslogPanicTolerated 投递函数 panic 不扩散到登录主流程。
func TestEnqueueSyslogPanicTolerated(t *testing.T) {
	s := &Service{}
	s.SetSyslogForwarder(func(string, interface{}) { panic("boom") })
	s.enqueueSyslog("", map[string]interface{}{}) // 不应 panic
}
