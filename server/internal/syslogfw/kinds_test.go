package syslogfw

import (
	"context"
	"testing"
)

// TestKindEnabled 六类消息的类型开关映射（含默认拒绝未知类型）。
func TestKindEnabled(t *testing.T) {
	allOn := config{
		forwardSecEvt: true, forwardACEvt: true, forwardAccess: true,
		forwardOpAudit: true, forwardLoginLog: true, forwardSysAlert: true,
	}
	for _, k := range []Kind{
		KindSecurityEvent, KindAccessControlEvent, KindAccessLog,
		KindOperationAudit, KindLoginLog, KindSystemAlert, KindTest,
	} {
		if !allOn.kindEnabled(k) {
			t.Errorf("全开配置下 kind %d 应外发", k)
		}
	}

	cases := []struct {
		name string
		cfg  config
		kind Kind
		want bool
	}{
		{"关操作审计", config{forwardOpAudit: false}, KindOperationAudit, false},
		{"开操作审计", config{forwardOpAudit: true}, KindOperationAudit, true},
		{"关登录日志", config{forwardLoginLog: false}, KindLoginLog, false},
		{"开登录日志", config{forwardLoginLog: true}, KindLoginLog, true},
		{"关系统告警", config{forwardSysAlert: false}, KindSystemAlert, false},
		{"开系统告警", config{forwardSysAlert: true}, KindSystemAlert, true},
		{"操作审计开关不影响安全事件", config{forwardOpAudit: false, forwardSecEvt: true}, KindSecurityEvent, true},
		{"测试消息不受开关影响", config{}, KindTest, true},
		{"未知类型不外发", config{forwardSecEvt: true}, Kind(99), false},
	}
	for _, c := range cases {
		if got := c.cfg.kindEnabled(c.kind); got != c.want {
			t.Errorf("%s: kindEnabled = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestLoadConfigNewKindKeys 新增三类开关从 settings 热读取；缺省（未配置）时默认 true（低频高价值日志）。
func TestLoadConfigNewKindKeys(t *testing.T) {
	fw := newTestForwarder(fakeSettings{vals: map[string]interface{}{}}, t.TempDir())
	cfg := fw.loadConfig(context.Background())
	if !cfg.forwardOpAudit || !cfg.forwardLoginLog || !cfg.forwardSysAlert {
		t.Errorf("新开关缺省应默认 true: %+v", cfg)
	}
	// 既有默认值不回退：总开关默认关、全量访问日志默认关
	if cfg.enabled || cfg.forwardAccess {
		t.Errorf("既有默认值被改变: %+v", cfg)
	}

	st := fakeSettings{vals: map[string]interface{}{
		"logging:syslog_forward_operation_audits": false,
		"logging:syslog_forward_login_logs":       false,
		"logging:syslog_forward_system_alerts":    true,
	}}
	fw = newTestForwarder(st, t.TempDir())
	cfg = fw.loadConfig(context.Background())
	if cfg.forwardOpAudit || cfg.forwardLoginLog || !cfg.forwardSysAlert {
		t.Errorf("新开关热读取错误: %+v", cfg)
	}
}
