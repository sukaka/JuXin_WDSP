package systemalerts

import (
	"context"
	"testing"
)

// TestSyslogForwardOnCreate 新建 OPEN 告警外发一次；合并（同 type+component 复警）不重复外发。
func TestSyslogForwardOnCreate(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	type call struct {
		hint    string
		payload interface{}
	}
	var calls []call
	e.SetSyslogForwarder(func(severityHint string, payload interface{}) {
		calls = append(calls, call{severityHint, payload})
	})

	a, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("新建告警应外发 1 次, got %d", len(calls))
	}
	if calls[0].hint != SeverityCritical { // GATEWAY_DOWN 默认 CRITICAL
		t.Errorf("severity 提示 = %q, want CRITICAL", calls[0].hint)
	}
	fwd, ok := calls[0].payload.(Alert)
	if !ok {
		t.Fatalf("payload 类型 = %T, want Alert", calls[0].payload)
	}
	if fwd.ID != a.ID || fwd.AlertType != TypeGatewayDown || fwd.Status != StatusOpen {
		t.Errorf("payload 告警内容错误: %+v", fwd)
	}

	// 同 type+component 再次触发 → 合并，不重复外发
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	}); err != nil {
		t.Fatalf("Raise merge: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("合并不应重复外发, got %d 次", len(calls))
	}
}

// TestSyslogForwardNilAndPanic 未注入时跳过；投递函数 panic 不影响告警主流程。
func TestSyslogForwardNilAndPanic(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	// 未注入：正常创建
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeDiskSpaceLow, Component: "DISK", Title: "磁盘空间不足", Message: "剩余 5%",
	}); err != nil {
		t.Fatalf("未注入投递函数时 Raise: %v", err)
	}
	// 投递函数 panic：Raise 仍成功返回告警
	e.SetSyslogForwarder(func(string, interface{}) { panic("boom") })
	a, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeValkeyUnavailable, Component: "VALKEY", Title: "Valkey 不可用", Message: "不可达",
	})
	if err != nil || a == nil {
		t.Fatalf("投递函数 panic 不应影响 Raise: alert=%v err=%v", a, err)
	}
}
