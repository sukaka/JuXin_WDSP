package systemalerts

import (
	"context"
	"testing"
	"time"
)

// TestNotifyForwardOnCreate 新建 OPEN 告警投递通知一次；合并不重复投递。
func TestNotifyForwardOnCreate(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	var calls []Alert
	e.SetNotifyForwarder(func(a Alert) { calls = append(calls, a) })

	a, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("新建告警应投递 1 次, got %d", len(calls))
	}
	if calls[0].ID != a.ID || calls[0].AlertType != TypeGatewayDown || calls[0].Status != StatusOpen {
		t.Errorf("投递内容错误: %+v", calls[0])
	}
	if calls[0].Severity != SeverityCritical {
		t.Errorf("severity = %q, want CRITICAL", calls[0].Severity)
	}

	// 同 type+component 复警 → 合并，不重复投递
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	}); err != nil {
		t.Fatalf("Raise merge: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("合并不应重复投递, got %d", len(calls))
	}
}

// TestNotifyForwardOnAutoRecover 自动恢复投递 RESOLVED 事件（通知层按开关决定是否外发）。
func TestNotifyForwardOnAutoRecover(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	var calls []Alert
	e.SetNotifyForwarder(func(a Alert) { calls = append(calls, a) })

	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeDatabaseUnavailable, Component: "POSTGRES", Title: "数据库不可用", Message: "不可达",
	}); err != nil {
		t.Fatalf("Raise: %v", err)
	}
	n, err := e.AutoRecover(context.Background(), "POSTGRES", TypeDatabaseUnavailable)
	if err != nil || n != 1 {
		t.Fatalf("AutoRecover: n=%d err=%v", n, err)
	}
	if len(calls) != 2 {
		t.Fatalf("触发+恢复应投递 2 次, got %d", len(calls))
	}
	got := calls[1]
	if got.Status != StatusResolved {
		t.Errorf("恢复事件 status = %q, want RESOLVED", got.Status)
	}
	if got.ResolveType == nil || *got.ResolveType != ResolveRecovered {
		t.Errorf("恢复事件 resolve_type = %v, want RECOVERED", got.ResolveType)
	}
	if got.ResolvedAt == nil {
		t.Error("恢复事件应有 resolved_at")
	}
}

// TestNotifyForwardNilAndPanic 未注入时跳过；投递函数 panic 不影响告警主流程。
func TestNotifyForwardNilAndPanic(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeDiskSpaceLow, Component: "DISK", Title: "磁盘空间不足", Message: "剩余 5%",
	}); err != nil {
		t.Fatalf("未注入投递函数时 Raise: %v", err)
	}
	e.SetNotifyForwarder(func(Alert) { panic("boom") })
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeValkeyUnavailable, Component: "VALKEY", Title: "Valkey 不可用", Message: "不可达",
	}); err != nil {
		t.Fatalf("投递函数 panic 不应影响 Raise: %v", err)
	}
}

// TestNotifyForwardSilenced 静默期内告警落库但不投递通知（与 syslog 外发同语义）。
func TestNotifyForwardSilenced(t *testing.T) {
	store := newFakeStore()
	e := NewEngine(store, EngineOptions{})
	var calls []Alert
	e.SetNotifyForwarder(func(a Alert) { calls = append(calls, a) })

	// 先触发并恢复一条告警，再把它置为静默期内（HasActiveSilence 含已关闭行）
	a, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	})
	if err != nil {
		t.Fatalf("Raise: %v", err)
	}
	if err := store.ResolveRecovered(context.Background(), a.ID, time.Now()); err != nil {
		t.Fatalf("ResolveRecovered: %v", err)
	}
	until := time.Now().Add(30 * time.Minute)
	store.mu.Lock()
	store.alerts[a.ID].SilencedUntil = &until
	store.mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("首次触发应投递 1 次, got %d", len(calls))
	}

	// 同指纹再次触发（无未关闭告警 → 新建）：落库成功但跳过通知投递
	if _, err := e.Raise(context.Background(), RaiseRequest{
		AlertType: TypeGatewayDown, Component: "GATEWAY", Title: "防护网关不可用", Message: "socket 不可达",
	}); err != nil {
		t.Fatalf("Raise silenced: %v", err)
	}
	if len(calls) != 1 {
		t.Errorf("静默期内不应投递通知, got %d", len(calls))
	}
}
