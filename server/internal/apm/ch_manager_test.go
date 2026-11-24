// ch_manager_test.go ClickHouse 连接管理器单测（假 dialer + 可关闭假连接）：
// DSN 不变走缓存 / 变化重建并关闭旧连接 / 建连失败降级 nil / 空 DSN 返回 nil /
// 探针与采集滞后适配器的无连接口径。
package apm

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeCHConn 可关闭的假 ClickHouse 连接（验证重建时旧连接回收）。
type fakeCHConn struct {
	closed   bool
	queryErr error
}

func (c *fakeCHConn) Query(context.Context, string, ...any) (CHRows, error) {
	if c.queryErr != nil {
		return nil, c.queryErr
	}
	return &fakeCHRows{}, nil
}

func (c *fakeCHConn) Close() error { c.closed = true; return nil }

// fakeDialer 记录 dial 次数并按序返回预置结果。
type fakeDialer struct {
	calls   int
	lastDSN string
	conns   []*fakeCHConn
	err     error
}

func (d *fakeDialer) dial(dsn string) (CHQuerier, error) {
	d.calls++
	d.lastDSN = dsn
	if d.err != nil {
		return nil, d.err
	}
	c := &fakeCHConn{}
	d.conns = append(d.conns, c)
	return c, nil
}

// newTestCHManager 以内存 fake 设置源 + 假 dialer 装配管理器。
func newTestCHManager(settings *fakeRuntimeSettings, envDSN string, d *fakeDialer) *CHManager {
	m := NewCHManager(NewRuntimeConfig(settings, true, envDSN))
	m.dial = d.dial
	return m
}

func TestCHManagerCachesSameDSN(t *testing.T) {
	d := &fakeDialer{}
	m := newTestCHManager(&fakeRuntimeSettings{}, "clickhouse://h:9000/apm", d)
	ctx := context.Background()
	q1, h1 := m.Resolve(ctx)
	if q1 == nil || h1 == nil {
		t.Fatal("首次解析应建连成功")
	}
	q2, h2 := m.Resolve(ctx)
	if d.calls != 1 {
		t.Errorf("DSN 未变化不应重复建连，dial 次数 = %d, want 1", d.calls)
	}
	if q2 != q1 || h2 != h1 {
		t.Error("DSN 未变化应返回缓存连接")
	}
	if d.conns[0].closed {
		t.Error("缓存命中不应关闭连接")
	}
}

func TestCHManagerRebuildsOnDSNChange(t *testing.T) {
	d := &fakeDialer{}
	settings := &fakeRuntimeSettings{}
	m := newTestCHManager(settings, "clickhouse://old:9000/apm", d)
	ctx := context.Background()
	q1, _ := m.Resolve(ctx)
	// 界面改 DSN → 重建：关旧连接、按新 DSN 建连
	settings.strings = map[string]string{"apm:clickhouse_dsn": "clickhouse://new:9000/apm"}
	q2, _ := m.Resolve(ctx)
	if d.calls != 2 || d.lastDSN != "clickhouse://new:9000/apm" {
		t.Errorf("dial 次数/DSN = %d/%q, want 2/新 DSN", d.calls, d.lastDSN)
	}
	if q2 == q1 {
		t.Error("DSN 变化应返回新连接")
	}
	if !d.conns[0].closed {
		t.Error("重建前应关闭旧连接")
	}
	if d.conns[1].closed {
		t.Error("新连接不应被关闭")
	}
}

func TestCHManagerDialFailureDegrades(t *testing.T) {
	d := &fakeDialer{err: errors.New("connection refused")}
	m := newTestCHManager(&fakeRuntimeSettings{}, "clickhouse://h:9000/apm", d)
	q, h := m.Resolve(context.Background())
	if q != nil || h != nil {
		t.Error("建连失败应降级为 nil/nil（遥测故障不影响管理面）")
	}
	if m.Connected(context.Background()) {
		t.Error("降级时 Connected 应为 false")
	}
}

func TestCHManagerEmptyDSN(t *testing.T) {
	d := &fakeDialer{}
	m := newTestCHManager(&fakeRuntimeSettings{}, "", d)
	q, h := m.Resolve(context.Background())
	if q != nil || h != nil {
		t.Error("空 DSN 应返回 nil/nil（纯无 Agent 模式）")
	}
	if d.calls != 0 {
		t.Errorf("空 DSN 不应建连，dial 次数 = %d", d.calls)
	}
}

func TestCHManagerClearDSNClosesOldConn(t *testing.T) {
	d := &fakeDialer{}
	settings := &fakeRuntimeSettings{}
	m := newTestCHManager(settings, "clickhouse://h:9000/apm", d)
	ctx := context.Background()
	if q, _ := m.Resolve(ctx); q == nil {
		t.Fatal("首次解析应建连成功")
	}
	// 界面显式清空（空串行）→ 关旧连接、降级 nil
	settings.strings = map[string]string{"apm:clickhouse_dsn": ""}
	q, h := m.Resolve(ctx)
	if q != nil || h != nil {
		t.Error("DSN 清空后应返回 nil/nil")
	}
	if !d.conns[0].closed {
		t.Error("DSN 清空应关闭旧连接")
	}
}

func TestCHProberAdapterAvailability(t *testing.T) {
	d := &fakeDialer{}
	settings := &fakeRuntimeSettings{}
	m := newTestCHManager(settings, "", d)
	adapter := NewCHProberAdapter(m)
	ctx := context.Background()
	// 无连接：Available=false（组件不采集不判级），Ping/TracesTableExists 报错
	if adapter.Available() {
		t.Error("无连接时 Available 应为 false")
	}
	if err := adapter.Ping(ctx); err == nil {
		t.Error("无连接时 Ping 应返回错误")
	}
	if _, err := adapter.TracesTableExists(ctx); err == nil {
		t.Error("无连接时 TracesTableExists 应返回错误")
	}
	// 配上 DSN 后：Available=true，Ping 走真实探测（假连接查询成功）
	settings.strings = map[string]string{"apm:clickhouse_dsn": "clickhouse://h:9000/apm"}
	if !adapter.Available() {
		t.Error("有连接时 Available 应为 true")
	}
	if err := adapter.Ping(ctx); err != nil {
		t.Errorf("有连接时 Ping 应成功: %v", err)
	}
}

func TestIngestLagSourceNoConn(t *testing.T) {
	d := &fakeDialer{}
	m := newTestCHManager(&fakeRuntimeSettings{}, "", d)
	src := NewIngestLagSource(m)
	ts, ok, err := src.LatestIngestAt(context.Background())
	if err != nil {
		t.Fatalf("无连接不应报错: %v", err)
	}
	if ok || !ts.IsZero() {
		t.Errorf("无连接应返回 ok=false 零值时间，got %v/%v", ts, ok)
	}
}

func TestIngestLagSourceWithConn(t *testing.T) {
	d := &fakeDialer{}
	settings := &fakeRuntimeSettings{strings: map[string]string{"apm:clickhouse_dsn": "clickhouse://h:9000/apm"}}
	m := newTestCHManager(settings, "", d)
	src := NewIngestLagSource(m)
	// 假连接返回空行集 → max(Timestamp) 为 NULL → ok=false（表空无数据，非故障）
	_, ok, err := src.LatestIngestAt(context.Background())
	if err != nil {
		t.Fatalf("有连接读数不应报错: %v", err)
	}
	if ok {
		t.Error("空表应 ok=false")
	}
}

func TestCHManagerRetriesAfterCooldownAndRecovers(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	d := &fakeDialer{err: errors.New("dial tcp: lookup clickhouse: no such host")}
	m := newTestCHManager(&fakeRuntimeSettings{}, "clickhouse://clickhouse:9000/apm", d)
	m.now = func() time.Time { return now }
	m.retryInterval = 15 * time.Second
	ctx := context.Background()

	// 首次建连失败：降级为 nil
	if q, h := m.Resolve(ctx); q != nil || h != nil {
		t.Fatal("首次失败应降级返回 nil/nil")
	}
	if d.calls != 1 {
		t.Fatalf("首次失败 dial 次数 = %d, want 1", d.calls)
	}

	// 冷却期内恢复了底层网络，Resolve 不应立即阻塞重试
	d.err = nil
	now = now.Add(10 * time.Second)
	if q, _ := m.Resolve(ctx); q != nil {
		t.Fatal("冷却期内应返回降级 nil，避免每次请求阻塞")
	}
	if d.calls != 1 {
		t.Fatalf("冷却期内不应重复 dial，got %d", d.calls)
	}

	// 冷却期过后自动重试并恢复
	now = now.Add(5 * time.Second)
	q, h := m.Resolve(ctx)
	if q == nil || h == nil {
		t.Fatal("冷却期后应自动重试建连并恢复")
	}
	if d.calls != 2 {
		t.Fatalf("恢复后 dial 次数 = %d, want 2", d.calls)
	}
	// 恢复后再次调用走缓存，不再重复建连
	if q2, _ := m.Resolve(ctx); q2 != q || d.calls != 2 {
		t.Fatalf("恢复后应命中缓存连接，dial=%d", d.calls)
	}
}

func TestCHManagerReconnectAndRetryDisconnected(t *testing.T) {
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	d := &fakeDialer{err: errors.New("network unreachable")}
	m := newTestCHManager(&fakeRuntimeSettings{}, "clickhouse://clickhouse:9000/apm", d)
	m.now = func() time.Time { return now }
	m.retryInterval = 15 * time.Second
	ctx := context.Background()

	// 首次失败进入冷却期
	if q, _ := m.Resolve(ctx); q != nil || d.calls != 1 {
		t.Fatalf("首次失败状态异常：q=%v calls=%d", q, d.calls)
	}
	// 冷却期内网络恢复：RetryDisconnected 立即绕过冷却建连
	d.err = nil
	q1, _ := m.RetryDisconnected(ctx)
	if q1 == nil || d.calls != 2 {
		t.Fatalf("RetryDisconnected 应绕过冷却恢复连接，q=%v calls=%d", q1, d.calls)
	}
	// 已连接状态下 RetryDisconnected 不打断现有连接
	if q2, _ := m.RetryDisconnected(ctx); q2 != q1 || d.calls != 2 || d.conns[0].closed {
		t.Fatalf("已连接时 RetryDisconnected 不应重建连接，calls=%d closed=%v", d.calls, d.conns[0].closed)
	}
	// Reconnect 显式重建会关闭旧连接并建新连接
	q3, _ := m.Reconnect(ctx)
	if q3 == nil || q3 == q1 || d.calls != 3 || !d.conns[0].closed || d.conns[1].closed {
		t.Fatalf("Reconnect 应回收旧连接并建新连接，calls=%d oldClosed=%v", d.calls, d.conns[0].closed)
	}
}
