package runtimehealth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClickHouseProber 是 ClickHouseProber 的可编程内存实现。
type fakeClickHouseProber struct {
	pingErr   error
	exists    bool
	existsErr error
	pingCalls int
}

func (f *fakeClickHouseProber) Ping(context.Context) error {
	f.pingCalls++
	return f.pingErr
}

func (f *fakeClickHouseProber) TracesTableExists(context.Context) (bool, error) {
	return f.exists, f.existsErr
}

// TestAPMClickHouseIncluded 注入门控：未注入探针（APM 关闭/DSN 空/连接失败降级）
// 不纳入采集；注入才纳入。组件不进 AllComponents() 固定清单（missing UNKNOWN 口径）。
func TestAPMClickHouseIncluded(t *testing.T) {
	if NewCollector(nil, Options{}).apmClickHouseIncluded() {
		t.Error("未注入探针不应纳入采集")
	}
	if !NewCollector(nil, Options{APMClickHouse: &fakeClickHouseProber{}}).apmClickHouseIncluded() {
		t.Error("注入探针应纳入采集")
	}
	for _, comp := range AllComponents() {
		if comp == ComponentAPMClickHouse {
			t.Error("APM_CLICKHOUSE 不得进入 AllComponents() 固定清单（默认部署 missing 会计 UNKNOWN）")
		}
	}
}

// TestProbeAPMClickHouseNilProber 未注入探针：UNKNOWN 且不触探针（判级由 collectAll
// 门控保证不产生快照，本用例兜底探针自身 nil 安全）。
func TestProbeAPMClickHouseNilProber(t *testing.T) {
	c := NewCollector(nil, Options{})
	snap := c.probeAPMClickHouse(context.Background())
	if snap.Component != ComponentAPMClickHouse || snap.Status != StatusUnknown {
		t.Errorf("nil prober snap = %+v, want UNKNOWN", snap)
	}
}

// TestProbeAPMClickHouseDown 轻查询失败判 DOWN（数据面不可达），不附延迟。
func TestProbeAPMClickHouseDown(t *testing.T) {
	p := &fakeClickHouseProber{pingErr: errors.New("connection refused")}
	c := NewCollector(nil, Options{APMClickHouse: p})
	snap := c.probeAPMClickHouse(context.Background())
	if snap.Status != StatusDown || !strings.Contains(snap.Message, "不可达") {
		t.Errorf("ping fail snap = %+v, want DOWN 不可达", snap)
	}
	if snap.LatencyMs != nil {
		t.Errorf("DOWN 不应附延迟, got %d", *snap.LatencyMs)
	}
	if p.pingCalls != 1 {
		t.Errorf("ping calls = %d, want 1", p.pingCalls)
	}
}

// TestProbeAPMClickHouseDegraded 可达但表检查失败/表不存在判 DEGRADED。
func TestProbeAPMClickHouseDegraded(t *testing.T) {
	// 表检查查询失败
	c := NewCollector(nil, Options{APMClickHouse: &fakeClickHouseProber{existsErr: errors.New("query timeout")}})
	snap := c.probeAPMClickHouse(context.Background())
	if snap.Status != StatusDegraded || !strings.Contains(snap.Message, "表检查失败") {
		t.Errorf("exists err snap = %+v, want DEGRADED 表检查失败", snap)
	}
	// 表不存在（数据面未初始化）
	c = NewCollector(nil, Options{APMClickHouse: &fakeClickHouseProber{exists: false}})
	snap = c.probeAPMClickHouse(context.Background())
	if snap.Status != StatusDegraded || !strings.Contains(snap.Message, "otel_traces 表不存在") {
		t.Errorf("missing table snap = %+v, want DEGRADED 表不存在", snap)
	}
}

// TestProbeAPMClickHouseUp 全部正常判 UP，延迟毫秒附 LatencyMs（可控时钟注入 150ms）。
func TestProbeAPMClickHouseUp(t *testing.T) {
	base := time.Date(2026, 8, 31, 12, 0, 0, 0, time.UTC)
	tick := 0
	now := func() time.Time {
		tick++
		return base.Add(time.Duration(tick-1) * 150 * time.Millisecond)
	}
	c := NewCollector(nil, Options{
		APMClickHouse: &fakeClickHouseProber{exists: true},
		Now:           now,
	})
	snap := c.probeAPMClickHouse(context.Background())
	if snap.Status != StatusUp || !strings.Contains(snap.Message, "正常") {
		t.Errorf("healthy snap = %+v, want UP", snap)
	}
	if snap.LatencyMs == nil || *snap.LatencyMs != 150 {
		t.Errorf("latency = %v, want 150ms", snap.LatencyMs)
	}
}
