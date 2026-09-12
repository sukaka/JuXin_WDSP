// traffic_test.go 流量趋势桶计数挂点单测（WDSP 接口访问趋势波形图）：
// 端点发现 upsert 成功后按记录 occurred_at 对齐 5 分钟桶自增；
// recorder 失败/发现失败只记日志不中断采集；未注入 recorder 时跳过。
package apiruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

type trafficCall struct {
	endpointID uuid.UUID
	bucket     time.Time
}

type fakeTraffic struct {
	calls []trafficCall
	err   error
}

func (f *fakeTraffic) RecordTrafficBucket(_ context.Context, endpointID uuid.UUID, bucketStart time.Time) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, trafficCall{endpointID, bucketStart})
	return nil
}

// fakeDiscoveryID 返回带固定 ID 的端点（流量桶计数需要 endpoint_id）。
type fakeDiscoveryID struct {
	id  uuid.UUID
	err error
}

func (f *fakeDiscoveryID) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &apiassets.Endpoint{ID: f.id, EndpointKey: in.Method + " " + in.PathTemplate}, nil
}

// 正常路径：每条有效记录在发现成功后按 occurred_at 对齐桶计数一次。
func TestCollectOnce_TrafficBuckets(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	at := time.Date(2026, 8, 12, 10, 7, 35, 0, time.UTC)
	mk := func(reqID string, occurredAt time.Time) Record {
		return Record{
			RequestID: reqID, EndpointKey: "GET /v1/items/{id}", Method: "GET", PathTemplate: "/v1/items/{id}",
			IsAPI: true, FinalAction: "ALLOW", OccurredAt: occurredAt,
		}
	}
	writeLines(t, logPath, []string{
		mustJSON(t, mk("r-t1", at)),
		mustJSON(t, mk("r-t2", at.Add(2*time.Minute))), // 同桶
		mustJSON(t, mk("r-t3", at.Add(5*time.Minute))), // 下一桶
		mustJSON(t, mk("r-t4", time.Time{})),           // occurred_at 缺失 → 回落采集时刻
	})

	epID := uuid.New()
	traffic := &fakeTraffic{}
	c := NewCollector(&fakeSaver{}, "test-traffic", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryID{id: epID})
	c.SetTrafficRecorder(traffic)

	n, err := c.CollectOnce(context.Background())
	if err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if n != 4 {
		t.Fatalf("processed = %d, want 4", n)
	}
	if len(traffic.calls) != 4 {
		t.Fatalf("traffic calls = %d, want 4", len(traffic.calls))
	}
	wantBucket := apiassets.TrafficBucketStart(at)
	if traffic.calls[0].endpointID != epID || traffic.calls[0].bucket != wantBucket {
		t.Fatalf("call[0] = %+v, want endpoint %s bucket %v", traffic.calls[0], epID, wantBucket)
	}
	if traffic.calls[1].bucket != wantBucket {
		t.Fatalf("call[1] bucket = %v, want 同桶 %v", traffic.calls[1].bucket, wantBucket)
	}
	if want := wantBucket.Add(apiassets.TrafficBucketSeconds * time.Second); traffic.calls[2].bucket != want {
		t.Fatalf("call[2] bucket = %v, want 下一桶 %v", traffic.calls[2].bucket, want)
	}
	// occurred_at 零值回落采集时刻：桶仍须对齐
	if got := traffic.calls[3].bucket; got != apiassets.TrafficBucketStart(got) || got.IsZero() {
		t.Fatalf("call[3] bucket = %v, want 对齐桶", got)
	}
}

// recorder 写失败只记日志：采集继续、断点照常前移（下轮不重读）。
func TestCollectOnce_TrafficRecorderFailureDoesNotStop(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	rec := Record{
		RequestID: "r-tf", EndpointKey: "GET /v1/items/{id}", Method: "GET", PathTemplate: "/v1/items/{id}",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	c := NewCollector(&fakeSaver{}, "test-traffic-fail", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryID{id: uuid.New()})
	c.SetTrafficRecorder(&fakeTraffic{err: errors.New("db down")})

	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CollectOnce = (%d, %v), want (1, nil)", n, err)
	}
	if _, err := os.Stat(cpPath); err != nil {
		t.Fatalf("checkpoint not saved: %v", err)
	}
}

// 发现 upsert 失败：无 endpoint_id，不计流量桶；采集继续。
func TestCollectOnce_DiscoveryFailureSkipsTraffic(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	rec := Record{
		RequestID: "r-td", EndpointKey: "GET /v1/items/{id}", Method: "GET", PathTemplate: "/v1/items/{id}",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	traffic := &fakeTraffic{}
	c := NewCollector(&fakeSaver{}, "test-traffic-disc-fail", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryID{err: errors.New("db down")})
	c.SetTrafficRecorder(traffic)

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(traffic.calls) != 0 {
		t.Fatalf("traffic calls = %d, want 0（发现失败无 endpoint_id）", len(traffic.calls))
	}
}

// 未注入 recorder（nil）：零开销跳过，采集正常。
func TestCollectOnce_WithoutTrafficRecorder(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-runtime-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	rec := Record{
		RequestID: "r-tn", EndpointKey: "GET /v1/items/{id}", Method: "GET", PathTemplate: "/v1/items/{id}",
		IsAPI: true, FinalAction: "ALLOW", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, rec)})

	c := NewCollector(&fakeSaver{}, "test-traffic-nil", logPath, cpPath, "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryID{id: uuid.New()})

	n, err := c.CollectOnce(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("CollectOnce = (%d, %v), want (1, nil)", n, err)
	}
}
