// sourcebuckets_test.go 暴露面来源聚合采集挂点测试：钩子调用参数（端点 ID /
// client_ip / 盐化指纹 / 事件时刻）、nil recorder 跳过、空 client_ip 跳过、
// 发现失败（nil 端点）跳过、聚合失败不中断采集（fail-open 仅此聚合）。
package apiruntime

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apiassets"
)

// fakeSourceRecorder 记录来源聚合调用；errOn 非空时返回错误（fail-open 路径）。
type sourceCall struct {
	endpointID  uuid.UUID
	clientIP    string
	fingerprint string
	ts          time.Time
}

type fakeSourceRecorder struct {
	calls []sourceCall
	err   error
}

func (f *fakeSourceRecorder) RecordSource(_ context.Context, endpointID uuid.UUID, clientIP, fingerprint string, ts time.Time) error {
	f.calls = append(f.calls, sourceCall{endpointID: endpointID, clientIP: clientIP, fingerprint: fingerprint, ts: ts})
	return f.err
}

// fakeDiscoveryWithID 发现 upsert 假实现（返回带 ID 端点）。
type fakeDiscoveryWithID struct {
	id  uuid.UUID
	err error
}

func (f *fakeDiscoveryWithID) UpsertDiscovery(_ context.Context, in apiassets.DiscoveryInput) (*apiassets.Endpoint, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &apiassets.Endpoint{ID: f.id, EndpointKey: in.Method + " " + in.PathTemplate}, nil
}

func TestRecordSourceBucketHook(t *testing.T) {
	dir := t.TempDir()
	epID := uuid.New()
	occurred := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	recs := []Record{
		// 正常：ALLOW 纯通行事件也聚合（全量口径）
		{RequestID: "s-1", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
			IsAPI: true, FinalAction: "ALLOW", ClientIP: "8.8.8.8", SourceFingerprint: "fp-a", OccurredAt: occurred},
		// 空 client_ip（旧版网关）：跳过聚合
		{RequestID: "s-2", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
			IsAPI: true, FinalAction: "ALLOW", SourceFingerprint: "fp-b", OccurredAt: occurred},
	}
	logPath := filepath.Join(dir, "events.log")
	writeLines(t, logPath, []string{mustJSON(t, recs[0]), mustJSON(t, recs[1])})

	saver := &fakeSaver{}
	src := &fakeSourceRecorder{}
	c := NewCollector(saver, "test-src", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryWithID{id: epID})
	c.SetSourceRecorder(src)

	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(src.calls) != 1 {
		t.Fatalf("source calls=%d, want 1", len(src.calls))
	}
	call := src.calls[0]
	if call.endpointID != epID || call.clientIP != "8.8.8.8" || call.fingerprint != "fp-a" || !call.ts.Equal(occurred) {
		t.Fatalf("source call = %+v", call)
	}
}

// TestRecordSourceBucketNilRecorder 未注入 recorder：零开销跳过，不 panic。
func TestRecordSourceBucketNilRecorder(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")
	writeLines(t, logPath, []string{mustJSON(t, Record{
		RequestID: "s-1", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
		IsAPI: true, FinalAction: "ALLOW", ClientIP: "8.8.8.8", OccurredAt: time.Now(),
	})})
	c := NewCollector(&fakeSaver{}, "test-nil", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryWithID{id: uuid.New()})
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
}

// TestRecordSourceBucketFailOpen 聚合失败只记日志不中断采集（断点照常前移、
// 主事件落库不受影响——fail-open 仅限此聚合）。
func TestRecordSourceBucketFailOpen(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")
	writeLines(t, logPath, []string{mustJSON(t, Record{
		RequestID: "s-1", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
		IsAPI: true, FinalAction: "BLOCK", RiskLevel: "HIGH", ClientIP: "8.8.8.8",
		SourceFingerprint: "fp-a", OccurredAt: time.Now(),
		Details: nil,
	})})
	saver := &fakeSaver{}
	src := &fakeSourceRecorder{err: errors.New("db down")}
	c := NewCollector(saver, "test-fail", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryWithID{id: uuid.New()})
	c.SetSourceRecorder(src)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce must not fail on source aggregation error: %v", err)
	}
	if len(src.calls) != 1 {
		t.Fatalf("source calls=%d, want 1", len(src.calls))
	}
	// notable 主事件照常落库
	if len(saver.saved) != 1 {
		t.Fatalf("saved=%d, want 1", len(saver.saved))
	}
}

// TestRecordSourceBucketDiscoveryFailed 发现 upsert 失败（nil 端点）时跳过聚合。
func TestRecordSourceBucketDiscoveryFailed(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")
	writeLines(t, logPath, []string{mustJSON(t, Record{
		RequestID: "s-1", EndpointKey: "GET /a", Method: "GET", PathTemplate: "/a",
		IsAPI: true, FinalAction: "ALLOW", ClientIP: "8.8.8.8", OccurredAt: time.Now(),
	})})
	src := &fakeSourceRecorder{}
	c := NewCollector(&fakeSaver{}, "test-discfail", logPath, filepath.Join(dir, "cp"), "node-1")
	c.SetDiscoveryUpserter(&fakeDiscoveryWithID{err: errors.New("quota exceeded")})
	c.SetSourceRecorder(src)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce: %v", err)
	}
	if len(src.calls) != 0 {
		t.Fatalf("source calls=%d, want 0", len(src.calls))
	}
}
