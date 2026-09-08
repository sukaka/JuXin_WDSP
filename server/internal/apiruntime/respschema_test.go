// respschema_test.go 响应 Schema 学习（P0-06）单元测试：
// 合并纯函数矩阵（并集/类型冲突首胜/截断语义/幂等）+ 采集器接线（fake recorder）。
package apiruntime

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 合并矩阵：新建 / 并集 / 类型冲突首胜 / 截断 OR / content_type 最新非空 / 坏文档容忍。
func TestMergeResponseSchema(t *testing.T) {
	obs := dsctx.ResponseObservation{
		StatusCode: 200, ContentType: "application/json",
		Fields: map[string]string{"a": "string", "b": "number"},
	}
	// 新建（无既有文档）
	doc := mergeResponseSchema(nil, obs)
	if len(doc.Fields) != 2 || doc.Fields["a"] != "string" || doc.ContentType != "application/json" || doc.Truncated {
		t.Fatalf("fresh doc = %+v", doc)
	}
	// 重复同一观测：幂等（字段集合不变）
	again := mergeResponseSchema(mustJSONDoc(t, doc), obs)
	if len(again.Fields) != 2 || again.Fields["b"] != "number" {
		t.Fatalf("idempotent merge = %+v", again)
	}
	// 并集 + 类型冲突保留既有（首胜）
	merged := mergeResponseSchema(mustJSONDoc(t, doc), dsctx.ResponseObservation{
		StatusCode: 200, Fields: map[string]string{"a": "number", "c": "bool"},
	})
	if len(merged.Fields) != 3 || merged.Fields["a"] != "string" || merged.Fields["c"] != "bool" {
		t.Fatalf("union/first-wins = %+v", merged)
	}
	// truncated 任一为真即真
	trunc := mergeResponseSchema(mustJSONDoc(t, doc), dsctx.ResponseObservation{
		StatusCode: 200, Fields: map[string]string{"x": "string"}, Truncated: true,
	})
	if !trunc.Truncated {
		t.Fatal("truncated must stick")
	}
	// content_type：空观测不改写，非空最新覆盖
	keep := mergeResponseSchema(mustJSONDoc(t, doc), dsctx.ResponseObservation{StatusCode: 200, Fields: map[string]string{"d": "null"}})
	if keep.ContentType != "application/json" {
		t.Fatalf("empty content_type must not overwrite: %+v", keep)
	}
	if over := mergeResponseSchema(mustJSONDoc(t, doc), dsctx.ResponseObservation{
		StatusCode: 200, ContentType: "application/problem+json", Fields: map[string]string{"d": "null"},
	}); over.ContentType != "application/problem+json" {
		t.Fatalf("latest content_type must win: %+v", over)
	}
	// 坏既有文档按空处理（容忍，不报错）
	if bad := mergeResponseSchema([]byte("{oops"), obs); len(bad.Fields) != 2 {
		t.Fatalf("bad existing doc tolerated: %+v", bad)
	}
}

func mustJSONDoc(t *testing.T, doc responseSchemaDoc) []byte {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal doc: %v", err)
	}
	return b
}

// 空值守卫：nil store / nil db / 空键 / 空观测 / 无状态码观测，均安全返回 nil。
func TestRecordResponseObservations_Guards(t *testing.T) {
	ctx := context.Background()
	var nilStore *RespSchemaStore
	if err := nilStore.RecordResponseObservations(ctx, "GET /v1/x", []dsctx.ResponseObservation{{StatusCode: 200, Fields: map[string]string{"a": "string"}}}); err != nil {
		t.Fatalf("nil store: %v", err)
	}
	if err := NewRespSchemaStore(nil).RecordResponseObservations(ctx, "GET /v1/x", []dsctx.ResponseObservation{{StatusCode: 200}}); err != nil {
		t.Fatalf("nil db: %v", err)
	}
	s := NewRespSchemaStore(nil)
	if err := s.RecordResponseObservations(ctx, "", []dsctx.ResponseObservation{{StatusCode: 200, Fields: map[string]string{"a": "string"}}}); err != nil {
		t.Fatalf("empty key: %v", err)
	}
	if err := s.RecordResponseObservations(ctx, "GET /v1/x", nil); err != nil {
		t.Fatalf("nil obs: %v", err)
	}
}

type fakeRespSchemaRecorder struct {
	calls   int
	lastKey string
	lastObs []dsctx.ResponseObservation
	err     error
}

func (f *fakeRespSchemaRecorder) RecordResponseObservations(_ context.Context, endpointKey string, obs []dsctx.ResponseObservation) error {
	f.calls++
	f.lastKey = endpointKey
	f.lastObs = obs
	return f.err
}

// 采集接线：携带 response_observations 的记录触发学习写入（透传端点键与观测）；
// 无观测不触发；写入失败不中断采集（错误记日志，不静默也不阻塞）。
func TestCollector_RespSchemaRecording(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "api-events.log")
	cpPath := filepath.Join(dir, "checkpoint")

	withObs := Record{
		RequestID: "r-obs-1", EndpointKey: "GET /v1/users/{id}", Method: "GET", PathTemplate: "/v1/users/{id}",
		IsAPI: true, FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: time.Now().UTC(),
		ResponseObservations: []dsctx.ResponseObservation{{
			StatusCode: 200, ContentType: "application/json", BodySize: 32,
			Fields: map[string]string{"id": "number"}, FieldCount: 1,
		}},
	}
	withoutObs := Record{
		RequestID: "r-obs-2", EndpointKey: "GET /v1/ping", Method: "GET", PathTemplate: "/v1/ping",
		IsAPI: true, FinalAction: "ALLOW", RiskLevel: "NONE", OccurredAt: time.Now().UTC(),
	}
	writeLines(t, logPath, []string{mustJSON(t, withObs), mustJSON(t, withoutObs)})

	rec := &fakeRespSchemaRecorder{}
	c := NewCollector(&fakeSaver{}, "test-resp", logPath, cpPath, "node-1")
	c.SetRespSchemaRecorder(rec)
	if _, err := c.CollectOnce(context.Background()); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if rec.calls != 1 || rec.lastKey != "GET /v1/users/{id}" || len(rec.lastObs) != 1 || rec.lastObs[0].Fields["id"] != "number" {
		t.Fatalf("recorder calls=%d key=%s obs=%+v", rec.calls, rec.lastKey, rec.lastObs)
	}

	// 写入失败不中断采集
	writeLines(t, logPath, []string{mustJSON(t, withObs)})
	rec.err = errors.New("db down")
	c2 := NewCollector(&fakeSaver{}, "test-resp-2", logPath, cpPath+"2", "node-1")
	c2.SetRespSchemaRecorder(rec)
	if _, err := c2.CollectOnce(context.Background()); err != nil {
		t.Fatalf("recorder error must not break collect: %v", err)
	}
}

// 解析容忍：response_observations 键缺失/为空均为零值，不视为坏行。
func TestParseRecordLine_ResponseObservationsOptional(t *testing.T) {
	rec, err := parseRecordLine([]byte(`{"request_id":"r-1","endpoint_key":"GET /v1/x"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.ResponseObservations != nil {
		t.Fatalf("missing key must be nil, got %+v", rec.ResponseObservations)
	}
	rec, err = parseRecordLine([]byte(`{"request_id":"r-1","response_observations":[{"status_code":404,"fields":{"error":"string"},"field_count":1}]}`))
	if err != nil {
		t.Fatalf("parse with obs: %v", err)
	}
	if len(rec.ResponseObservations) != 1 || rec.ResponseObservations[0].StatusCode != 404 {
		t.Fatalf("obs parsed = %+v", rec.ResponseObservations)
	}
}
