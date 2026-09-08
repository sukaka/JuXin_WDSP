// HTTP 事件 v2 构造与线格式测试（契约 WDSP_AGENT_HTTP_EVENT_V2_CONTRACT.md §1/§2：
// 包络 schema_version=2、event_id 稳定生成、headers 数组形态、body_quality 内嵌、
// 来源/协议/关联字段按冻结枚举填充；仅冻结字段不造假值）。
package events

import (
	"encoding/json"
	"strings"
	"testing"
)

func v2TestRecord(withResp bool) HTTPRecord {
	rec := HTTPRecord{
		FlowID:    "a1-1.1.1.1-80-2.2.2.2-8080-1788256800",
		RequestTS: 1788256800.123,
		SrcIP:     "1.1.1.1", SrcPort: 80, DstIP: "2.2.2.2", DstPort: 8080,
		Direction:     "ingress",
		TLSVisibility: VisibilityPlaintext,
		Request: &HTTPMessage{
			Method: "POST", Scheme: "http", Host: "h", URI: "/api?token=********",
			Headers: map[string]string{"authorization": "********"},
			Body:    `{"password":"********","q":"x"}`,
		},
	}
	if withResp {
		ts := 1788256800.456
		lat := int64(333)
		rec.ResponseTS = &ts
		rec.LatencyMs = &lat
		rec.Response = &HTTPMessage{Status: 200, BodyTruncated: true, OriginalBodySize: 4096, Body: "{}"}
	}
	return rec
}

// event_id 稳定：同记录多次生成一致；重试/重启语义不变；不同记录不同 ID。
func TestStableEventID(t *testing.T) {
	rec := v2TestRecord(true)
	id1 := StableEventID("a1", rec)
	id2 := StableEventID("a1", rec)
	if id1 != id2 {
		t.Fatal("同记录 event_id 应稳定")
	}
	if !strings.HasPrefix(id1, "ev-") || len(id1) != 3+64 {
		t.Fatalf("event_id 形态错误: %q", id1)
	}
	other := v2TestRecord(true)
	other.RequestTS += 0.001
	if StableEventID("a1", other) == id1 {
		t.Fatal("不同 request_ts 应产生不同 event_id")
	}
	if StableEventID("a2", rec) == id1 {
		t.Fatal("不同 agent 应产生不同 event_id")
	}
	// 红线：ID 不含敏感正文（hex 摘要，正文变更不影响 ID）
	rec.Request.Body = `{"password":"super-secret-plaintext"}`
	if StableEventID("a1", rec) != id1 {
		t.Fatal("event_id 不应依赖正文内容")
	}
	if strings.Contains(id1, "super-secret") {
		t.Fatal("event_id 泄漏正文")
	}
}

// v2 字段填充与线格式：包络 schema_version=2；记录含 event_id/source/association/
// collection_ts；headers 数组形态；body_quality 内嵌且 original_total_size 语义正确。
func TestNewHTTPRecordV2Complete(t *testing.T) {
	rec := v2TestRecord(true)
	src := SourceRef{Type: SourcePassiveHTTP1, Instance: "sensor-0", Epoch: 1788250000, CapabilitiesVersion: "cap-v1"}
	batch := NewHTTPBatchV2("a1", []HTTPRecord{rec}, src)
	if batch.SchemaVersion != HTTPRecordSchemaVersion || len(batch.Records) != 1 {
		t.Fatalf("包络错误: %+v", batch)
	}
	out := batch.Records[0]
	if out.EventID != StableEventID("a1", rec) {
		t.Fatal("event_id 应为稳定生成值")
	}
	if out.SourceType != SourcePassiveHTTP1 || out.SourceInstance != "sensor-0" || out.SourceEpoch != 1788250000 {
		t.Fatalf("来源字段错误: %+v", out)
	}
	if out.SourceCapabilitiesVersion != "cap-v1" {
		t.Fatalf("source_capabilities_version 错误: %q", out.SourceCapabilitiesVersion)
	}
	if out.ObservedHTTPVersion != HTTPVersion11 {
		t.Fatalf("被动 HTTP/1 观测协议错误: %q", out.ObservedHTTPVersion)
	}
	if out.OriginalHTTPVersion != nil {
		t.Fatal("被动采集原协议不可确认，应为 null")
	}
	if out.AssociationState != AssocComplete || out.AssociationReason != "" {
		t.Fatalf("双向齐全应为 COMPLETE/空 reason: %s/%q", out.AssociationState, out.AssociationReason)
	}
	if out.CaptureStreamID == nil || *out.CaptureStreamID != rec.FlowID {
		t.Fatal("被动源 capture_stream_id 应为 flow_id")
	}
	if out.ApplicationBindingID != nil || out.BindingVersion != nil {
		t.Fatal("被动采集无来源绑定，两字段应同 null")
	}
	if out.CollectionTS != rec.RequestTS {
		t.Fatal("collection_ts 应取来源采集时间")
	}
	if out.Response == nil || !out.Response.BodyQuality.Truncated ||
		out.Response.BodyQuality.OriginalTotalSize == nil || *out.Response.BodyQuality.OriginalTotalSize != 4096 {
		t.Fatalf("响应 body_quality 错误: %+v", out.Response)
	}
	if out.Request.BodyQuality.CapturedBytes != int64(len(rec.Request.Body)) {
		t.Fatalf("请求 body_quality 错误: %+v", out.Request.BodyQuality)
	}
	if out.Request.Headers["authorization"] == nil ||
		len(out.Request.Headers["authorization"]) != 1 || out.Request.Headers["authorization"][0] != "********" {
		t.Fatalf("headers 应为数组形态: %+v", out.Request.Headers)
	}
	// 序列化线格式逐字段对齐契约 §2
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	if env["schema_version"] != float64(2) {
		t.Fatalf("包络 schema_version 应为 2: %v", env["schema_version"])
	}
	recs, _ := env["records"].([]any)
	m, _ := recs[0].(map[string]any)
	for _, k := range []string{"event_id", "flow_id", "request_ts", "response_ts", "latency_ms",
		"collection_ts", "src_ip", "src_port", "direction", "tls_visibility",
		"source_type", "source_instance", "source_epoch", "observed_http_version",
		"association_state", "association_reason", "request", "response", "grpc"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("序列化缺字段 %s", k)
		}
	}
	if _, ok := m["schema_version"]; ok {
		t.Fatal("schema_version 仅在批次包络，记录级不应携带")
	}
	if v, ok := m["original_http_version"]; !ok || v != nil {
		t.Fatal("original_http_version 应显式为 null")
	}
	if v, ok := m["application_binding_id"]; !ok || v != nil {
		t.Fatal("application_binding_id 应显式为 null（与 binding_version 同有同无）")
	}
	if v, ok := m["grpc"]; !ok || v != nil {
		t.Fatal("非 gRPC 流量 grpc 应显式为 null")
	}
	// headers 数组形态 + body_quality 内嵌（original_total_size 字段名）
	req, _ := m["request"].(map[string]any)
	hdrs, _ := req["headers"].(map[string]any)
	if arr, _ := hdrs["authorization"].([]any); len(arr) != 1 {
		t.Fatalf("request.headers 应为数组形态: %v", hdrs)
	}
	bq, _ := req["body_quality"].(map[string]any)
	if bq == nil {
		t.Fatal("request.body_quality 缺失")
	}
	for _, k := range []string{"captured_bytes", "original_total_size", "truncated", "skipped_reason"} {
		if _, ok := bq[k]; !ok {
			t.Fatalf("body_quality 缺字段 %s", k)
		}
	}
	if strings.Contains(string(data), "super-secret") || !strings.Contains(string(data), "********") {
		t.Fatal("序列化应保留脱敏后内容且不出现明文")
	}
}

// 响应缺失 → REQUEST_ONLY/TIMEOUT；单向源 → REQUEST_ONLY/SOURCE_REQUEST_ONLY。
func TestNewHTTPRecordV2Association(t *testing.T) {
	rec := v2TestRecord(false)
	out := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourcePassiveHTTP1})
	if out.AssociationState != AssocRequestOnly || out.AssociationReason != AssocReasonTimeout {
		t.Fatalf("响应缺失: %s/%s", out.AssociationState, out.AssociationReason)
	}
	if out.Response != nil {
		t.Fatal("无响应记录 response 应为 null")
	}
	out2 := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourceNginxMirror, RequestOnly: true})
	if out2.AssociationState != AssocRequestOnly || out2.AssociationReason != AssocReasonSourceRequestOnly {
		t.Fatalf("单向源: %s/%s", out2.AssociationState, out2.AssociationReason)
	}
}

// 原协议仅在可确认时填写；UNKNOWN 按不可确认处理（不以观测值回填）。
func TestNewHTTPRecordV2OriginalVersion(t *testing.T) {
	rec := v2TestRecord(true)
	out := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourceEnvoyTap, OriginalHTTPVersion: HTTPVersion2, ObservedHTTPVersion: HTTPVersion2})
	if out.OriginalHTTPVersion == nil || *out.OriginalHTTPVersion != HTTPVersion2 {
		t.Fatal("可确认原协议应填写")
	}
	out2 := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourceEnvoyTap, OriginalHTTPVersion: HTTPVersionUnknown})
	if out2.OriginalHTTPVersion != nil {
		t.Fatal("UNKNOWN 应为 null")
	}
}

// body_quality 边界：budget_exceeded 转写为 truncated；空报文体 original_total_size=0；
// 跳过重采（content_type）时 captured=0。
func TestNewHTTPRecordV2BodyQuality(t *testing.T) {
	rec := v2TestRecord(true)
	// 批次预算缩减标记（v1 内部词表）→ v2 枚举外，语义即预算截断
	rec.Request.Body = ""
	rec.Request.BodyTruncated = true
	rec.Request.BodySkippedReason = BodySkippedBudgetExceeded
	rec.Request.OriginalBodySize = 4096
	out := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourcePassiveHTTP1})
	q := out.Request.BodyQuality
	if q.SkippedReason != "" || !q.Truncated || q.CapturedBytes != 0 ||
		q.OriginalTotalSize == nil || *q.OriginalTotalSize != 4096 {
		t.Fatalf("budget_exceeded 应转写为 truncated: %+v", q)
	}
	// 确认为空报文体 → original_total_size=0（非 null）
	rec2 := v2TestRecord(true)
	rec2.Request.Body = ""
	rec2.Request.OriginalBodySize = 0
	q2 := NewHTTPRecordV2("a1", rec2, SourceRef{Type: SourcePassiveHTTP1}).Request.BodyQuality
	if q2.OriginalTotalSize == nil || *q2.OriginalTotalSize != 0 {
		t.Fatalf("空报文体 original_total_size 应为 0: %+v", q2)
	}
	// content_type 跳过：captured=0 + skipped_reason 透传
	rec3 := v2TestRecord(true)
	rec3.Request.Body = ""
	rec3.Request.BodySkippedReason = "content_type"
	rec3.Request.OriginalBodySize = 128
	q3 := NewHTTPRecordV2("a1", rec3, SourceRef{Type: SourcePassiveHTTP1}).Request.BodyQuality
	if q3.SkippedReason != "content_type" || q3.CapturedBytes != 0 ||
		q3.OriginalTotalSize == nil || *q3.OriginalTotalSize != 128 {
		t.Fatalf("content_type 跳过: %+v", q3)
	}
}

// 缺省来源实例与观测协议默认值。
func TestNewHTTPRecordV2Defaults(t *testing.T) {
	rec := v2TestRecord(true)
	out := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourcePassiveHTTP1})
	if out.SourceInstance != "default" {
		t.Fatalf("缺省来源实例应为 default: %q", out.SourceInstance)
	}
	if out.ObservedHTTPVersion != HTTPVersion11 {
		t.Fatalf("被动源默认观测协议应为 1.1: %q", out.ObservedHTTPVersion)
	}
	out2 := NewHTTPRecordV2("a1", rec, SourceRef{Type: SourceEnvoyTap})
	if out2.ObservedHTTPVersion != HTTPVersionUnknown {
		t.Fatalf("未知来源默认观测协议应为 UNKNOWN: %q", out2.ObservedHTTPVersion)
	}
	if out.TLSVisibility != VisibilityPlaintext {
		t.Fatalf("tls_visibility 应为 PLAINTEXT: %q", out.TLSVisibility)
	}
}
