// http_events_test.go Phase 3 单测：HTTP 记录校验矩阵 / 记录→CopyFrom 行转换
// （response null、截断标记、ts 精度）/ 策略 masking 校验矩阵 / 保留清理 sweeper。
package agents

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

// validHTTPRecord 合法 HTTP 记录（含响应）。
func validHTTPRecord() HTTPRecord {
	respTS := 1788256800.156
	latency := int64(33)
	return HTTPRecord{
		FlowID:     "a1-10.1.1.10-51234-10.1.2.20-8080-1788256800",
		RequestTS:  1788256800.123,
		ResponseTS: &respTS,
		LatencyMS:  &latency,
		SrcIP:      "10.1.1.10", SrcPort: 51234, DstIP: "10.1.2.20", DstPort: 8080,
		Direction: "ingress", TLSVisibility: "PLAINTEXT",
		Request: HTTPRequestPart{
			Method: "POST", Scheme: "http", Host: "api.example.com", URI: "/api/login",
			HTTPBodyFields: HTTPBodyFields{
				Headers:          map[string]string{"content-type": "application/json", "authorization": "********"},
				Body:             `{"user":"alice","password":"********"}`,
				OriginalBodySize: 42,
			},
		},
		Response: &HTTPResponsePart{
			Status: 200,
			HTTPBodyFields: HTTPBodyFields{
				Headers:          map[string]string{"content-type": "application/json", "set-cookie": "********"},
				Body:             `{"token":"********"}`,
				OriginalBodySize: 31,
			},
		},
	}
}

// TestHTTPRecordsValidate 批量校验矩阵（契约 §3：≤100 条、必填字段、枚举、
// response 与 response_ts/latency_ms 同步 null）。
func TestHTTPRecordsValidate(t *testing.T) {
	t.Run("非法 Kubernetes 元数据整段忽略", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.K8s = &K8sMetadata{Pod: strings.Repeat("x", 254), Side: "server"}
		req := &HTTPRecordsRequest{Records: []HTTPRecord{rec}}
		if err := req.Validate(); err != nil {
			t.Fatalf("事件不应被拒绝: %v", err)
		}
		if req.Records[0].K8s != nil {
			t.Fatalf("invalid k8s should be discarded: %#v", req.Records[0].K8s)
		}
	})
	t.Run("空批量拒绝", func(t *testing.T) {
		if err := (&HTTPRecordsRequest{}).Validate(); err == nil {
			t.Error("应拒绝空 records")
		}
	})
	t.Run("契约示例记录放行", func(t *testing.T) {
		if err := (&HTTPRecordsRequest{Records: []HTTPRecord{validHTTPRecord()}}).Validate(); err != nil {
			t.Errorf("合法记录被拒绝: %v", err)
		}
	})
	t.Run("100 条上限内放行", func(t *testing.T) {
		recs := make([]HTTPRecord, MaxHTTPRecordsPerBatch)
		for i := range recs {
			recs[i] = validHTTPRecord()
		}
		if err := (&HTTPRecordsRequest{Records: recs}).Validate(); err != nil {
			t.Errorf("100 条应放行: %v", err)
		}
	})
	t.Run("101 条拒绝", func(t *testing.T) {
		recs := make([]HTTPRecord, MaxHTTPRecordsPerBatch+1)
		for i := range recs {
			recs[i] = validHTTPRecord()
		}
		if err := (&HTTPRecordsRequest{Records: recs}).Validate(); err == nil {
			t.Error("超过 100 条应拒绝")
		}
	})
	t.Run("response 为 null（响应未捕获）放行", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Response = nil
		rec.ResponseTS = nil
		rec.LatencyMS = nil
		if err := (&HTTPRecordsRequest{Records: []HTTPRecord{rec}}).Validate(); err != nil {
			t.Errorf("response null 应放行: %v", err)
		}
	})

	bad := []struct {
		name   string
		mutate func(*HTTPRecord)
	}{
		{"flow_id 缺失", func(r *HTTPRecord) { r.FlowID = "" }},
		{"request_ts 非正", func(r *HTTPRecord) { r.RequestTS = 0 }},
		{"request_ts NaN", func(r *HTTPRecord) { r.RequestTS = math.NaN() }},
		{"src_ip 非法", func(r *HTTPRecord) { r.SrcIP = "x" }},
		{"dst_ip 缺失", func(r *HTTPRecord) { r.DstIP = "" }},
		{"端口越界", func(r *HTTPRecord) { r.SrcPort = 65536 }},
		{"direction 枚举外", func(r *HTTPRecord) { r.Direction = "sideways" }},
		{"direction 缺失", func(r *HTTPRecord) { r.Direction = "" }},
		{"tls_visibility 密文（契约 §3 密文流不产生 HTTP 记录）", func(r *HTTPRecord) { r.TLSVisibility = "ENCRYPTED" }},
		{"method 缺失", func(r *HTTPRecord) { r.Request.Method = "" }},
		{"method 含空格", func(r *HTTPRecord) { r.Request.Method = "GE T" }},
		{"scheme 枚举外", func(r *HTTPRecord) { r.Request.Scheme = "ftp" }},
		{"host 缺失", func(r *HTTPRecord) { r.Request.Host = "" }},
		{"uri 缺失", func(r *HTTPRecord) { r.Request.URI = "" }},
		{"uri 超 2048 字节（索引行宽安全）", func(r *HTTPRecord) { r.Request.URI = "/" + strings.Repeat("a", 2048) }},
		{"response null 但携带 response_ts", func(r *HTTPRecord) {
			r.Response = nil
			ts := 1788256800.2
			r.ResponseTS = &ts
			r.LatencyMS = nil
		}},
		{"response 存在但缺 latency_ms", func(r *HTTPRecord) { r.LatencyMS = nil }},
		{"response_ts 早于 request_ts", func(r *HTTPRecord) { ts := r.RequestTS - 1; r.ResponseTS = &ts }},
		{"latency_ms 为负", func(r *HTTPRecord) { ms := int64(-1); r.LatencyMS = &ms }},
		{"latency_ms 超 int32", func(r *HTTPRecord) { ms := int64(math.MaxInt32) + 1; r.LatencyMS = &ms }},
		{"status 越界", func(r *HTTPRecord) { r.Response.Status = 42 }},
		{"body_skipped_reason 枚举外", func(r *HTTPRecord) { r.Request.BodySkippedReason = "too_large" }},
		{"original_body_size 为负", func(r *HTTPRecord) { r.Request.OriginalBodySize = -1 }},
		{"headers 过多", func(r *HTTPRecord) {
			h := map[string]string{}
			for i := 0; i < maxHTTPHeadersPerMessage+1; i++ {
				h[string(rune('a'+i%26))+strings.Repeat("x", i)] = "v"
			}
			r.Request.Headers = h
		}},
		{"header 名含控制字符", func(r *HTTPRecord) { r.Request.Headers = map[string]string{"bad\r\nname": "v"} }},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			rec := validHTTPRecord()
			c.mutate(&rec)
			if err := (&HTTPRecordsRequest{Records: []HTTPRecord{rec}}).Validate(); err == nil {
				t.Error("应拒绝非法记录")
			}
		})
	}

	t.Run("method/scheme 规范化", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Request.Method = "post"
		rec.Request.Scheme = "HTTP"
		req := &HTTPRecordsRequest{Records: []HTTPRecord{rec}}
		if err := req.Validate(); err != nil {
			t.Fatalf("校验失败: %v", err)
		}
		got := req.Records[0]
		if got.Request.Method != "POST" || got.Request.Scheme != "http" {
			t.Errorf("规范化失败: method=%q scheme=%q", got.Request.Method, got.Request.Scheme)
		}
	})
}

// TestHTTPEventCopyRow 记录→CopyFrom 行转换：response null 同步 nil、截断标记与
// 原始长度透传、ts 毫秒精度、headers jsonb。
func TestHTTPEventCopyRow(t *testing.T) {
	agentID := uuid.New()

	t.Run("response null 同步 nil", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Response = nil
		rec.ResponseTS = nil
		rec.LatencyMS = nil
		rec.Request.Body = "" // 未采集 body → NULL
		row := httpEventCopyRow(agentID, &rec)
		if row[0] != agentID || row[1] != rec.FlowID {
			t.Errorf("agent_id/flow_id 异常: %v %v", row[0], row[1])
		}
		// 注意：CopyFrom 行为 interface{} 包裹的类型化 nil（pgx 落 NULL），断言须先类型展开
		if row[3].(*int) != nil {
			t.Errorf("latency_ms 应为 nil: %v", row[3])
		}
		if row[14].(*int) != nil {
			t.Errorf("status 应为 nil: %v", row[14])
		}
		if row[16].([]byte) != nil || row[18].(*string) != nil {
			t.Errorf("response_headers/body 应为 nil: %v %v", row[16], row[18])
		}
		if row[17].(*string) != nil {
			t.Errorf("空 request body 应为 nil: %v", row[17])
		}
		if row[20] != false || row[22] != int64(0) {
			t.Errorf("响应侧截断/原始长度应为零值: %v %v", row[20], row[22])
		}
		if got := string(row[15].([]byte)); got != `{"authorization":"********","content-type":"application/json"}` {
			t.Errorf("request_headers jsonb 异常: %s", got)
		}
	})

	t.Run("response 完整 + 截断标记", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Response.BodyTruncated = true
		rec.Response.OriginalBodySize = 300000
		row := httpEventCopyRow(agentID, &rec)
		if *row[3].(*int) != 33 {
			t.Errorf("latency_ms = %v, want 33", row[3])
		}
		if *row[14].(*int) != 200 {
			t.Errorf("status = %v, want 200", row[14])
		}
		if row[20] != true || row[22] != int64(300000) {
			t.Errorf("resp 截断/原始长度 = %v/%v", row[20], row[22])
		}
		if row[19] != false || row[21] != int64(42) {
			t.Errorf("req 截断/原始长度 = %v/%v", row[19], row[21])
		}
		if *row[18].(*string) != `{"token":"********"}` {
			t.Errorf("response_body 异常: %v", row[18])
		}
	})

	t.Run("ts 毫秒精度", func(t *testing.T) {
		rec := validHTTPRecord()
		row := httpEventCopyRow(agentID, &rec)
		ts := row[2].(time.Time)
		want := time.Unix(1788256800, 123000000).UTC()
		if d := ts.Sub(want); d < -time.Millisecond || d > time.Millisecond {
			t.Errorf("ts = %v, want ≈%v", ts, want)
		}
	})

	t.Run("nil headers 落 {}", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Request.Headers = nil
		row := httpEventCopyRow(agentID, &rec)
		if got := string(row[15].([]byte)); got != `{}` {
			t.Errorf("nil headers 应落 {}: %s", got)
		}
	})

	t.Run("skipped_reason 透传（000113）", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Request.Body = ""
		rec.Request.BodySkippedReason = SkipReasonContentType
		rec.Response.Body = ""
		rec.Response.BodySkippedReason = SkipReasonEncoding
		row := httpEventCopyRow(agentID, &rec)
		if row[23] != "content_type" || row[24] != "encoding" {
			t.Errorf("skipped_reason = (%v, %v), want (content_type, encoding)", row[23], row[24])
		}
	})

	t.Run("response null 时 resp_skipped_reason 落空串", func(t *testing.T) {
		rec := validHTTPRecord()
		rec.Response = nil
		rec.ResponseTS = nil
		rec.LatencyMS = nil
		row := httpEventCopyRow(agentID, &rec)
		if row[24] != "" {
			t.Errorf("resp_skipped_reason 应为空串: %v", row[24])
		}
	})
}

// TestPolicyMaskingValidate masking 段校验矩阵（Phase 3 契约 §5/§7：
// 缺省合法；mode 非法或 names 非数组 → PUT 400）。
func TestPolicyMaskingValidate(t *testing.T) {
	mutate := func(fn func(map[string]interface{})) json.RawMessage {
		var m map[string]interface{}
		if err := json.Unmarshal(validPolicyJSON(), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		raw, _ := json.Marshal(m)
		return raw
	}

	t.Run("无 masking 段（既有策略）合法", func(t *testing.T) {
		if err := ValidatePolicyConfigJSON(validPolicyJSON()); err != nil {
			t.Errorf("缺省 masking 被拒绝: %v", err)
		}
	})
	t.Run("契约 §5 默认示例合法", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{
				"headers": map[string]interface{}{"mode": "MASK", "names": []string{"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}},
				"params":  map[string]interface{}{"mode": "MASK", "names": []string{"password", "passwd", "pwd", "token", "access_token", "refresh_token", "secret", "api_key", "apikey"}},
			}
		})
		if err := ValidatePolicyConfigJSON(raw); err != nil {
			t.Errorf("契约默认示例被拒绝: %v", err)
		}
	})
	t.Run("masking 分组缺省合法", func(t *testing.T) {
		raw := mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{
				"headers": map[string]interface{}{"mode": "HASH"},
			}
		})
		if err := ValidatePolicyConfigJSON(raw); err != nil {
			t.Errorf("params 缺省被拒绝: %v", err)
		}
	})
	t.Run("mode 全部枚举合法", func(t *testing.T) {
		for _, mode := range []string{"NONE", "MASK", "HASH", "DROP"} {
			raw := mutate(func(m map[string]interface{}) {
				m["masking"] = map[string]interface{}{
					"headers": map[string]interface{}{"mode": mode, "names": []string{"authorization"}},
				}
			})
			if err := ValidatePolicyConfigJSON(raw); err != nil {
				t.Errorf("mode=%s 被拒绝: %v", mode, err)
			}
		}
	})

	bad := []struct {
		name string
		raw  json.RawMessage
	}{
		{"headers.mode 非法", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"headers": map[string]interface{}{"mode": "ENCRYPT"}}
		})},
		{"headers.mode 缺失", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"headers": map[string]interface{}{"names": []string{"a"}}}
		})},
		{"params.mode 非法", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"params": map[string]interface{}{"mode": "mask"}}
		})},
		{"names 非数组", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"headers": map[string]interface{}{"mode": "MASK", "names": "authorization"}}
		})},
		{"names 含空名", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"headers": map[string]interface{}{"mode": "MASK", "names": []string{"authorization", " "}}}
		})},
		{"masking 未知字段", mutate(func(m map[string]interface{}) {
			m["masking"] = map[string]interface{}{"cookies": map[string]interface{}{"mode": "MASK"}}
		})},
		{"masking 非对象", mutate(func(m map[string]interface{}) {
			m["masking"] = "MASK"
		})},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidatePolicyConfigJSON(c.raw); err == nil {
				t.Error("应拒绝非法 masking 段")
			}
		})
	}
}

// ---------- 保留清理 sweeper ----------

// fakeHTTPCleaner HTTPEventCleaner 内存实现。
type fakeHTTPCleaner struct {
	before         time.Time
	n              int64
	err            error
	overrideBefore time.Time
	overrideN      int64
	overrideErr    error
}

func (f *fakeHTTPCleaner) DeleteExpiredHTTPEvents(_ context.Context, before time.Time) (int64, error) {
	f.before = before
	return f.n, f.err
}

func (f *fakeHTTPCleaner) DeleteExpiredCaptureOverrides(_ context.Context, before time.Time) (int64, error) {
	f.overrideBefore = before
	return f.overrideN, f.overrideErr
}

// TestHTTPEventSweeper 清理逻辑：cutoff = now-7d（契约 §6）；删除行数透传；错误不静默。
func TestHTTPEventSweeper(t *testing.T) {
	fixed := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	t.Run("cutoff 为 7 天前", func(t *testing.T) {
		cl := &fakeHTTPCleaner{n: 42}
		s := NewHTTPEventSweeper(cl).SetClock(func() time.Time { return fixed })
		n, err := s.SweepOnce(context.Background())
		if err != nil {
			t.Fatalf("SweepOnce: %v", err)
		}
		if n != 42 {
			t.Errorf("删除行数 = %d, want 42", n)
		}
		want := fixed.Add(-HTTPEventRetention)
		if !cl.before.Equal(want) {
			t.Errorf("cutoff = %v, want %v", cl.before, want)
		}
		if HTTPEventRetention != 7*24*time.Hour {
			t.Errorf("retention = %v, want 7d（契约 §6）", HTTPEventRetention)
		}
	})
	t.Run("删除失败如实返回", func(t *testing.T) {
		cl := &fakeHTTPCleaner{err: errors.New("db down")}
		s := NewHTTPEventSweeper(cl).SetClock(func() time.Time { return fixed })
		if _, err := s.SweepOnce(context.Background()); err == nil {
			t.Error("错误不得静默吞掉")
		}
	})
	t.Run("分区表跳过 HTTP 事件逐行删除时仍执行定向采集规则清理", func(t *testing.T) {
		cl := &fakeHTTPCleaner{n: 0, overrideN: 5}
		s := NewHTTPEventSweeper(cl).SetClock(func() time.Time { return fixed })
		n, err := s.SweepOnce(context.Background())
		if err != nil {
			t.Fatalf("SweepOnce: %v", err)
		}
		if n != 5 {
			t.Fatalf("total deleted = %d, want 5 (override cleanup must still run)", n)
		}
		wantOverrideBefore := fixed.Add(-CaptureOverrideRetention)
		if !cl.overrideBefore.Equal(wantOverrideBefore) {
			t.Fatalf("overrideBefore = %v, want %v", cl.overrideBefore, wantOverrideBefore)
		}
	})
}

func TestHTTPRecordV1BodyNulRejected(t *testing.T) {
	req := HTTPRecordsRequest{Records: []HTTPRecord{validHTTPRecord()}}
	req.Records[0].Request.Body = "hello\x00world"
	if err := req.Validate(); err == nil {
		t.Fatal("v1 request.body containing NUL must fail validation (400)")
	}
	req2 := HTTPRecordsRequest{Records: []HTTPRecord{validHTTPRecord()}}
	req2.Records[0].Response.Body = "ok\x00bad"
	if err := req2.Validate(); err == nil {
		t.Fatal("v1 response.body containing NUL must fail validation (400)")
	}
}

func TestInsertHTTPEventV2SQLIncludesPartitionKeyInOnConflict(t *testing.T) {
	sql := buildInsertHTTPEventV2SQL()
	if !strings.Contains(sql, "ON CONFLICT (agent_id, event_id, ts) WHERE event_id IS NOT NULL DO NOTHING") {
		t.Fatalf("v2 insert SQL must include ts in ON CONFLICT: %s", sql)
	}
	if strings.Contains(sql, "ON CONFLICT (agent_id, event_id) ") {
		t.Fatalf("v2 insert SQL must not use non-partitioned ON CONFLICT: %s", sql)
	}
}
