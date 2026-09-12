// G2 镜像来源装配与发送路径测试：v2 唯一线格式（不降级误标）、未协商丢弃计数、
// invalid_records 索引隔离、磁盘缓存 'M' 标签与补传。
package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jiuzhang-waf/wdsp-agent/internal/buffer"
	"github.com/jiuzhang-waf/wdsp-agent/internal/config"
	"github.com/jiuzhang-waf/wdsp-agent/internal/events"
)

func mirrorV2Record(uri string) events.HTTPRecordV2 {
	return events.NewHTTPRecordV2("a1", p1Record(uri), events.SourceRef{
		Type: events.SourceNginxMirror, Instance: "nginx-a", Epoch: 1788250000,
		RequestOnly: true,
	})
}

// 镜像记录入队：v2rec 随队列项传递，与 v1 记录共享字节预算。
func TestMirrorRecordQueueing(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	a.httpQ = make(chan httpQItem, 4)
	rec := mirrorV2Record("/api/m")
	a.onMirrorRecord(rec)
	item := <-a.httpQ
	if item.v2rec == nil || item.v2rec.SourceType != events.SourceNginxMirror {
		t.Fatalf("v2rec 未随队列传递: %+v", item)
	}
	if item.v2rec.AssociationReason != events.AssocReasonSourceRequestOnly {
		t.Fatalf("association_reason=%q", item.v2rec.AssociationReason)
	}
	if a.httpQBytes.Load() <= 0 {
		t.Fatal("字节预算应记账")
	}
}

// v2 线格式上行：schema_version=2 包络 + source_type=NGINX_MIRROR 如实标注。
func TestSendMirrorBatchV2Wire(t *testing.T) {
	var got events.HTTPRequestV2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("解析: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(got.Records)})
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	a.httpV2.Store(true)
	a.sendMirrorBatch([]events.HTTPRecordV2{mirrorV2Record("/m1"), mirrorV2Record("/m2")})
	if got.SchemaVersion != events.HTTPRecordSchemaVersion {
		t.Fatalf("schema_version=%d", got.SchemaVersion)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records=%d", len(got.Records))
	}
	for _, rec := range got.Records {
		if rec.SourceType != events.SourceNginxMirror || rec.SourceInstance != "nginx-a" {
			t.Fatalf("来源标注错误: %s/%s", rec.SourceType, rec.SourceInstance)
		}
		if rec.Response != nil || rec.ResponseTS != nil || rec.LatencyMS != nil {
			t.Fatal("单向源 response/response_ts/latency_ms 必须恒 null")
		}
	}
	if a.metrics.Accepted.Load() != 2 {
		t.Fatalf("accepted=%d", a.metrics.Accepted.Load())
	}
}

// 未协商 v2：丢弃计数（mirror_v2_not_negotiated），不降级 v1、不向服务端发请求。
func TestSendMirrorBatchNotNegotiated(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL) // httpV2 缺省 false（未协商）
	a.sendMirrorBatch([]events.HTTPRecordV2{mirrorV2Record("/m1")})
	if calls.Load() != 0 {
		t.Fatal("未协商不得发出请求")
	}
	if a.metrics.dropReasonsSnapshot()[DropReasonMirrorV2NotNegotiated] != 1 {
		t.Fatalf("应计数 mirror_v2_not_negotiated: %v", a.metrics.dropReasonsSnapshot())
	}
}

// 永久非法：按 invalid_records 索引隔离，剩余重发一次。
func TestSendMirrorBatchInvalidIsolation(t *testing.T) {
	var accepted []string
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req events.HTTPRequestV2
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("解析: %v", err)
		}
		for i, rec := range req.Records {
			if strings.Contains(rec.Request.URI, "/poison") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error":           map[string]string{"code": "INVALID_ARGUMENT", "message": "bad"},
					"invalid_records": []events.InvalidRecord{{Index: i, Reason: "records[i]: 非法"}},
				})
				return
			}
		}
		for _, rec := range req.Records {
			accepted = append(accepted, rec.Request.URI)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(req.Records)})
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	a.httpV2.Store(true)
	a.sendMirrorBatch([]events.HTTPRecordV2{
		mirrorV2Record("/ok1"), mirrorV2Record("/poison"), mirrorV2Record("/ok2"),
	})
	if len(accepted) != 2 {
		t.Fatalf("合法记录应重发接受: %v", accepted)
	}
	if a.metrics.dropReasonsSnapshot()[DropReasonPermanentInvalid] != 1 {
		t.Fatalf("permanent_invalid 应计数 1: %v", a.metrics.dropReasonsSnapshot())
	}
	if n := calls.Load(); n != 2 {
		t.Fatalf("请求数应为 2（原批+隔离重发）: %d", n)
	}
}

// 磁盘缓存 'M' 标签保留完整 v2 字段，补传经 v2 线格式上行（不降级）。
func TestMirrorSpoolAndReplay(t *testing.T) {
	var got events.HTTPRequestV2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("解析: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(events.HTTPV2Response{AcceptedCount: len(got.Records)})
	}))
	defer srv.Close()
	a := newTestAgent(t, srv.URL)
	buf, err := buffer.Open(t.TempDir(), 0, 0, time.Minute, true)
	if err != nil {
		t.Fatal(err)
	}
	a.buf = buf
	a.httpV2.Store(true)

	rec := mirrorV2Record("/api/spooled")
	a.bufferMirror([]events.HTTPRecordV2{rec})
	if a.buf.Bytes() == 0 {
		t.Fatal("镜像记录应落缓存")
	}
	a.online.Store(true)
	a.replayBuffer()
	if got.SchemaVersion != events.HTTPRecordSchemaVersion || len(got.Records) != 1 {
		t.Fatalf("补传包络错误: %+v", got)
	}
	if got.Records[0].SourceType != events.SourceNginxMirror ||
		got.Records[0].AssociationReason != events.AssocReasonSourceRequestOnly {
		t.Fatalf("补传记录 v2 字段丢失: %+v", got.Records[0])
	}
	if a.buf.Bytes() != 0 {
		t.Fatalf("补传成功后缓存应清空: %d", a.buf.Bytes())
	}
}

// 接收器装配：默认关闭；配置非法 Fail-Open（nil + 日志，不影响进程）。
func TestNewMirrorReceiverWiring(t *testing.T) {
	a := newTestAgent(t, "http://127.0.0.1:1")
	if a.newMirrorReceiver() != nil {
		t.Fatal("默认关闭")
	}
	a.cfg.Mirror = config.MirrorConfig{
		Enabled: true, SocketPath: filepath.Join(t.TempDir(), "m.sock"),
		SourceInstance: "nginx-a", // 缺 InstanceToken
	}
	if a.newMirrorReceiver() != nil {
		t.Fatal("缺 instance_token 必须拒绝")
	}
	a.cfg.Mirror.InstanceToken = "tok"
	if a.newMirrorReceiver() == nil {
		t.Fatal("合法配置应创建接收器")
	}
}
