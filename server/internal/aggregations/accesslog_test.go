package aggregations

import (
	"encoding/json"
	"testing"
	"time"
)

func TestMinuteBucketAdd(t *testing.T) {
	b := newMinuteBucket()
	b.add("shop", 200, 0.003)
	b.add("shop", 200, 0.02)
	b.add("shop", 403, 0.001)
	b.add("unknown", 500, 1.2)
	rows := b.rows()

	var req2xx, req403, req5xx, dur *AggRow
	for i := range rows {
		r := &rows[i]
		switch {
		case r.Metric == "http_requests_total" && r.Labels["status_class"] == "2xx" && r.Labels["app"] == "shop":
			req2xx = r
		case r.Metric == "http_requests_total" && r.Labels["status_class"] == "4xx":
			req403 = r
		case r.Metric == "http_requests_total" && r.Labels["status_class"] == "5xx":
			req5xx = r
		case r.Metric == "http_request_duration_ms" && r.Labels["app"] == "shop":
			dur = r
		}
	}
	if req2xx == nil || req2xx.Value != 2 {
		t.Errorf("2xx count: %+v", req2xx)
	}
	if req403 == nil || req403.Value != 1 {
		t.Errorf("4xx count: %+v", req403)
	}
	if req5xx == nil || req5xx.Value != 1 || req5xx.Labels["app"] != "unknown" {
		t.Errorf("5xx count: %+v", req5xx)
	}
	if dur == nil || dur.Value != 3 {
		t.Fatalf("duration total: %+v", dur)
	}
	buckets, _ := dur.Extra["buckets"].([]int)
	if len(buckets) != 11 || buckets[0] != 2 || buckets[2] != 1 || buckets[9] != 0 {
		t.Errorf("duration buckets: %v", buckets)
	}
}

func TestAccessLogEntryParse(t *testing.T) {
	line := `{"level":"info","ts":1784600000.5,"logger":"http.log.access","request":{"remote_ip":"203.0.113.1","method":"GET","host":"shop.example.com","uri":"/a?x=1","headers":{}},"status":200,"size":123,"duration":0.0045}`
	var e AccessLogEntry
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatal(err)
	}
	if e.Request.Host != "shop.example.com" || e.Status != 200 || e.Duration < 0.004 || e.Duration > 0.005 {
		t.Errorf("parse: %+v", e)
	}
	ts := time.Unix(int64(e.Ts), 0).UTC()
	if ts.Truncate(time.Minute) != time.Unix(1784600000-1784600000%60, 0).UTC() {
		t.Errorf("bucket: %v", ts)
	}
}

func TestStatusClass(t *testing.T) {
	if statusClass(200) != "2xx" || statusClass(404) != "4xx" || statusClass(503) != "5xx" || statusClass(308) != "2xx" {
		t.Error("status class mapping wrong")
	}
}
