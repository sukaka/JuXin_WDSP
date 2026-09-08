// handler_runtime_test.go 阶段3 第二批接口（/apm/runtime）参数校验、过滤器透传、
// 降级负载与权限注册测试（httptest + fakeRepo，不依赖数据库/ClickHouse）。
package apm

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestListRuntimeParams 参数校验：service/instance_id 长度上限、窗口 24h 上限 → 400；
// 缺省窗口 1h；合法过滤透传到 store。
func TestListRuntimeParams(t *testing.T) {
	repo := &fakeRepo{}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.runtime.read")

	// 缺省：窗口 1h、无过滤；fakeRepo 降级负载原样透出（agentless + note + 空数组）
	rr := doGet(t, mux, "/api/v1/apm/runtime", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	if repo.runtimeFilter == nil {
		t.Fatal("store not called")
	}
	if d := repo.runtimeFilter.End.Sub(repo.runtimeFilter.Start); d != time.Hour {
		t.Errorf("default window = %v, want 1h", d)
	}
	data := dataOf(t, rr)
	if data["data_source"] != "agentless" || data["note"] == "" {
		t.Errorf("degraded payload = %v", data)
	}
	instances, ok := data["instances"].([]interface{})
	if !ok || instances == nil {
		t.Errorf("instances must be an array, got %v", data["instances"])
	}

	// 合法组合透传
	rr = doGet(t, mux, "/api/v1/apm/runtime", url.Values{
		"service": {"order-svc"}, "instance_id": {"host-a-4321"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	f := repo.runtimeFilter
	if f.Service != "order-svc" || f.InstanceID != "host-a-4321" {
		t.Errorf("filter = %+v", f)
	}

	// 非法参数 → 400
	now := time.Now().UTC()
	cases := []struct {
		name  string
		query url.Values
	}{
		{"service too long", url.Values{"service": {strings.Repeat("x", 129)}}},
		{"instance_id too long", url.Values{"instance_id": {strings.Repeat("x", 129)}}},
		{"window over 24h", url.Values{
			"start_time": {now.Add(-25 * time.Hour).Format(time.RFC3339)},
			"end_time":   {now.Format(time.RFC3339)},
		}},
		{"bad start_time", url.Values{"start_time": {"not-a-time"}}},
		{"start not before end", url.Values{
			"start_time": {now.Format(time.RFC3339)},
			"end_time":   {now.Add(-time.Hour).Format(time.RFC3339)},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := doGet(t, mux, "/api/v1/apm/runtime", c.query)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400, body: %s", rr.Code, rr.Body.String())
			}
		})
	}
}

// TestListRuntimePayload 正常负载结构：instances/metrics/points 合同字段齐备
// （前端并行开发合同：{data_source, instances:[{instance_id, service_name,
// metrics:[{name, unit, description, latest_value, points:[{ts, value}]}]}], note}）。
func TestListRuntimePayload(t *testing.T) {
	ts := time.Date(2026, 8, 30, 11, 30, 0, 0, time.UTC)
	repo := &fakeRepo{runtime: &RuntimeData{
		DataSource: dataSourceOTel,
		Note:       runtimeNormalNote,
		Instances: []RuntimeInstance{{
			InstanceID: "host-a-1", ServiceName: "jiuzhang-server",
			Metrics: []RuntimeMetric{{
				Name: "go.goroutine.count", Unit: "{goroutine}",
				Description: "Count of live goroutines.（来源 scope: go.opentelemetry.io/contrib/instrumentation/runtime）",
				LatestValue: 42,
				Points:      []RuntimePoint{{Ts: ts, Value: 40}, {Ts: ts.Add(18 * time.Second), Value: 42}},
			}},
		}},
	}}
	mux := newTestMux(NewHandler(repo, fakeSettings{}, 10*time.Minute), "apm.runtime.read")

	rr := doGet(t, mux, "/api/v1/apm/runtime", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body: %s", rr.Code, rr.Body.String())
	}
	data := dataOf(t, rr)
	if data["data_source"] != "otel" || data["note"] == "" {
		t.Errorf("payload header = %v", data)
	}
	instances := data["instances"].([]interface{})
	if len(instances) != 1 {
		t.Fatalf("instances = %v", data["instances"])
	}
	inst := instances[0].(map[string]interface{})
	if inst["instance_id"] != "host-a-1" || inst["service_name"] != "jiuzhang-server" {
		t.Errorf("instance = %v", inst)
	}
	metrics := inst["metrics"].([]interface{})
	if len(metrics) != 1 {
		t.Fatalf("metrics = %v", inst["metrics"])
	}
	m := metrics[0].(map[string]interface{})
	for _, k := range []string{"name", "unit", "description", "latest_value", "points"} {
		if _, ok := m[k]; !ok {
			t.Errorf("metric missing key %q: %v", k, m)
		}
	}
	points := m["points"].([]interface{})
	if len(points) != 2 {
		t.Fatalf("points = %v", m["points"])
	}
	p := points[0].(map[string]interface{})
	if p["ts"] == "" || p["value"] != 40.0 {
		t.Errorf("point = %v", p)
	}
}
