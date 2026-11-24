package tests

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/runtimehealth"
	"github.com/jiuzhang-waf/server/internal/upstreams"
)

// TestUpstreamHealthProbeSyncsAppAndUpstreamList 端到端接口与数据库集成测试：
// 验证 runtimehealth 采集器探测 HTTP/HTTPS 源站后：
// 1. 逐源站记录写入 upstream_health_records，且 GET /applications/{id}/upstreams 透出实时健康状态、状态码、耗时与错误；
// 2. 应用级健康状态自动汇总回写 applications.health_status（HEALTHY / DEGRADED / UNHEALTHY / UNKNOWN），且不递增乐观锁 version；
// 3. 关闭健康检查后，下一轮采集把应用健康状态复位为 UNKNOWN，源站恢复为 DISABLED。
func TestUpstreamHealthProbeSyncsAppAndUpstreamList(t *testing.T) {
	env := setupTestEnv(t)
	env.createUserDirect(t, "ops_health_sync", "OpsHealth@2026!", "SECURITY_ADMIN")
	cookies, csrf := env.login(t, "ops_health_sync", "OpsHealth@2026!")

	suffix := strings.ReplaceAll(uuid.NewString()[:8], "-", "")
	resp := env.post(t, "/api/v1/applications",
		fmt.Sprintf(`{"code":"health-%s","name":"官网健康测试","protection_mode":"PROTECT"}`, suffix), cookies, csrf)
	var appRes apiResp
	readJSON(t, resp, &appRes)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create app status=%d", resp.StatusCode)
	}
	appID, _ := appRes.Data["id"].(string)

	// 启用应用（仅 ACTIVE 非镜像应用纳入源站健康探测）
	enResp := env.post(t, fmt.Sprintf("/api/v1/applications/%s/enable", appID), `{}`, cookies, csrf)
	enResp.Body.Close()
	if enResp.StatusCode != http.StatusOK {
		t.Fatalf("enable app status=%d", enResp.StatusCode)
	}

	// 记录启用后的版本号，后续健康同步不得递增该版本号
	getApp := func() (healthStatus string, version float64) {
		r := env.get(t, fmt.Sprintf("/api/v1/applications/%s", appID), cookies)
		defer r.Body.Close()
		var out apiResp
		readJSON(t, r, &out)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("get app status=%d", r.StatusCode)
		}
		hs, _ := out.Data["health_status"].(string)
		ver, _ := out.Data["version"].(float64)
		return hs, ver
	}
	initHealth, initVersion := getApp()
	if initHealth != "UNKNOWN" {
		t.Fatalf("初始应用健康状态应为 UNKNOWN，got %q", initHealth)
	}

	// 添加 3 个源站：HTTP 启用检查、HTTPS 启用检查、HTTP 关闭检查
	addUpstream := func(body string) (string, float64) {
		r := env.post(t, fmt.Sprintf("/api/v1/applications/%s/upstreams", appID), body, cookies, csrf)
		defer r.Body.Close()
		var out apiResp
		readJSON(t, r, &out)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("add upstream status=%d body=%+v", r.StatusCode, out)
		}
		id, _ := out.Data["id"].(string)
		ver, _ := out.Data["version"].(float64)
		return id, ver
	}
	uHTTP, vHTTP := addUpstream(`{"name":"http-origin","scheme":"http","host":"10.10.0.1","port":80,"health_check_enabled":true,"health_check_path":"/news","health_check_method":"GET","expected_status_codes":"200-299"}`)
	uHTTPS, vHTTPS := addUpstream(`{"name":"https-origin","scheme":"https","host":"10.10.0.2","port":443,"health_check_enabled":true,"health_check_path":"/health","health_check_method":"HEAD","expected_status_codes":"200","tls_verify":false}`)
	uDisabled, _ := addUpstream(`{"name":"nohc-origin","scheme":"http","host":"10.10.0.3","port":8080,"health_check_enabled":false}`)

	var mu sync.Mutex
	probeResults := map[string]*upstreams.TestResult{
		"http://10.10.0.1:80/news":    {HTTPStatus: 204, ResponseTimeMs: 12},
		"https://10.10.0.2:443/health": {HTTPStatus: 200, ResponseTimeMs: 25},
	}
	collector := runtimehealth.NewCollector(env.db, runtimehealth.Options{
		UpstreamProber: func(_ context.Context, in upstreams.TestInput) *upstreams.TestResult {
			if !in.AllowPrivate {
				return &upstreams.TestResult{ErrorCode: "SSRF_BLOCKED", ErrorMessage: "private not allowed"}
			}
			key := fmt.Sprintf("%s://%s:%d%s", in.Scheme, in.Host, in.Port, in.HealthCheckPath)
			mu.Lock()
			defer mu.Unlock()
			if r, ok := probeResults[key]; ok {
				cp := *r
				return &cp
			}
			return &upstreams.TestResult{ErrorCode: "CONNECTION_FAILED", ErrorMessage: "unexpected target " + key}
		},
	})

	listUpstreamsMap := func() map[string]map[string]any {
		r := env.get(t, fmt.Sprintf("/api/v1/applications/%s/upstreams", appID), cookies)
		defer r.Body.Close()
		var out apiResp
		readJSON(t, r, &out)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("list upstreams status=%d", r.StatusCode)
		}
		rawItems, _ := out.Data["items"].([]any)
		m := make(map[string]map[string]any, len(rawItems))
		for _, item := range rawItems {
			obj, _ := item.(map[string]any)
			id, _ := obj["id"].(string)
			m[id] = obj
		}
		return m
	}

	// 场景 1：两个启用检查的 HTTP/HTTPS 源站全部通过 -> 应用 HEALTHY，不递增 version
	if err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce(1) failed: %v", err)
	}
	hs, ver := getApp()
	if hs != "HEALTHY" {
		t.Fatalf("全源站通过时应用健康状态 = %q，want HEALTHY", hs)
	}
	if ver != initVersion {
		t.Fatalf("后台健康刷新不应递增应用 version：got %v, want %v", ver, initVersion)
	}
	ups := listUpstreamsMap()
	if ups[uHTTP]["health_status"] != "HEALTHY" || ups[uHTTP]["last_response_time_ms"] != float64(12) || ups[uHTTP]["last_response_status"] != float64(204) {
		t.Errorf("http upstream health mismatch: %+v", ups[uHTTP])
	}
	if ups[uHTTPS]["health_status"] != "HEALTHY" || ups[uHTTPS]["last_response_time_ms"] != float64(25) {
		t.Errorf("https upstream health mismatch: %+v", ups[uHTTPS])
	}
	if ups[uDisabled]["health_status"] != "DISABLED" {
		t.Errorf("disabled health check upstream = %v, want DISABLED", ups[uDisabled]["health_status"])
	}

	// 场景 2：HTTPS 源站返回 502（不匹配 200）-> 应用 DEGRADED，源站透出 UNEXPECTED_STATUS 与可读错误
	mu.Lock()
	probeResults["https://10.10.0.2:443/health"] = &upstreams.TestResult{HTTPStatus: 502, ResponseTimeMs: 31}
	mu.Unlock()
	if err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce(2) failed: %v", err)
	}
	hs, _ = getApp()
	if hs != "DEGRADED" {
		t.Fatalf("部分源站失败时应用健康状态 = %q，want DEGRADED", hs)
	}
	ups = listUpstreamsMap()
	if ups[uHTTPS]["health_status"] != "UNHEALTHY" || ups[uHTTPS]["last_health_error_code"] != "UNEXPECTED_STATUS" || ups[uHTTPS]["last_response_status"] != float64(502) {
		t.Errorf("degraded https upstream mismatch: %+v", ups[uHTTPS])
	}

	// 场景 3：HTTP 源站超时 -> 全部失败，应用 UNHEALTHY
	mu.Lock()
	probeResults["http://10.10.0.1:80/news"] = &upstreams.TestResult{ResponseTimeMs: 3001, ErrorCode: "TIMEOUT", ErrorMessage: "context deadline exceeded"}
	mu.Unlock()
	if err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce(3) failed: %v", err)
	}
	hs, _ = getApp()
	if hs != "UNHEALTHY" {
		t.Fatalf("全源站失败时应用健康状态 = %q，want UNHEALTHY", hs)
	}

	// 场景 4：关闭两台源站健康检查 -> 下一轮采集复位应用健康状态为 UNKNOWN，源站变为 DISABLED
	disableHC := func(id, name, scheme, host string, port int, version float64) {
		r := env.request(t, http.MethodPut, fmt.Sprintf("/api/v1/upstreams/%s", id),
			fmt.Sprintf(`{"name":%q,"scheme":%q,"host":%q,"port":%d,"weight":10,"priority":0,"health_check_enabled":false,"health_check_path":"/health","health_check_method":"GET","health_check_interval_seconds":30,"health_check_timeout_seconds":5,"expected_status_codes":"200","connect_timeout_ms":3000,"response_header_timeout_ms":10000,"tls_server_name":"","tls_verify":false,"max_retries":1,"version":%d}`,
				name, scheme, host, port, int(version)), cookies, csrf)
		defer r.Body.Close()
		if r.StatusCode != http.StatusOK {
			t.Fatalf("update upstream %s status=%d", id, r.StatusCode)
		}
	}
	disableHC(uHTTP, "http-origin", "http", "10.10.0.1", 80, vHTTP)
	disableHC(uHTTPS, "https-origin", "https", "10.10.0.2", 443, vHTTPS)

	if err := collector.CollectOnce(context.Background()); err != nil {
		t.Fatalf("CollectOnce(4) failed: %v", err)
	}
	hs, _ = getApp()
	if hs != "UNKNOWN" {
		t.Fatalf("全部关闭健康检查后应用健康状态 = %q，want UNKNOWN", hs)
	}
	ups = listUpstreamsMap()
	if ups[uHTTP]["health_status"] != "DISABLED" || ups[uHTTPS]["health_status"] != "DISABLED" {
		t.Errorf("关闭检查后源站状态应为 DISABLED: http=%v https=%v", ups[uHTTP]["health_status"], ups[uHTTPS]["health_status"])
	}
}
