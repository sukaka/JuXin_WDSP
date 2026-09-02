package jiuzhang_guard

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/identitybehavior"
)

// ibHandlerFunc 自定义下游处理器（caddyhttp.Handler 适配）。
type ibHandlerFunc func(http.ResponseWriter, *http.Request) error

func (f ibHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) error { return f(w, r) }

// provisionIBHTestGuard 经完整 Provision 装配测试 Guard（memory 后端，进程级引擎测试后复位）。
func provisionIBHTestGuard(t *testing.T, cfg Guard) *Guard {
	t.Helper()
	resetSharedEngineForTest()
	t.Cleanup(resetSharedEngineForTest)
	g := &cfg
	if g.EventsLog == "" {
		g.EventsLog = filepath.Join(t.TempDir(), "events.log")
	}
	if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { g.Cleanup() })
	return g
}

// ibServe 发送一个请求经完整 ServeHTTP 链路（默认 GET /，远端 203.0.113.10）。
func ibServe(t *testing.T, g *Guard, remoteAddr, target string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, target, nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	called := false
	rec := httptest.NewRecorder()
	if err := g.ServeHTTP(rec, r, nextHandler{&called}); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if !called {
		t.Fatal("request must reach upstream")
	}
	return rec
}

// readIBEvents 读取身份事件 JSONL。
func readIBEvents(t *testing.T, path string) []map[string]any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

// 配置缺省 = 零行为变化：未下发 identity_behavior → 引擎不装配、无事件文件、请求照常。
func TestIdentityBehaviorDefaultZeroChange(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{AppID: "app1", EventsLog: filepath.Join(dir, "events.log")})
	if g.ibh != nil {
		t.Fatal("nil identity_behavior must not provision engine")
	}
	ibServe(t, g, "203.0.113.10:1", "http://waf-test.local/", map[string]string{"User-Agent": "curl/8.1"})
	if _, err := os.Stat(filepath.Join(dir, "identity-events.log")); !os.IsNotExist(err) {
		t.Fatalf("no identity event file must be created: %v", err)
	}
	// enabled=false 同样零变化
	g2 := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events2.log"),
		IdentityBehavior: &identityBehaviorJSON{Enabled: false},
	})
	if g2.ibh != nil {
		t.Fatal("disabled identity_behavior must not provision engine")
	}
}

// 启用后请求经过产生 identity-events.log 记录（观测 + 快照）。
func TestIdentityBehaviorEnabledEmits(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", AppCode: "shop", EventsLog: filepath.Join(dir, "events.log"),
		IdentitySalt:     "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
	})
	if g.ibh == nil {
		t.Fatal("enabled identity_behavior must provision engine")
	}
	ibServe(t, g, "203.0.113.10:1", "http://waf-test.local/api/users?id=1", map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/120",
		"X-API-Key":  "key-abc-1",
	})
	logPath := filepath.Join(dir, "identity-events.log")
	lines := readIBEvents(t, logPath)
	var obs, snap map[string]any
	for _, m := range lines {
		switch m["record_type"] {
		case "identity_observation":
			obs = m
		case "behavior_snapshot":
			snap = m
		}
	}
	if obs == nil || snap == nil {
		t.Fatalf("observation and snapshot expected: %v", lines)
	}
	if obs["identity_key"] == "" || obs["identity_type"] != "APPLICATION" || obs["client_ip"] != "203.0.113.10" {
		t.Fatalf("observation fields: %v", obs)
	}
	if confidence, ok := obs["identity_confidence"].(float64); !ok || confidence != 75 {
		t.Fatalf("identity confidence: %v", obs["identity_confidence"])
	}
	evidence, ok := obs["identity_evidence"].([]any)
	if !ok || len(evidence) != 1 || evidence[0] != "credential:api_key" {
		t.Fatalf("identity evidence: %v", obs["identity_evidence"])
	}
	creds, ok := obs["credentials"].([]any)
	if !ok || len(creds) != 1 || creds[0].(map[string]any)["type"] != "API_KEY" {
		t.Fatalf("credentials: %v", obs["credentials"])
	}
	if obs["app_id"] != "app1" || obs["app_code"] != "shop" || obs["path"] != "/api/users" {
		t.Fatalf("observation attribution: %v", obs)
	}
	// 凭据身份跨 IP 同 key
	ibServe(t, g, "198.51.100.5:1", "http://waf-test.local/api/users?id=2", map[string]string{
		"User-Agent": "Mozilla/5.0 Chrome/120",
		"X-API-Key":  "key-abc-1",
	})
	var keys []string
	for _, m := range readIBEvents(t, logPath) {
		if m["record_type"] == "identity_observation" {
			keys = append(keys, m["identity_key"].(string))
		}
	}
	if len(keys) < 2 || keys[0] != keys[1] {
		t.Fatalf("credential identity must be stable across IPs: %v", keys)
	}
}

// 敏感路径扫描 4 次 + 多 IP 同 UA → 同 identity_key 且产生 SENSITIVE_PATH_PROBE 信号记录。
func TestIdentityBehaviorSensitiveScanSignal(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
		IdentitySalt:     "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
	})
	ua := map[string]string{"User-Agent": "sqlmap/1.7"}
	ips := []string{"203.0.113.10:1", "203.0.113.11:1", "198.51.100.9:1", "203.0.113.10:1"}
	for _, ip := range ips {
		ibServe(t, g, ip, "http://waf-test.local/.git/config", ua)
	}
	lines := readIBEvents(t, filepath.Join(dir, "identity-events.log"))
	var identityKeys []string
	var signals []map[string]any
	for _, m := range lines {
		switch m["record_type"] {
		case "identity_observation":
			identityKeys = append(identityKeys, m["identity_key"].(string))
			if m["identity_type"] != "BOT" {
				t.Fatalf("sqlmap UA must classify BOT: %v", m)
			}
		case "recon_signal":
			signals = append(signals, m)
		}
	}
	if len(identityKeys) == 0 {
		t.Fatal("observations expected")
	}
	for _, k := range identityKeys[1:] {
		if k != identityKeys[0] {
			t.Fatalf("same UA across IPs must share identity_key: %v", identityKeys)
		}
	}
	// SENSITIVE_PATH_PROBE 信号（60s 节流 → 同 (identity,rule) 1 条）
	var probe []map[string]any
	for _, m := range signals {
		if m["signal"] == "SENSITIVE_PATH_PROBE" {
			probe = append(probe, m)
		}
	}
	if len(probe) != 1 {
		t.Fatalf("SENSITIVE_PATH_PROBE signals: %v", signals)
	}
	if probe[0]["rule_code"] != "RECON-PATH-001" || probe[0]["mode"] != "OBSERVE" || probe[0]["identity_key"] != identityKeys[0] {
		t.Fatalf("probe signal fields: %v", probe[0])
	}
	meta := probe[0]["metadata"].(map[string]any)
	if meta["matched_prefix"] != "/.git" {
		t.Fatalf("probe metadata: %v", meta)
	}
	// 敏感命中计入行为快照（behavior_snapshot 节流 1 条/identity/60s——仅能观测到
	// 首条快照，其 24h 窗命中为首次请求自身的 1 次；跨请求累计由 tracker 测试覆盖）
	var sawSnapshot bool
	for _, m := range lines {
		if m["record_type"] != "behavior_snapshot" {
			continue
		}
		sawSnapshot = true
		w := m["windows"].(map[string]any)["24h"].(map[string]any)
		if w["sensitive_path_hits"].(float64) < 1 {
			t.Fatalf("24h sensitive hits must record the probe: %v", w)
		}
	}
	if !sawSnapshot {
		t.Fatal("behavior snapshot expected")
	}
}

// 身份行为白名单：命中 IP → 完全跳过观测与信号（无记录），请求照常放行。
func TestIdentityBehaviorWhitelistSkips(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
		IdentityBehavior: &identityBehaviorJSON{
			Enabled:      true,
			WhitelistIPs: []string{"203.0.113.0/24"},
		},
	})
	ibServe(t, g, "203.0.113.10:1", "http://waf-test.local/.git/config", map[string]string{"User-Agent": "sqlmap/1.7"})
	logPath := filepath.Join(dir, "identity-events.log")
	if _, err := os.Stat(logPath); err == nil {
		if lines := readIBEvents(t, logPath); len(lines) != 0 {
			t.Fatalf("whitelisted ip must produce no records: %v", lines)
		}
	}
	// 非白名单 IP 正常观测
	ibServe(t, g, "198.51.100.9:1", "http://waf-test.local/.git/config", map[string]string{"User-Agent": "sqlmap/1.7"})
	if lines := readIBEvents(t, logPath); len(lines) == 0 {
		t.Fatal("non-whitelisted ip must be observed")
	}
}

// 装配失败 fail-open：非法白名单地址 → Provision 不报错、引擎置 nil、请求照常。
func TestIdentityBehaviorCompileFailureFailOpen(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
		IdentityBehavior: &identityBehaviorJSON{Enabled: true, WhitelistIPs: []string{"bad-cidr"}},
	})
	if g.ibh != nil {
		t.Fatal("compile failure must leave engine nil (fail-open)")
	}
	ibServe(t, g, "203.0.113.10:1", "http://waf-test.local/", nil)
}

// Validate：非法比率/阈值拒绝配置。
func TestIdentityBehaviorValidate(t *testing.T) {
	badRatio := 1.5
	g := &Guard{
		AppID: "app1", EventsLog: filepath.Join(t.TempDir(), "events.log"),
		IdentityBehavior: &identityBehaviorJSON{Enabled: true, URIEnumNewRatioThreshold: &badRatio},
	}
	if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "identity_behavior") {
		t.Fatalf("bad ratio must fail validate: %v", err)
	}
	neg := int64(-1)
	g.IdentityBehavior = &identityBehaviorJSON{Enabled: true, AuthFailThreshold: &neg}
	if err := g.Validate(); err == nil {
		t.Fatal("negative threshold must fail validate")
	}
	g.IdentityBehavior = &identityBehaviorJSON{Enabled: true}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
}

// 配置重载（Provision/Cleanup）无泄漏：Cleanup 置 nil 且可重复；重装配可继续记录。
func TestIdentityBehaviorReloadNoLeak(t *testing.T) {
	dir := t.TempDir()
	mk := func() *Guard {
		resetSharedEngineForTest()
		g := &Guard{
			AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
			IdentityBehavior: &identityBehaviorJSON{Enabled: true},
		}
		if err := g.Provision(caddy.Context{Context: context.Background()}); err != nil {
			t.Fatalf("provision: %v", err)
		}
		return g
	}
	g1 := mk()
	ibServe(t, g1, "203.0.113.10:1", "http://waf-test.local/", nil)
	if err := g1.Cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if g1.ibh != nil {
		t.Fatal("cleanup must nil engine")
	}
	if err := g1.Cleanup(); err != nil {
		t.Fatalf("second cleanup must be safe: %v", err)
	}
	g2 := mk()
	defer g2.Cleanup()
	ibServe(t, g2, "203.0.113.11:1", "http://waf-test.local/", nil)
	lines := readIBEvents(t, filepath.Join(dir, "identity-events.log"))
	var ips []string
	for _, m := range lines {
		if m["record_type"] == "identity_observation" {
			ips = append(ips, m["client_ip"].(string))
		}
	}
	if len(ips) != 2 {
		t.Fatalf("both generations must have recorded: %v", ips)
	}
	resetSharedEngineForTest()
}

// 身份写入请求上下文：下游桥接可取（IdentityFrom 供 apiprotect bridgeRequestContext 复用）。
func TestIdentityBehaviorContextBridge(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
		IdentitySalt:     "test-salt",
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
	})
	var seenKey string
	handler := ibHandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if id := identitybehavior.IdentityFrom(r.Context()); id != nil {
			seenKey = id.Key
		}
		w.WriteHeader(200)
		return nil
	})
	r := httptest.NewRequest(http.MethodGet, "http://waf-test.local/", nil)
	r.RemoteAddr = "203.0.113.10:1"
	r.Header.Set("User-Agent", "curl/8.1")
	if err := g.ServeHTTP(httptest.NewRecorder(), r, handler); err != nil {
		t.Fatalf("serve: %v", err)
	}
	if seenKey == "" {
		t.Fatal("identity must be visible in request context downstream")
	}
}

// 观测点不拦截：敏感路径请求照常到达上游并返回上游状态码（纯 OBSERVE）。
func TestIdentityBehaviorObserveOnlyNoBlock(t *testing.T) {
	dir := t.TempDir()
	g := provisionIBHTestGuard(t, Guard{
		AppID: "app1", EventsLog: filepath.Join(dir, "events.log"),
		IdentityBehavior: &identityBehaviorJSON{Enabled: true},
	})
	rec := ibServe(t, g, "203.0.113.10:1", "http://waf-test.local/.git/config", map[string]string{"User-Agent": "sqlmap/1.7"})
	if rec.Code != 200 {
		t.Fatalf("observe-only must not alter response: %d", rec.Code)
	}
}
