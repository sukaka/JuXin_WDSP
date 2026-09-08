// 检测与事件映射测试（内联单规则 Coraza，无需规则目录、无需 root）。
package mirrorcap

import (
	"bufio"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	corazatypes "github.com/corazawaf/coraza/v3/types"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

func TestWAFSeverityMapping(t *testing.T) {
	cases := []struct {
		in    corazatypes.RuleSeverity
		sev   string
		delta int
	}{
		{corazatypes.RuleSeverityCritical, "CRITICAL", 50},
		{corazatypes.RuleSeverityError, "HIGH", 40},
		{corazatypes.RuleSeverityWarning, "MEDIUM", 25},
		{corazatypes.RuleSeverityNotice, "LOW", 10},
		{corazatypes.RuleSeverityUnset, "INFO", 0},
	}
	for _, c := range cases {
		sev, delta := wafSeverity(c.in)
		if sev != c.sev || delta != c.delta {
			t.Errorf("wafSeverity(%v)=(%s,%d) want (%s,%d)", c.in, sev, delta, c.sev, c.delta)
		}
	}
}

func TestMirrorDirectives(t *testing.T) {
	d := mirrorDirectives("/etc/caddy/rules")
	if !strings.HasPrefix(d, "SecRuleEngine DetectionOnly") {
		t.Error("旁路必须固定 DetectionOnly")
	}
	for _, want := range []string{
		"Include /etc/caddy/rules/coraza.conf",
		"Include /etc/caddy/rules/crs/crs-setup.conf",
		"Include /etc/caddy/rules/crs/rules/*.conf",
		"Include /etc/caddy/rules/jiuzhang/jiuzhang-custom.conf",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("指令序列缺少 %q", want)
		}
	}
	if strings.Contains(d, "SecRuleEngine On") || strings.Contains(d, "SecRuleEngine DetectionOnly\nSecRuleEngine") {
		t.Error("指令序列不得包含防护模式")
	}
}

// newTestDetector 内联单规则 WAF：ARGS 含 attack 即命中（CRITICAL）。
func newTestDetector(t *testing.T, eventsPath string) *Detector {
	t.Helper()
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(
		"SecRuleEngine DetectionOnly\n" +
			`SecRule ARGS "@contains attack" "id:100100,phase:2,t:none,log,msg:'test attack rule',severity:'CRITICAL',tag:'attack-sqli'"`))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	events, err := apievents.NewLogger(eventsPath, "mirror-test-node")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = events.Close() })
	return &Detector{
		cfg:    Config{IdentitySalt: "test-salt", BodyMax: 1024},
		waf:    waf,
		events: events,
		stats:  &Stats{},
	}
}

func readEventRecords(t *testing.T, path string) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取事件文件: %v", err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("事件行非 JSON: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// HandleRequest 全链路：SQLi 特征请求 → waf 命中进 details、风险非 NONE、
// final_action 封顶 OBSERVE、mirror.capture 标注首位、真实源 IP 入库。
func TestHandleRequestEmitsObserveCappedEvent(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "api-runtime-events.log")
	d := newTestDetector(t, evPath)

	req, err := httpReadRaw("GET /api/users?id=attack HTTP/1.1\r\nHost: api.example.com:8080\r\nUser-Agent: curl/8\r\n\r\n")
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	meta := FlowMeta{SrcIP: "172.31.0.20", SrcPort: 51000, DstIP: "172.31.0.10", DstPort: 8080}
	d.HandleRequest(req, meta, false)

	recs := readEventRecords(t, evPath)
	if len(recs) != 1 {
		t.Fatalf("事件数=%d want 1", len(recs))
	}
	rec := recs[0]
	if rec["final_action"] != string(dsctx.ActionObserve) {
		t.Errorf("final_action=%v want OBSERVE（旁路封顶）", rec["final_action"])
	}
	if rec["risk_level"] == "NONE" || rec["risk_level"] == nil {
		t.Errorf("risk_level=%v 应非 NONE（SQLi 命中）", rec["risk_level"])
	}
	if rec["endpoint_key"] != "GET /api/users" {
		t.Errorf("endpoint_key=%v want GET /api/users", rec["endpoint_key"])
	}
	if rec["client_ip"] != "172.31.0.20" {
		t.Errorf("client_ip=%v want 172.31.0.20（真实源地址）", rec["client_ip"])
	}
	if rec["source_fingerprint"] == nil || rec["source_fingerprint"] == "" {
		t.Error("source_fingerprint 应非空")
	}
	if rec["gateway_node_id"] != "mirror-test-node" {
		t.Errorf("gateway_node_id=%v", rec["gateway_node_id"])
	}
	if rec["domain"] != "api.example.com" {
		t.Errorf("domain=%v want api.example.com（去端口小写）", rec["domain"])
	}
	if rec["request_id"] == nil || rec["request_id"] == "" {
		t.Error("request_id 应非空")
	}
	// details：首位 mirror.capture（INFO），且包含 waf 命中（规则 100100）
	details, ok := rec["details"].([]any)
	if !ok || len(details) < 2 {
		t.Fatalf("details 应至少含 mirror.capture + waf 命中: %v", rec["details"])
	}
	first := details[0].(map[string]any)
	if first["detector"] != "mirror" || first["rule_id"] != "mirror.capture" || first["category"] != "INFO" {
		t.Errorf("details[0]=%v 应为 mirror 标注", first)
	}
	var sawWAF bool
	for _, it := range details[1:] {
		m := it.(map[string]any)
		if m["detector"] == "waf" && m["rule_id"] == "100100" {
			sawWAF = true
			if m["severity"] != "CRITICAL" {
				t.Errorf("waf severity=%v want CRITICAL", m["severity"])
			}
			ev, _ := m["evidence"].(map[string]any)
			if ev["engine"] != "coraza" {
				t.Errorf("waf evidence.engine=%v want coraza", ev["engine"])
			}
		}
	}
	if !sawWAF {
		t.Error("details 中未找到 waf 规则 100100 命中")
	}
}

// 正常请求（无命中）：事件仍输出（端点发现通道），risk NONE，final_action OBSERVE。
func TestHandleRequestBenign(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "api-runtime-events.log")
	d := newTestDetector(t, evPath)

	req, err := httpReadRaw("GET /health HTTP/1.1\r\nHost: internal\r\n\r\n")
	if err != nil {
		t.Fatalf("构造请求: %v", err)
	}
	d.HandleRequest(req, FlowMeta{SrcIP: "10.0.0.5", SrcPort: 40000, DstIP: "10.0.0.6", DstPort: 80}, false)

	recs := readEventRecords(t, evPath)
	if len(recs) != 1 {
		t.Fatalf("事件数=%d want 1", len(recs))
	}
	if recs[0]["risk_level"] != "NONE" {
		t.Errorf("risk_level=%v want NONE", recs[0]["risk_level"])
	}
	if recs[0]["final_action"] != "OBSERVE" {
		t.Errorf("final_action=%v want OBSERVE", recs[0]["final_action"])
	}
	if recs[0]["response_status"] != float64(0) {
		t.Errorf("response_status=%v want 0（镜像不采集响应）", recs[0]["response_status"])
	}
}

// httpReadRaw 从原始报文构造请求（与流层还原路径一致）。
func httpReadRaw(wire string) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
}
