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
	"time"

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
		"SecAuditEngine RelevantOnly",
		"SecAuditLogParts ABIJDEFHZ",
		"SecAuditLog /var/log/caddy/coraza-audit.log",
		"Include /etc/caddy/rules/crs/crs-setup.conf",
		"Include /etc/caddy/rules/crs/rules/*.conf",
		"Include /etc/caddy/rules/jiuzhang/jiuzhang-custom.conf",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("指令序列缺少 %q", want)
		}
	}
	corazaIdx := strings.Index(d, "Include /etc/caddy/rules/coraza.conf")
	auditIdx := strings.Index(d, "SecAuditEngine RelevantOnly")
	partsIdx := strings.Index(d, "SecAuditLogParts ABIJDEFHZ")
	if auditIdx <= corazaIdx || partsIdx <= corazaIdx {
		t.Errorf("SecAuditEngine/SecAuditLogParts 必须位于 coraza.conf 之后以覆写 POC 默认: %s", d)
	}
	if strings.Contains(d, "SecRuleEngine On") || strings.Contains(d, "SecRuleEngine DetectionOnly\nSecRuleEngine") {
		t.Error("指令序列不得包含防护模式")
	}
	off := mirrorDirectivesWithAudit("/etc/caddy/rules", "off")
	if !strings.Contains(off, "SecAuditEngine Off") {
		t.Errorf("auditLog=off 应输出 SecAuditEngine Off: %s", off)
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

// 静态资源路径无安全命中时跳过事件输出；命中 WAF 攻击规则时照常告警且 is_api=false。
func TestHandleRequestStaticAssetSuppression(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "api-runtime-events.log")
	d := newTestDetector(t, evPath)

	// 无攻击的静态 JS（带 Cookie）：不产出事件
	benignStatic, err := httpReadRaw("GET /astro/page.BsuiZEAU.js HTTP/1.1\r\nHost: web.example.com\r\nCookie: sid=abc\r\n\r\n")
	if err != nil {
		t.Fatalf("构造静态请求: %v", err)
	}
	d.HandleRequest(benignStatic, FlowMeta{SrcIP: "10.0.0.5", SrcPort: 40001, DstIP: "10.0.0.6", DstPort: 80}, false)
	if _, statErr := os.Stat(evPath); statErr == nil {
		recs := readEventRecords(t, evPath)
		if len(recs) != 0 {
			t.Fatalf("无攻击静态资源不应输出事件，实际输出 %d 条: %+v", len(recs), recs)
		}
	}

	// 静态路径携带攻击参数：WAF 命中后照常输出安全事件，但 is_api=false
	attackStatic, err := httpReadRaw("GET /favicon.ico?x=attack HTTP/1.1\r\nHost: web.example.com\r\n\r\n")
	if err != nil {
		t.Fatalf("构造攻击静态请求: %v", err)
	}
	d.HandleRequest(attackStatic, FlowMeta{SrcIP: "10.0.0.5", SrcPort: 40002, DstIP: "10.0.0.6", DstPort: 80}, false)
	recs := readEventRecords(t, evPath)
	if len(recs) != 1 {
		t.Fatalf("命中 WAF 的静态请求应输出 1 条安全告警，实际 %d 条", len(recs))
	}
	if recs[0]["is_api"] != false {
		t.Fatalf("静态路径告警 is_api 应为 false，实际 %v", recs[0]["is_api"])
	}
}

// bodyTruncated=true 时屏蔽因 64KB 截断产生的 200002/200003 解析误报，但真实攻击规则照常检出。
func TestHandleRequestTruncatedBodySuppressesParserFalsePositive(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "api-runtime-events.log")
	waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join([]string{
		"SecRuleEngine DetectionOnly",
		"SecRequestBodyAccess On",
		`SecRule REQUEST_HEADERS:Content-Type "^application/json" "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"`,
		`SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',severity:2"`,
		`SecRule REQUEST_URI "@contains attack" "id:100100,phase:1,t:none,log,msg:'real attack',severity:'CRITICAL'"`,
	}, "\n")))
	if err != nil {
		t.Fatalf("NewWAF: %v", err)
	}
	events, err := apievents.NewLogger(evPath, "mirror-test-node")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { _ = events.Close() })
	d := &Detector{cfg: Config{BodyMax: 64}, waf: waf, events: events, stats: &Stats{}}

	// 截断的不完整 JSON：200002 应被抑制（不应出现 detector=waf rule_id=200002）
	truncBody := `{"key":"truncat`
	req, err := httpReadRaw("POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n" + truncBody)
	if err != nil {
		t.Fatalf("构造截断请求: %v", err)
	}
	d.HandleRequest(req, FlowMeta{SrcIP: "10.0.0.1", SrcPort: 12345, DstIP: "10.0.0.2", DstPort: 80}, true)

	// 同样畸形 JSON 但 bodyTruncated=false：200002 应照常触发
	req2, err := httpReadRaw("POST /api/upload HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n" + truncBody)
	if err != nil {
		t.Fatalf("构造未截断畸形请求: %v", err)
	}
	d.HandleRequest(req2, FlowMeta{SrcIP: "10.0.0.1", SrcPort: 12346, DstIP: "10.0.0.2", DstPort: 80}, false)

	recs := readEventRecords(t, evPath)
	if len(recs) != 2 {
		t.Fatalf("事件数=%d want 2", len(recs))
	}
	for _, raw := range recs[0]["details"].([]any) {
		m := raw.(map[string]any)
		if m["detector"] == "waf" && m["rule_id"] == "200002" {
			t.Fatalf("截断请求体不应误报 200002: %+v", m)
		}
	}
	var saw200002 bool
	for _, raw := range recs[1]["details"].([]any) {
		m := raw.(map[string]any)
		if m["detector"] == "waf" && m["rule_id"] == "200002" {
			saw200002 = true
		}
	}
	if !saw200002 {
		t.Fatalf("未截断畸形 JSON 应正常触发 200002: %+v", recs[1]["details"])
	}
}

// 域名过滤生效但站点发现仍记录全量观察，且按接口精确 source_mode / SniffDisabled 控流。
func TestHandleRequestDomainFilterAndPerInterfaceDiscoveryMode(t *testing.T) {
	dir := t.TempDir()
	evPath := filepath.Join(dir, "api-runtime-events.log")
	discPath := filepath.Join(dir, "site-discovery.jsonl")
	d := newTestDetector(t, evPath)
	d.cfg.Domains = []string{"shop.example.com", "*.api.example.com"}

	agg, err := NewDiscoveryAggregator("gw-1", "ROUTED", discPath, time.Hour, &Stats{})
	if err != nil {
		t.Fatalf("NewDiscoveryAggregator: %v", err)
	}
	d.SetDiscovery(agg)

	// 1. 不在目标域名列表中，但该接口承担 MIRROR 发现角色：跳过检测事件，但记录 MIRROR 发现
	otherReq, _ := httpReadRaw("GET /api/x HTTP/1.1\r\nHost: other.example.com\r\n\r\n")
	d.HandleRequest(otherReq, FlowMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", DstPort: 80, SourceMode: "MIRROR"}, false)

	// 2. 命中泛域名，但接口为纯检测（SniffDisabled=true）：产出检测事件，但不写发现
	matchReq, _ := httpReadRaw("GET /api/orders HTTP/1.1\r\nHost: v2.api.example.com\r\n\r\n")
	d.HandleRequest(matchReq, FlowMeta{SrcIP: "10.0.0.1", DstIP: "10.0.0.3", DstPort: 80, SniffDisabled: true}, false)

	if err := agg.Close(); err != nil {
		t.Fatalf("agg.Close: %v", err)
	}
	recs := readEventRecords(t, evPath)
	if len(recs) != 1 || recs[0]["domain"] != "v2.api.example.com" {
		t.Fatalf("仅目标域名应输出检测事件, got %+v", recs)
	}
	discRecs := readDiscoveryRecords(t, discPath)
	if len(discRecs) != 1 || discRecs[0].Domain != "other.example.com" || discRecs[0].SourceMode != "MIRROR" {
		t.Fatalf("站点发现应仅含开启嗅探接口的记录且使用精确 source_mode=MIRROR, got %+v", discRecs)
	}
}

// httpReadRaw 从原始报文构造请求（与流层还原路径一致）。
func httpReadRaw(wire string) (*http.Request, error) {
	return http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
}
