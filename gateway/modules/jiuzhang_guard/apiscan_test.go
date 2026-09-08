// apiscan_test.go 扫描识别与响应偏离的模块级装配测试（W9-GW）：
// 配置校验正反（坏密钥/坏基线显式拒绝）、请求链路端到端打标（scanner 明细进事件）、
// 响应链路端到端偏离（schema_new_field 等明细进事件）。
package jiuzhang_guard

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
)

// guardScanTestKey 测试用签名密钥（32 字节）。
var guardScanTestKey = []byte("0123456789abcdef0123456789abcdef")

// signGuardScanHeader 按三段式时效契约构造扫描签名头（与 server apiscan.Signer.Sign 及
// detectors.verifyScanSignature 同一构造：{job_id}.{unix_ts}.{hex(HMAC(key, job_id|unix_ts))}）。
func signGuardScanHeader(jobID string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, guardScanTestKey)
	mac.Write([]byte(jobID + "|" + ts))
	return jobID + "." + ts + "." + hex.EncodeToString(mac.Sum(nil))
}

// api_scan_verification 装配校验：非法 hex / 非 32 字节显式拒绝（不静默吞错）；
// 未配置（nil/空）合法（降级仅存在性识别）；错误信息不含密钥材料。
func TestValidate_ScanVerification(t *testing.T) {
	base := func() *Guard {
		return &Guard{EventsLog: "x.log", APIDynamicProtection: true, APIProtectionMode: "OBSERVE"}
	}
	g := base()
	if err := g.Validate(); err != nil {
		t.Fatalf("nil scan verification must be valid: %v", err)
	}
	g = base()
	g.APIScanVerification = &scanVerificationJSON{KeyHex: "  "}
	if err := g.Validate(); err != nil {
		t.Fatalf("empty key must be valid (presence-only): %v", err)
	}
	g = base()
	g.APIScanVerification = &scanVerificationJSON{KeyHex: "not-hex-zz"}
	if err := g.Validate(); err == nil {
		t.Fatal("non-hex key must be rejected")
	} else if strings.Contains(err.Error(), "not-hex-zz") {
		t.Fatalf("error must not contain key material: %v", err)
	}
	g = base()
	g.APIScanVerification = &scanVerificationJSON{KeyHex: hex.EncodeToString([]byte("sixteen-byte-key"))}
	if err := g.Validate(); err == nil {
		t.Fatal("16-byte key must be rejected")
	}
	g = base()
	g.APIScanVerification = &scanVerificationJSON{KeyHex: hex.EncodeToString(guardScanTestKey)}
	if err := g.Validate(); err != nil {
		t.Fatalf("32-byte key must be valid: %v", err)
	}
	key, err := parseAPIScanVerificationKey(g.APIScanVerification)
	if err != nil || string(key) != string(guardScanTestKey) {
		t.Fatalf("parse: %v %x", err, key)
	}
}

// api_response_baselines 装配校验：坏基线显式拒绝；合法基线按端点归组。
func TestValidate_ResponseBaselines(t *testing.T) {
	g := &Guard{
		EventsLog: "x.log", APIDynamicProtection: true, APIProtectionMode: "OBSERVE",
		APIResponseBaselines: []detectors.ResponseBaseline{{EndpointKey: "GET /a", StatusCode: 99, Fields: map[string]string{"x": "string"}}},
	}
	if err := g.Validate(); err == nil {
		t.Fatal("bad status_code must be rejected")
	}
	g.APIResponseBaselines = []detectors.ResponseBaseline{
		{EndpointKey: "GET /v1/users/{id}", StatusCode: 200, Fields: map[string]string{"id": "number"}},
	}
	if err := g.Validate(); err != nil {
		t.Fatalf("valid baselines rejected: %v", err)
	}
}

// 端到端：有效签名扫描头经请求链路打 scanner 标并进事件（学习样本排除规则的消费点）；
// 伪造签名不打 scanner 标、另产伪造嫌疑明细。
func TestServeNext_ScannerSignalEndToEnd(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.apiScanKey = guardScanTestKey

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

	// 有效签名
	req := httptest.NewRequest(http.MethodGet, "/v1/users/5", nil)
	req.Header.Set("X-JiuZhang-Scan", signGuardScanHeader(jobID))
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	// 伪造签名（末两位改 00）
	forged := signGuardScanHeader(jobID)
	forged = forged[:len(forged)-2] + "00"
	req2 := httptest.NewRequest(http.MethodGet, "/v1/users/6", nil)
	req2.Header.Set("X-JiuZhang-Scan", forged)
	if err := g.serveNext(httptest.NewRecorder(), req2, next); err != nil {
		t.Fatalf("serveNext forged: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 2 {
		t.Fatalf("want 2 api events, got %d", len(recs))
	}
	hasDetail := func(recIdx int, ruleID string) bool {
		for _, d := range recs[recIdx].Details {
			if d.RuleID == ruleID {
				return true
			}
		}
		return false
	}
	if !hasDetail(0, "scanner.signature_valid") {
		t.Fatalf("valid scan must be tagged: %+v", recs[0].Details)
	}
	if hasDetail(1, "scanner.signature_valid") || hasDetail(1, "scanner.presence_only") {
		t.Fatalf("forged scan must not be tagged: %+v", recs[1].Details)
	}
	if !hasDetail(1, "scanner.signature_forged") {
		t.Fatalf("forgery detail missing: %+v", recs[1].Details)
	}
	// 证据不含签名值（三段式契约的第三段 hex 签名）
	sigPart := forged[strings.LastIndex(forged, ".")+1:]
	for _, d := range recs[1].Details {
		for _, v := range d.Evidence {
			if strings.Contains(v, sigPart) {
				t.Fatalf("evidence must not contain signature: %+v", d.Evidence)
			}
		}
	}
}

// 端到端：响应偏离检测——端点有基线时新字段/缺失字段/未见状态码明细进事件，响应体不受影响。
func TestServeNext_ResponseDeviationEndToEnd(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	g.apiRespBaselines = detectors.GroupResponseBaselines([]detectors.ResponseBaseline{{
		EndpointKey: "GET /v1/users",
		StatusCode:  200,
		Fields:      map[string]string{"id": "number", "name": "string"},
	}})

	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":7,"email":"a@example.com"}`) // name 缺失、email 为基线外新字段
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Accept", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}

	recs := readAPIRecords(t, logPath)
	if len(recs) != 1 {
		t.Fatalf("want 1 api event, got %d", len(recs))
	}
	var newField, missingField bool
	for _, d := range recs[0].Details {
		switch d.RuleID {
		case "response.schema_new_field":
			newField = true
			if d.Evidence["field"] != "email" {
				t.Fatalf("bad new_field evidence: %+v", d.Evidence)
			}
		case "response.schema_missing_field":
			missingField = true
			if d.Evidence["field"] != "name" {
				t.Fatalf("bad missing_field evidence: %+v", d.Evidence)
			}
		}
		// 证据不落响应值
		for _, v := range d.Evidence {
			if v == "a@example.com" {
				t.Fatalf("evidence must not contain response value: %+v", d.Evidence)
			}
		}
	}
	if !newField || !missingField {
		t.Fatalf("deviation details missing: %+v", recs[0].Details)
	}
}

// 端到端（负例）：无基线下发时同样的偏离报文零偏离明细。
func TestServeNext_ResponseDeviationNoBaseline(t *testing.T) {
	g, logPath := newAPITestGuard(t, "OBSERVE", nil)
	next := nextFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"totally":"unexpected","shape":1}`)
		return nil
	})
	req := httptest.NewRequest(http.MethodGet, "/v1/users", nil)
	req.Header.Set("Accept", "application/json")
	if err := g.serveNext(httptest.NewRecorder(), req, next); err != nil {
		t.Fatalf("serveNext: %v", err)
	}
	for _, rec := range readAPIRecords(t, logPath) {
		for _, d := range rec.Details {
			if strings.HasPrefix(d.RuleID, "response.schema_") {
				t.Fatalf("no baseline must yield no deviation detail: %+v", d)
			}
		}
	}
}
