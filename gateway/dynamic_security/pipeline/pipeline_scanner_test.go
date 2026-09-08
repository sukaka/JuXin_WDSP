// pipeline_scanner_test.go 扫描流量识别的管线接线（W9-GW）：
// 密钥经 Config.ScanVerificationKey 注入，X-JiuZhang-Scan 头在统一管线请求相位打标；
// 不挂 api.IsAPI 分类门槛；管线关闭时零行为。
package pipeline

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

var pipeScanKey = []byte("0123456789abcdef0123456789abcdef")

// signPipeScanHeader 时效签名契约："{job_id}.{unix_ts}.{hex(HMAC-SHA256(key, job_id|unix_ts))}"。
func signPipeScanHeader(jobID string) string {
	tsPart := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, pipeScanKey)
	mac.Write([]byte(jobID + "|" + tsPart))
	return jobID + "." + tsPart + "." + hex.EncodeToString(mac.Sum(nil))
}

func newScanRequest(t *testing.T, headerValue string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(http.MethodGet, "http://h/v1/users/5", nil)
	if err != nil {
		t.Fatal(err)
	}
	if headerValue != "" {
		r.Header.Set("X-JiuZhang-Scan", headerValue)
	}
	return r
}

// 有效签名经管线打 scanner 标（学习样本排除规则的消费点）；伪造签名不打标、另产伪造嫌疑明细。
func TestProcessScannerSignal(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"

	res, err := Process(newScanRequest(t, signPipeScanHeader(jobID)), Config{
		Enabled: true, Mode: "OBSERVE", ScanVerificationKey: pipeScanKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "scanner.signature_valid") {
		t.Fatalf("valid scan signature must be tagged: %+v", res.Context.CopyMatches())
	}
	if hasRule(res, "scanner.signature_forged") {
		t.Fatalf("valid signature must not raise forgery detail: %+v", res.Context.CopyMatches())
	}

	// 伪造（错误密钥签名）：不打 scanner 标，产伪造嫌疑明细
	forged := signPipeScanHeader(jobID)[:len(signPipeScanHeader(jobID))-2] + "00"
	res, err = Process(newScanRequest(t, forged), Config{
		Enabled: true, Mode: "OBSERVE", ScanVerificationKey: pipeScanKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasRule(res, "scanner.signature_valid") || hasRule(res, "scanner.presence_only") {
		t.Fatalf("forged signature must not be tagged scanner: %+v", res.Context.CopyMatches())
	}
	if !hasRule(res, "scanner.signature_forged") {
		t.Fatalf("forgery detail missing: %+v", res.Context.CopyMatches())
	}

	// 未配密钥：仅存在性打标
	res, err = Process(newScanRequest(t, signPipeScanHeader(jobID)), Config{
		Enabled: true, Mode: "OBSERVE",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !hasRule(res, "scanner.presence_only") {
		t.Fatalf("presence-only tagging missing: %+v", res.Context.CopyMatches())
	}

	// 无头：零扫描明细
	res, err = Process(newScanRequest(t, ""), Config{
		Enabled: true, Mode: "OBSERVE", ScanVerificationKey: pipeScanKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range res.Context.CopyMatches() {
		if m.Detector == "scanner" || strings.HasPrefix(m.RuleID, "scanner.") {
			t.Fatalf("no header must yield no scanner detail: %+v", m)
		}
	}
}

// 管线关闭（Enabled=false）：扫描识别零行为（Skipped，不进管线）。
func TestProcessScannerSignalDisabled(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	res, err := Process(newScanRequest(t, signPipeScanHeader(jobID)), Config{
		Enabled: false, ScanVerificationKey: pipeScanKey,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Skipped || res.Context != nil {
		t.Fatalf("disabled pipeline must skip: %+v", res)
	}
}
