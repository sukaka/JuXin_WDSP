// scanner_test.go 扫描流量识别（W9-GW）单测：
// 签名校验正反（伪造不打标、另产伪造嫌疑明细）/未配密钥存在性打标/无头零行为/
// 证据不含签名值与密钥材料/装配期密钥校验。
package detectors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// scanTestKey 测试用签名密钥（32 字节，与 apiscan.GenerateSigningKey 产物同形态）。
var scanTestKey = []byte("0123456789abcdef0123456789abcdef")

// signScanHeaderAt 按时效签名契约计算签名头值：
// "{job_id}.{unix_ts}.{hex(HMAC-SHA256(key, job_id|unix_ts))}"（ts 为签名时刻 Unix 秒）。
func signScanHeaderAt(key []byte, jobID string, ts int64) string {
	tsPart := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(jobID + "|" + tsPart))
	return jobID + "." + tsPart + "." + hex.EncodeToString(mac.Sum(nil))
}

// signScanHeader 以当前时刻签名（校验侧 ±scanSignatureTimeWindow 时窗内有效）。
func signScanHeader(key []byte, jobID string) string {
	return signScanHeaderAt(key, jobID, time.Now().Unix())
}

func newScannerCtx() *dsctx.RequestContext {
	return dsctx.New("rid-scan", dsctx.DefaultParseLimits())
}

func scannerMatches(ctx *dsctx.RequestContext, detector string) []dsctx.DetectorMatch {
	var out []dsctx.DetectorMatch
	for _, m := range ctx.CopyMatches() {
		if m.Detector == detector {
			out = append(out, m)
		}
	}
	return out
}

// assertNoScanSecret 证据纪律：任何明细的证据不得含签名值与密钥材料
// （job 标识允许入证据；签名取末段——时效签名头为 "{job_id}.{ts}.{sig}" 三段）。
func assertNoScanSecret(t *testing.T, ctx *dsctx.RequestContext, headerValue string) {
	t.Helper()
	sigPart := ""
	if i := strings.LastIndex(headerValue, "."); i >= 0 {
		sigPart = headerValue[i+1:]
	}
	for _, m := range ctx.CopyMatches() {
		for k, v := range m.Evidence {
			if sigPart != "" && strings.Contains(v, sigPart) {
				t.Fatalf("evidence must not contain signature value: %+v", m.Evidence)
			}
			if strings.Contains(v, string(scanTestKey)) || strings.Contains(v, hex.EncodeToString(scanTestKey)) {
				t.Fatalf("evidence must not contain key material: %+v", m.Evidence)
			}
			_ = k
		}
	}
}

// 有效签名：打 detector=scanner 标（OBSERVE/INFO，置信 1.0），证据含 job 标识不含签名值。
func TestCheckScannerSignal_ValidSignature(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	value := signScanHeader(scanTestKey, jobID)
	r := httptest.NewRequest("GET", "/v1/users", nil)
	r.Header.Set(ScanHeader, value)
	ctx := newScannerCtx()
	CheckScannerSignal(ctx, r, scanTestKey)

	ms := scannerMatches(ctx, "scanner")
	if len(ms) != 1 {
		t.Fatalf("want 1 scanner match, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.RuleID != "scanner.signature_valid" || m.Category != "OBSERVE" || m.Severity != "INFO" {
		t.Fatalf("bad match meta: %+v", m)
	}
	if m.Confidence != 1.0 {
		t.Fatalf("signature verification is deterministic, confidence = %v", m.Confidence)
	}
	if m.Evidence["job_id"] != jobID || m.Evidence["verification"] != "signature" {
		t.Fatalf("bad evidence: %+v", m.Evidence)
	}
	if len(scannerMatches(ctx, "api_authz")) != 0 {
		t.Fatalf("valid signature must not raise forgery detail: %+v", ctx.CopyMatches())
	}
	assertNoScanSecret(t, ctx, value)
}

// 伪造签名（错误密钥/篡改 job_id/过期时间窗/畸形头）：不打 scanner 标，产 api_authz 伪造嫌疑
// 明细（OBSERVE/MEDIUM）；reason 区分 invalid_signature / timestamp_out_of_window / malformed_header。
func TestCheckScannerSignal_ForgedSignature(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	now := time.Now()
	signed := signScanHeaderAt(scanTestKey, jobID, now.Unix()) // 固定 ts，消除秒级漂移
	tsPart := strconv.FormatInt(now.Unix(), 10)
	cases := []struct {
		name       string
		value      string
		wantReason string
	}{
		{"wrong key", signScanHeader([]byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), jobID), "invalid_signature"},
		{"tampered job", strings.Replace(signed, jobID[:8], "00000000", 1), "invalid_signature"},
		{"tampered ts", strings.Replace(signed, "."+tsPart+".", "."+strconv.FormatInt(now.Unix()-30, 10)+".", 1), "invalid_signature"},
		// 时效回归（LOW-G12）：HMAC 合法但 ts 超 ±scanSignatureTimeWindow——
		// 无时窗签名泄漏后可无限重放污染学习样本，过期/未来超限一律拒绝
		{"expired ts", signScanHeaderAt(scanTestKey, jobID, now.Add(-10*time.Minute).Unix()), "timestamp_out_of_window"},
		{"future ts", signScanHeaderAt(scanTestKey, jobID, now.Add(10*time.Minute).Unix()), "timestamp_out_of_window"},
		{"no signature", jobID, "malformed_header"},
		{"no ts", jobID + "." + hex.EncodeToString(make([]byte, 32)), "malformed_header"},
		{"bad hex", jobID + "." + tsPart + ".zzzz", "malformed_header"},
		{"truncated sig", jobID + "." + tsPart + ".abcd", "malformed_header"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/v1/users", nil)
			r.Header.Set(ScanHeader, c.value)
			ctx := newScannerCtx()
			CheckScannerSignal(ctx, r, scanTestKey)

			if ms := scannerMatches(ctx, "scanner"); len(ms) != 0 {
				t.Fatalf("forged signature must not be tagged scanner: %+v", ms)
			}
			ms := scannerMatches(ctx, "api_authz")
			if len(ms) != 1 {
				t.Fatalf("want 1 forgery detail, got %+v", ctx.CopyMatches())
			}
			m := ms[0]
			if m.RuleID != "scanner.signature_forged" || m.Category != "OBSERVE" || m.Severity != "MEDIUM" {
				t.Fatalf("bad forgery meta: %+v", m)
			}
			if m.Evidence["reason"] != c.wantReason {
				t.Fatalf("bad forgery evidence: %+v (want reason %q)", m.Evidence, c.wantReason)
			}
			assertNoScanSecret(t, ctx, c.value)
		})
	}
}

// 时窗边界：恰好 ±scanSignatureTimeWindow 内的签名仍有效（容忍两端时钟偏差与在途时延）。
func TestCheckScannerSignal_TimeWindowEdge(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	now := time.Now()
	// 窗口内侧 30s（整秒截断 + 秒级漂移会让恰压线的 ts 出窗，边界严格性由过期用例覆盖）
	for _, ts := range []int64{now.Add(-(scanSignatureTimeWindow - 30*time.Second)).Unix(), now.Add((scanSignatureTimeWindow - 30*time.Second)).Unix()} {
		r := httptest.NewRequest("GET", "/v1/users", nil)
		r.Header.Set(ScanHeader, signScanHeaderAt(scanTestKey, jobID, ts))
		ctx := newScannerCtx()
		// 注入固定 now，消除用例执行与签名时刻之间的秒级漂移
		checkScannerSignalAt(ctx, r, scanTestKey, now)
		if ms := scannerMatches(ctx, "scanner"); len(ms) != 1 {
			t.Fatalf("ts %d at window edge must be accepted: %+v", ts, ctx.CopyMatches())
		}
	}
}

// 未下发密钥：仅按头存在性打标（scanner.presence_only，OBSERVE/INFO，保守置信 0.6），不产伪造明细。
func TestCheckScannerSignal_PresenceOnly(t *testing.T) {
	jobID := "3f6b9d2e-7c1a-4e55-9a3d-2c8f0b1e6a47"
	value := signScanHeader(scanTestKey, jobID)
	r := httptest.NewRequest("GET", "/v1/users", nil)
	r.Header.Set(ScanHeader, value)
	ctx := newScannerCtx()
	CheckScannerSignal(ctx, r, nil)

	ms := scannerMatches(ctx, "scanner")
	if len(ms) != 1 {
		t.Fatalf("want 1 scanner match, got %+v", ctx.CopyMatches())
	}
	m := ms[0]
	if m.RuleID != "scanner.presence_only" || m.Category != "OBSERVE" || m.Severity != "INFO" {
		t.Fatalf("bad presence meta: %+v", m)
	}
	if m.Confidence != 0.6 {
		t.Fatalf("presence-only must be conservative, confidence = %v", m.Confidence)
	}
	if m.Evidence["job_id"] != jobID || m.Evidence["verification"] != "presence_only" {
		t.Fatalf("bad presence evidence: %+v", m.Evidence)
	}
	assertNoScanSecret(t, ctx, value)
}

// 无头零行为；nil 入参防御。
func TestCheckScannerSignal_NoHeader(t *testing.T) {
	ctx := newScannerCtx()
	CheckScannerSignal(ctx, httptest.NewRequest("GET", "/v1/users", nil), scanTestKey)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("no header must be zero behavior: %+v", ctx.CopyMatches())
	}
	CheckScannerSignal(nil, nil, scanTestKey) // 不 panic
	CheckScannerSignal(ctx, nil, scanTestKey)
	if len(ctx.CopyMatches()) != 0 {
		t.Fatalf("nil request must be zero behavior: %+v", ctx.CopyMatches())
	}
}

// 装配期密钥校验：nil/空 = 未下发（合法）；非 32 字节为配置错误（显式返回，不静默）。
func TestValidateScanVerificationKey(t *testing.T) {
	if err := ValidateScanVerificationKey(nil); err != nil {
		t.Fatalf("nil key must be accepted (presence-only mode): %v", err)
	}
	if err := ValidateScanVerificationKey(scanTestKey); err != nil {
		t.Fatalf("32-byte key must be accepted: %v", err)
	}
	for _, n := range []int{1, 16, 31, 33, 64} {
		if err := ValidateScanVerificationKey(make([]byte, n)); err == nil {
			t.Fatalf("%d-byte key must be rejected", n)
		}
	}
}
