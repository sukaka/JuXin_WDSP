// scanner.go 扫描流量识别（W9-GW，背景A 扫描识别闭环；设计稿 docs/API_ACTIVE_SCANNING.md §8）。
//
// 管理面主动扫描探针携带 X-JiuZhang-Scan 头，值为
// "{job_id}.{unix_ts}.{hex(HMAC-SHA256(key, job_id|unix_ts))}"
// （构造见 server/internal/apiscan/sign.go；密钥经发布通道 api_scan_verification.key_hex 下发）。
// 签名为时效签名：unix_ts 为签名时刻（Unix 秒，十进制），校验侧做 ±scanSignatureTimeWindow
// 时间窗检查——无时窗的签名泄漏后可无限重放污染学习样本，时窗同时容忍两端时钟偏差与
// 在途时延。HMAC 消息为 "job_id|unix_ts"（pipe 分隔与 response/signature.go 同一惯例）。
// 本检测器产出 detector=scanner 明细，消费者：管理面学习样本排除规则
// （server/internal/apiruntime/samples.go：details 含 detector=scanner 明细即排除，
// 「扫描流量不进学习/不进行为基线」）与事件打标。
//
// 纪律：
//   - 已下发密钥时校验签名有效性：无效签名不打 scanner 标（防伪造扫描标记污染学习排除），
//     另产 api_authz 级 OBSERVE 明细说明伪造嫌疑；
//   - 未下发密钥（key 为空）时仅按头存在性打标（无法防伪造，诚实降级）；
//   - 证据只含 job 标识与识别方式，绝不含签名值与密钥材料；
//   - 扫描识别不挂 api.IsAPI 分类门槛：扫描探针目标即 API 端点，分类漏判不应关掉识别。
package detectors

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// ScanHeader 扫描隔离签名头名（与 server apiscan.ScanHeader 同一约定；json/头名为跨分片契约）。
const ScanHeader = "X-JiuZhang-Scan"

// scanSignKeyBytes 签名密钥长度（字节；与 apiscan.NewSigner 的 32 字节约束一致）。
const scanSignKeyBytes = 32

// scanSignatureTimeWindow 签名时间窗（±5 分钟）：ts 与本地时钟偏差在窗口内才接受——
// 无时窗签名泄漏后可无限重放污染学习样本；窗口取值容忍两端时钟偏差与在途时延。
const scanSignatureTimeWindow = 5 * time.Minute

// maxScanJobIDLen 证据中 job 标识长度上限（uuid 36 字符；超长截断防脏数据放大）。
const maxScanJobIDLen = 64

// ValidateScanVerificationKey 装配期校验扫描签名密钥（nil/空 = 未下发，仅存在性识别；
// 非空须 32 字节，否则配置错误显式返回，不静默吞错）。
func ValidateScanVerificationKey(key []byte) error {
	if len(key) == 0 {
		return nil
	}
	if len(key) != scanSignKeyBytes {
		return &ScanKeyLengthError{Got: len(key)}
	}
	return nil
}

// ScanKeyLengthError 扫描签名密钥长度非法。
type ScanKeyLengthError struct{ Got int }

func (e *ScanKeyLengthError) Error() string {
	return "api_scan_verification: key must be 32 bytes (64 hex chars)"
}

// CheckScannerSignal 扫描流量识别：请求携带 X-JiuZhang-Scan 头时按密钥配置分三支——
//   - key 非空且签名有效（HMAC 一致且 ts 在 ±scanSignatureTimeWindow 内）→
//     detector=scanner（scanner.signature_valid，OBSERVE/INFO，置信 1.0）；
//   - key 非空且签名无效/过期/畸形 → 不打 scanner 标，产 api_authz 伪造嫌疑明细
//     （scanner.signature_forged，OBSERVE/MEDIUM；reason 区分 malformed_header /
//     timestamp_out_of_window / invalid_signature）；
//   - key 为空（未下发密钥）→ 仅存在性打标（scanner.presence_only，OBSERVE/INFO，保守置信 0.6）。
//
// 无头零行为。证据只含 job 标识（签名值不落证据）。
func CheckScannerSignal(ctx *dsctx.RequestContext, r *http.Request, key []byte) {
	checkScannerSignalAt(ctx, r, key, time.Now())
}

// checkScannerSignalAt CheckScannerSignal 的可测实现（now 可注入，时间窗判定可复现）。
func checkScannerSignalAt(ctx *dsctx.RequestContext, r *http.Request, key []byte, now time.Time) {
	if ctx == nil || r == nil {
		return
	}
	value := strings.TrimSpace(r.Header.Get(ScanHeader))
	if value == "" {
		return
	}
	// 形态 "{job_id}.{unix_ts}.{hex sig}"：job_id 为 uuid（无点），两段 Cut 依次拆出
	jobPart, rest, _ := strings.Cut(value, ".")
	tsPart, sigPart, _ := strings.Cut(rest, ".")
	jobID := truncateScanJobID(jobPart)
	if len(key) == 0 {
		// 未下发密钥：仅按头存在性识别（无法防伪造，置信保守取值）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "scanner",
			RuleID:     "scanner.presence_only",
			Category:   "OBSERVE",
			Severity:   "INFO",
			Message:    "api scan header observed (no verification key configured, presence only)",
			Evidence:   map[string]string{"job_id": jobID, "verification": "presence_only"},
			Confidence: 0.6,
		})
		return
	}
	if ok, _ := verifyScanSignature(key, jobPart, tsPart, sigPart, now); ok {
		// 签名有效（HMAC 一致且 ts 在时间窗内）：确定性识别（置信 1.0）
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "scanner",
			RuleID:     "scanner.signature_valid",
			Category:   "OBSERVE",
			Severity:   "INFO",
			Message:    "api scan traffic identified (signature verified)",
			Evidence:   map[string]string{"job_id": jobID, "verification": "signature"},
			Confidence: 1.0,
		})
		return
	}
	// 签名无效/过期/畸形：不打 scanner 标（防伪造扫描标记绕过学习样本排除），
	// 另产 api_authz 级伪造嫌疑明细（证据含未信任的 job 标识与失败原因供排查，不含签名值）
	_, reason := verifyScanSignature(key, jobPart, tsPart, sigPart, now)
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector: "api_authz",
		RuleID:   "scanner.signature_forged",
		Category: "OBSERVE",
		Severity: "MEDIUM",
		Message:  "scan header present with invalid signature (forgery suspect)",
		Evidence: map[string]string{
			"job_id_untrusted": jobID,
			"reason":           reason,
		},
		ScoreDelta: 10,
	})
}

// verifyScanSignature 校验扫描签名（与 apiscan.Signer.Verify 同一构造）：
// ts 须可解析且与 now 偏差在 ±scanSignatureTimeWindow 内（过期/未来超限即拒绝——
// 无时窗签名泄漏后可无限重放）；HMAC-SHA256(key, jobID|ts) 的 hex 与 sigPart 一致
// （jobID/ts 直接按原文参与 HMAC，大小写/前导零差异即判无效，不做归一化宽容）。
// 返回失败原因（malformed_header / timestamp_out_of_window / invalid_signature），
// 供伪造嫌疑明细取证；原因只描述形态，不含签名值与密钥材料。
func verifyScanSignature(key []byte, jobPart, tsPart, sigPart string, now time.Time) (bool, string) {
	if jobPart == "" || tsPart == "" || sigPart == "" {
		return false, "malformed_header"
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return false, "malformed_header"
	}
	sig, err := hex.DecodeString(sigPart)
	if err != nil || len(sig) != sha256.Size {
		return false, "malformed_header"
	}
	if d := now.Sub(time.Unix(ts, 0)); d < -scanSignatureTimeWindow || d > scanSignatureTimeWindow {
		return false, "timestamp_out_of_window"
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(jobPart + "|" + tsPart))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return false, "invalid_signature"
	}
	return true, ""
}

// truncateScanJobID 证据用 job 标识截断（不含签名部分；空值给占位说明）。
func truncateScanJobID(job string) string {
	if job == "" {
		return "(unparseable)"
	}
	if len(job) > maxScanJobIDLen {
		return job[:maxScanJobIDLen]
	}
	return job
}
