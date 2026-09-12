// samples_scanner_test.go 扫描流量样本排除规则单测（W6-D / P1-07 学习隔离）。
// 规则本体在 samples.go（本波仅小改该文件）；details 含 detector=scanner 明细
// （网关校验 X-JiuZhang-Scan 签名头后产出）的事件一律不进学习样本。
// 本波网关侧识别尚未上线，规则处于待命态——本测试锁定其生效语义。
package apiruntime

import (
	"testing"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// TestSampleVerdict_ScannerTraffic 扫描标记事件一律排除，且优先于其他规则
// （来源身份优先：扫描流量无论放行/阻断/WAF 命中都不是真实流量学习样本）。
func TestSampleVerdict_ScannerTraffic(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
	}{
		{"放行扫描流量", Record{FinalAction: "ALLOW", ResponseStatus: 200,
			Details: []dsctx.DetectorMatch{{Detector: "scanner", RuleID: "x-jiuzhang-scan"}}}},
		{"被阻断的扫描流量", Record{FinalAction: "BLOCK",
			Details: []dsctx.DetectorMatch{{Detector: "scanner", RuleID: "x-jiuzhang-scan"}}}},
		{"扫描流量叠加WAF命中", Record{FinalAction: "ALLOW", Details: []dsctx.DetectorMatch{
			{Detector: "waf", RuleID: "942100"}, {Detector: "scanner", RuleID: "x-jiuzhang-scan"}}}},
		{"5xx扫描流量", Record{FinalAction: "ALLOW", ResponseStatus: 500,
			Details: []dsctx.DetectorMatch{{Detector: "scanner", RuleID: "x-jiuzhang-scan"}}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			accepted, reason := sampleVerdict(&c.rec)
			if accepted || reason != ExcludeReasonScannerTraffic {
				t.Fatalf("verdict=(%v,%q), want (false,%q)", accepted, reason, ExcludeReasonScannerTraffic)
			}
		})
	}
	// 无扫描明细的相似流量不受影响（回归）
	accepted, _ := sampleVerdict(&Record{FinalAction: "ALLOW", ResponseStatus: 200})
	if !accepted {
		t.Fatal("normal traffic should still be accepted")
	}
}
