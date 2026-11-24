// engine_test.go 暴露面判定规则矩阵表驱动测试：MANUAL 优先 / 公网多日 HIGH /
// 公网单日少量 MEDIUM / 仅合作方 / 仅内网达阈值 / 流量不足回落 DNS 配置 /
// NXDOMAIN / 旁路部署证据 / 全不足 UNKNOWN / 流量与域名冲突时流量优先且证据注明。
package apiexposure

import (
	"strings"
	"testing"
)

func intPtr(v int) *int { return &v }

// evidenceTypes 提取证据类型序列（断言辅助）。
func evidenceTypes(a Assessment) []string {
	out := []string{}
	for _, e := range a.Evidence {
		out = append(out, e.Type)
	}
	return out
}

// hasEvidenceType 证据链是否含指定类型。
func hasEvidenceType(a Assessment, typ string) bool {
	for _, e := range a.Evidence {
		if e.Type == typ {
			return true
		}
	}
	return false
}

func TestEvaluateMatrix(t *testing.T) {
	base := EvidenceInput{
		WindowDays:     7,
		Hostname:       "api.example.com",
		HTTPSPort:      intPtr(443),
		DeploymentMode: DeployReverseProxy,
		MinRequests:    50,
		MinDays:        2,
	}
	cases := []struct {
		name       string
		mutate     func(in *EvidenceInput)
		verdict    string
		source     string
		confidence string
		evidence   string // 首个证据类型（空 = 不断言）
		mustHave   string // 证据链必须包含的类型（空 = 不断言）
	}{
		{
			name: "MANUAL 来源优先不改判",
			mutate: func(in *EvidenceInput) {
				in.ExistingValue = VerdictPublic
				in.ExistingSource = SourceManual
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 5, Requests: 500, UniqueSources: 3}}
			},
			verdict: VerdictPublic, source: SourceManual, confidence: ConfidenceHigh, evidence: "manual",
		},
		{
			name: "锁定等同人工优先",
			mutate: func(in *EvidenceInput) {
				in.Locked = true
				in.ExistingValue = VerdictInternal
				in.ExistingSource = "AUTO"
			},
			verdict: VerdictInternal, source: SourceManual, confidence: ConfidenceHigh, evidence: "manual",
		},
		{
			name: "锁定无人工值时结论 UNKNOWN 但来源 MANUAL",
			mutate: func(in *EvidenceInput) {
				in.Locked = true
			},
			verdict: VerdictUnknown, source: SourceManual, confidence: ConfidenceHigh, evidence: "manual",
		},
		{
			name: "公网来源多日 HIGH",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePublic, Days: 5, Requests: 30, UniqueSources: 3}}
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_public",
		},
		{
			name: "公网来源请求量达阈值单日也 HIGH",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePublic, Days: 1, Requests: 60, UniqueSources: 2}}
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_public",
		},
		{
			name: "公网来源单日少量 MEDIUM",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePublic, Days: 1, Requests: 5, UniqueSources: 1}}
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceMedium, evidence: "traffic_public",
		},
		{
			name: "公网与内网并存时公网优先",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{
					{Scope: ScopePublic, Days: 2, Requests: 10, UniqueSources: 2},
					{Scope: ScopeInternal, Days: 5, Requests: 500, UniqueSources: 8},
				}
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_public",
		},
		{
			name: "仅合作方来源单日 MEDIUM",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePartner, Days: 1, Requests: 12, UniqueSources: 2}}
			},
			verdict: VerdictPartner, source: SourceTraffic, confidence: ConfidenceMedium, evidence: "traffic_partner",
		},
		{
			name: "仅合作方来源多日稳定 HIGH",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePartner, Days: 3, Requests: 40, UniqueSources: 2}}
			},
			verdict: VerdictPartner, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_partner",
		},
		{
			name: "仅内网达阈值 MEDIUM",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 3, Requests: 120, UniqueSources: 6}}
			},
			verdict: VerdictInternal, source: SourceTraffic, confidence: ConfidenceMedium, evidence: "traffic_internal",
		},
		{
			name: "仅内网量大自然日多 HIGH",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 5, Requests: 300, UniqueSources: 20}}
			},
			verdict: VerdictInternal, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_internal",
		},
		{
			name: "内网未达请求阈值回落 DNS 公网可解析 PUBLIC/LOW",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 3, Requests: 20, UniqueSources: 2}}
				in.DNSResult = DNSPublic
			},
			verdict: VerdictPublic, source: SourceConfig, confidence: ConfidenceLow,
			evidence: "traffic_insufficient", mustHave: "config_dns",
		},
		{
			name: "内网未达天数阈值回落 DNS 仅私网 INTERNAL/LOW",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 1, Requests: 500, UniqueSources: 2}}
				in.DNSResult = DNSPrivateOnly
			},
			verdict: VerdictInternal, source: SourceConfig, confidence: ConfidenceLow,
			evidence: "traffic_insufficient", mustHave: "config_dns",
		},
		{
			name: "无流量域名公网可解析 PUBLIC/LOW",
			mutate: func(in *EvidenceInput) {
				in.DNSResult = DNSPublic
			},
			verdict: VerdictPublic, source: SourceConfig, confidence: ConfidenceLow,
			evidence: "traffic_insufficient", mustHave: "config_dns",
		},
		{
			name: "无流量域名 NXDOMAIN INTERNAL/LOW",
			mutate: func(in *EvidenceInput) {
				in.DNSResult = DNSNXDomain
			},
			verdict: VerdictInternal, source: SourceConfig, confidence: ConfidenceLow, mustHave: "config_dns",
		},
		{
			name: "DNS 查询失败不伪造结论 UNKNOWN/LOW 且证据注明",
			mutate: func(in *EvidenceInput) {
				in.DNSResult = DNSError
			},
			verdict: VerdictUnknown, source: SourceConfig, confidence: ConfidenceLow,
			mustHave: "config_dns_error",
		},
		{
			name: "MIRROR 旁路部署记录证据仍可经 DNS 判定",
			mutate: func(in *EvidenceInput) {
				in.DeploymentMode = DeployMirror
				in.DNSResult = DNSPublic
			},
			verdict: VerdictPublic, source: SourceConfig, confidence: ConfidenceLow,
			mustHave: "deployment_bypass",
		},
		{
			name: "TRANSPARENT 在线串接记入 config_listen 而非旁路 deployment_bypass",
			mutate: func(in *EvidenceInput) {
				in.DeploymentMode = DeployTransparent
			},
			verdict: VerdictUnknown, source: SourceConfig, confidence: ConfidenceLow,
			mustHave: "config_listen",
		},
		{
			name: "无流量无域名全不足 UNKNOWN/LOW",
			mutate: func(in *EvidenceInput) {
				in.Hostname = ""
			},
			verdict: VerdictUnknown, source: SourceConfig, confidence: ConfidenceLow,
			evidence: "traffic_insufficient", mustHave: "insufficient",
		},
		{
			name: "公网流量与内网域名冲突流量优先且证据注明",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopePublic, Days: 3, Requests: 20, UniqueSources: 2}}
				in.DNSResult = DNSNXDomain
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceHigh,
			evidence: "traffic_public", mustHave: "traffic_priority",
		},
		{
			name: "内网流量与公网域名冲突流量优先且证据注明",
			mutate: func(in *EvidenceInput) {
				in.Buckets = []ScopeBucket{{Scope: ScopeInternal, Days: 3, Requests: 120, UniqueSources: 6}}
				in.DNSResult = DNSPublic
			},
			verdict: VerdictInternal, source: SourceTraffic, confidence: ConfidenceMedium,
			evidence: "traffic_internal", mustHave: "traffic_priority",
		},
		{
			name: "历史 AUTO 维度不阻断引擎改判",
			mutate: func(in *EvidenceInput) {
				in.ExistingValue = VerdictInternal
				in.ExistingSource = "AUTO"
				in.Buckets = []ScopeBucket{{Scope: ScopePublic, Days: 2, Requests: 10, UniqueSources: 1}}
			},
			verdict: VerdictPublic, source: SourceTraffic, confidence: ConfidenceHigh, evidence: "traffic_public",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := base
			c.mutate(&in)
			a := Evaluate(in)
			if a.Verdict != c.verdict || a.Source != c.source || a.Confidence != c.confidence {
				t.Fatalf("Evaluate = (%s, %s, %s), want (%s, %s, %s)",
					a.Verdict, a.Source, a.Confidence, c.verdict, c.source, c.confidence)
			}
			if len(a.Evidence) == 0 {
				t.Fatal("evidence must not be empty")
			}
			if c.evidence != "" && a.Evidence[0].Type != c.evidence {
				t.Fatalf("first evidence = %s, want %s (all=%v)", a.Evidence[0].Type, c.evidence, evidenceTypes(a))
			}
			if c.mustHave != "" && !hasEvidenceType(a, c.mustHave) {
				t.Fatalf("evidence types %v missing %s", evidenceTypes(a), c.mustHave)
			}
			for _, e := range a.Evidence {
				if strings.TrimSpace(e.Summary) == "" {
					t.Fatalf("evidence %s has empty summary", e.Type)
				}
			}
		})
	}
}

// TestEvaluateDefaults 阈值缺省回退（MinRequests/MinDays/WindowDays 零值时取默认）。
func TestEvaluateDefaults(t *testing.T) {
	a := Evaluate(EvidenceInput{
		Buckets: []ScopeBucket{{Scope: ScopeInternal, Days: 2, Requests: 60, UniqueSources: 3}},
	})
	if a.Verdict != VerdictInternal || a.Confidence != ConfidenceMedium {
		t.Fatalf("default thresholds: got (%s, %s), want (INTERNAL, MEDIUM)", a.Verdict, a.Confidence)
	}
}

// TestConfidenceScore 置信度数值映射（维度表写入口径）。
func TestConfidenceScore(t *testing.T) {
	if ConfidenceScore(ConfidenceLow) != 0.3 || ConfidenceScore(ConfidenceMedium) != 0.6 ||
		ConfidenceScore(ConfidenceHigh) != 0.9 || ConfidenceScore("X") != 0 {
		t.Fatal("confidence score mapping broken")
	}
}

// TestEvaluateTransparentIsNotPassiveBypass 验证 P2-1：TRANSPARENT 是内联串接模式，
// 仅 MIRROR 产出 deployment_bypass，TRANSPARENT 正常产出 config_listen 证据。
func TestEvaluateTransparentIsNotPassiveBypass(t *testing.T) {
	a := Evaluate(EvidenceInput{
		WindowDays:     7,
		Hostname:       "tpx.example.com",
		HTTPPort:       intPtr(80),
		HTTPSPort:      intPtr(443),
		DeploymentMode: DeployTransparent,
		DNSResult:      DNSPublic,
	})
	if a.Verdict != VerdictPublic || a.Source != SourceConfig {
		t.Fatalf("Evaluate(TRANSPARENT) = (%s, %s), want (PUBLIC, CONFIG)", a.Verdict, a.Source)
	}
	if hasEvidenceType(a, "deployment_bypass") {
		t.Fatalf("TRANSPARENT must not emit deployment_bypass evidence: %+v", a.Evidence)
	}
	if !hasEvidenceType(a, "config_listen") {
		t.Fatalf("TRANSPARENT must emit config_listen evidence: %+v", a.Evidence)
	}
}
