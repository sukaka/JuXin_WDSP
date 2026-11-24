// engine.go API 网络暴露面判定引擎：规则矩阵纯函数（无 IO，表驱动单测）。
//
// 判定优先级（高→低）：
//  1. MANUAL：classification_locked 或现存 source='MANUAL' → 引擎不改维度，
//     仅产评估明细（verdict=人工值，source=MANUAL）；
//  2. TRAFFIC_OBSERVED：观察窗内来源桶（scope×天数×请求数×去重指纹数）；
//     公网来源 → PUBLIC；仅合作方出口 CIDR → PARTNER；仅内网且达量达日 → INTERNAL；
//  3. CONFIG（流量不足回落）：域名经公网 DNS 可解析到公网 IP → PUBLIC(LOW)；
//     不可公网解析（NXDOMAIN/仅私网）→ INTERNAL(LOW)；MIRROR/TRANSPARENT 旁路
//     部署只记证据不单独出判定；
//  4. 以上都不足 → UNKNOWN(LOW)。
//
// 流量与配置冲突时以实际观测流量为准，并在证据中注明。
package apiexposure

import (
	"fmt"
	"strings"
)

// 判定结论词表（api_exposure_assessments.verdict；应用层校验不落 CHECK）。
const (
	VerdictInternal = "INTERNAL"
	VerdictPartner  = "PARTNER"
	VerdictPublic   = "PUBLIC"
	VerdictUnknown  = "UNKNOWN"
)

// 判定来源词表（api_exposure_assessments.source / api_classification_dimensions.source）。
const (
	SourceManual  = "MANUAL"           // 人工确认（引擎永不覆盖）
	SourceTraffic = "TRAFFIC_OBSERVED" // 流量观测证据
	SourceConfig  = "CONFIG"           // 配置证据（域名解析/部署模式）
)

// 置信度词表（api_exposure_assessments.confidence）。
const (
	ConfidenceLow    = "LOW"
	ConfidenceMedium = "MEDIUM"
	ConfidenceHigh   = "HIGH"
)

// ConfidenceScore 置信度 → 分类维度表数值映射（0.3/0.6/0.9；未知值 0）。
func ConfidenceScore(c string) float64 {
	switch c {
	case ConfidenceLow:
		return 0.3
	case ConfidenceMedium:
		return 0.6
	case ConfidenceHigh:
		return 0.9
	}
	return 0
}

// 来源范围词表（api_endpoint_source_buckets.scope / api_endpoint_source_seen.scope；
// INTERNAL/PUBLIC 与 apigeo.ClassifyIPScope 输出口径一致，PARTNER 由引擎侧叠加
// 合作方出口 CIDR 判定）。
const (
	ScopeInternal = "INTERNAL"
	ScopePublic   = "PUBLIC"
	ScopePartner  = "PARTNER"
)

// 部署模式词表（applications.deployment_mode，镜像现有四值）。
const (
	DeployReverseProxy = "REVERSE_PROXY"
	DeployRouted       = "ROUTED"
	DeployMirror       = "MIRROR"
	DeployTransparent  = "TRANSPARENT"
)

// 仅内网来源 HIGH 置信加码倍数：请求量 ≥ minRequests×internalHighRequestsFactor
// 且覆盖自然日 ≥ minDays×internalHighDaysFactor 时 HIGH（量大且日多为稳定口径）。
const (
	internalHighRequestsFactor = 4
	internalHighDaysFactor     = 2
)

// EvidenceItem 证据明细（api_exposure_assessments.evidence JSONB 元素；
// summary 由引擎直接生成中文，前端展示不做翻译）。
type EvidenceItem struct {
	Type    string `json:"type"`
	Summary string `json:"summary"`
}

// ScopeBucket 观察窗内单来源范围聚合。
type ScopeBucket struct {
	Scope         string // INTERNAL / PUBLIC / PARTNER
	Days          int    // 覆盖自然日数
	Requests      int64  // 窗口内请求总数
	UniqueSources int    // 去重来源指纹数（匿名无指纹流量不计入）
}

// EvidenceInput 引擎证据输入（纯数据，由装配侧从库/设置/DNS 装配）。
type EvidenceInput struct {
	// 观察窗（天，用于证据文案）
	WindowDays int
	// 窗口内来源范围聚合（空 = 窗口内无流量）
	Buckets []ScopeBucket
	// 现存 EXPOSURE 分类（人工确认优先判定用）
	ExistingValue  string // 现存维度值（空 = 无维度行）
	ExistingSource string // 现存维度来源
	Locked         bool   // api_endpoints.classification_locked
	// 配置证据
	Hostname       string // 归属域名（空 = 未归属/无 host）
	HTTPPort       *int   // 监听 HTTP 端口（未知为 nil）
	HTTPSPort      *int   // 监听 HTTPS 端口（未知为 nil）
	DeploymentMode string // REVERSE_PROXY / ROUTED / MIRROR / TRANSPARENT（空 = 未知）
	DNSResult      string // 公网 DNS 视角（dns.go 词表；空 = 未解析/未启用）
	// 判定阈值（引擎配置）
	MinRequests int64 // 默认 50
	MinDays     int   // 默认 2
}

// Assessment 一次评估结论。
type Assessment struct {
	Verdict    string
	Source     string
	Confidence string
	Evidence   []EvidenceItem
}

// verdictLabel 判定值中文标签（证据文案用）。
func verdictLabel(v string) string {
	switch v {
	case VerdictInternal:
		return "内网"
	case VerdictPartner:
		return "合作方"
	case VerdictPublic:
		return "公网"
	case VerdictUnknown:
		return "未知"
	}
	return v
}

// bucketOf 取指定范围的来源桶（无该范围返回零值）。
func bucketOf(buckets []ScopeBucket, scope string) ScopeBucket {
	for _, b := range buckets {
		if b.Scope == scope {
			return b
		}
	}
	return ScopeBucket{Scope: scope}
}

// Evaluate 按规则矩阵判定暴露面（纯函数；输入证据不足时如实产出 UNKNOWN，
// 不伪造结论）。
func Evaluate(in EvidenceInput) Assessment {
	minReq := in.MinRequests
	if minReq <= 0 {
		minReq = DefaultMinRequests
	}
	minDays := in.MinDays
	if minDays <= 0 {
		minDays = DefaultMinDays
	}
	window := in.WindowDays
	if window <= 0 {
		window = DefaultObservationDays
	}

	// 1. 人工确认优先：锁定或现存 MANUAL → 引擎不改维度，仅产评估明细。
	if in.Locked || in.ExistingSource == SourceManual {
		verdict := in.ExistingValue
		if verdict == "" {
			verdict = VerdictUnknown
		}
		return Assessment{
			Verdict:    verdict,
			Source:     SourceManual,
			Confidence: ConfidenceHigh,
			Evidence: []EvidenceItem{{
				Type:    "manual",
				Summary: fmt.Sprintf("暴露面已经人工确认为「%s」（分类锁定/人工来源），引擎不覆盖", verdictLabel(verdict)),
			}},
		}
	}

	// 2. 流量观测证据（优先级高于配置证据；冲突时注明流量优先）。
	pub := bucketOf(in.Buckets, ScopePublic)
	partner := bucketOf(in.Buckets, ScopePartner)
	internal := bucketOf(in.Buckets, ScopeInternal)
	if pub.Requests > 0 {
		conf := ConfidenceMedium
		if pub.Days >= 2 || pub.Requests >= minReq {
			conf = ConfidenceHigh
		}
		ev := []EvidenceItem{{
			Type:    "traffic_public",
			Summary: fmt.Sprintf("近%d天存在公网来源调用（%d 个来源，覆盖 %d 天）", window, pub.UniqueSources, pub.Days),
		}}
		ev = appendTrafficConflict(ev, in, VerdictPublic)
		return Assessment{Verdict: VerdictPublic, Source: SourceTraffic, Confidence: conf, Evidence: ev}
	}
	if partner.Requests > 0 {
		conf := ConfidenceMedium
		if partner.Days >= minDays {
			conf = ConfidenceHigh // 多日稳定出现
		}
		ev := []EvidenceItem{{
			Type:    "traffic_partner",
			Summary: fmt.Sprintf("近%d天来源均命中合作方出口网段（%d 个来源，覆盖 %d 天），未观测到公网来源", window, partner.UniqueSources, partner.Days),
		}}
		ev = appendTrafficConflict(ev, in, VerdictPartner)
		return Assessment{Verdict: VerdictPartner, Source: SourceTraffic, Confidence: conf, Evidence: ev}
	}
	if internal.Requests >= minReq && internal.Days >= minDays {
		conf := ConfidenceMedium
		if internal.Requests >= minReq*internalHighRequestsFactor && internal.Days >= minDays*internalHighDaysFactor {
			conf = ConfidenceHigh // 量大且覆盖自然日多
		}
		ev := []EvidenceItem{{
			Type:    "traffic_internal",
			Summary: fmt.Sprintf("近%d天仅观测到内网来源调用（共 %d 次请求，覆盖 %d 天）", window, internal.Requests, internal.Days),
		}}
		ev = appendTrafficConflict(ev, in, VerdictInternal)
		return Assessment{Verdict: VerdictInternal, Source: SourceTraffic, Confidence: conf, Evidence: ev}
	}

	// 流量证据不足（可能有少量内网流量但未达阈值）：记入证据链后回落配置判定。
	var ev []EvidenceItem
	total := pub.Requests + partner.Requests + internal.Requests
	if total > 0 {
		ev = append(ev, EvidenceItem{
			Type: "traffic_insufficient",
			Summary: fmt.Sprintf("近%d天流量证据不足（内网 %d 次/覆盖 %d 天，阈值 ≥%d 次且 ≥%d 天；无公网/合作方来源）",
				window, internal.Requests, internal.Days, minReq, minDays),
		})
	} else {
		ev = append(ev, EvidenceItem{
			Type:    "traffic_insufficient",
			Summary: fmt.Sprintf("近%d天未观测到调用流量（API 动态防护管线未开启或无请求）", window),
		})
	}

	// 3. 配置证据回落（仅 MIRROR 镜像旁路为被动旁路观测；TRANSPARENT 为在线串接拦截模式，
	// 具备真实业务域名与监听端口，正常记入 config_listen 配置证据）。
	if in.DeploymentMode == DeployMirror {
		ev = append(ev, EvidenceItem{
			Type:    "deployment_bypass",
			Summary: fmt.Sprintf("旁路观测部署（%s），监听配置不适用", in.DeploymentMode),
		})
	} else if in.Hostname != "" {
		ev = append(ev, EvidenceItem{Type: "config_listen", Summary: listenSummary(in)})
	}
	switch in.DNSResult {
	case DNSPublic:
		ev = append(ev, EvidenceItem{
			Type:    "config_dns",
			Summary: fmt.Sprintf("域名 %s 经公网 DNS 可解析到公网 IP", in.Hostname),
		})
		return Assessment{Verdict: VerdictPublic, Source: SourceConfig, Confidence: ConfidenceLow, Evidence: ev}
	case DNSPrivateOnly, DNSNXDomain:
		ev = append(ev, EvidenceItem{
			Type:    "config_dns",
			Summary: fmt.Sprintf("域名 %s 不可公网解析（%s）", in.Hostname, dnsResultLabel(in.DNSResult)),
		})
		return Assessment{Verdict: VerdictInternal, Source: SourceConfig, Confidence: ConfidenceLow, Evidence: ev}
	case DNSError:
		ev = append(ev, EvidenceItem{
			Type:    "config_dns_error",
			Summary: fmt.Sprintf("公网 DNS 查询失败（域名 %s），不伪造结论", in.Hostname),
		})
	}

	// 4. 全部证据不足。
	ev = append(ev, EvidenceItem{
		Type:    "insufficient",
		Summary: "流量与配置证据均不足，暴露面无法判定",
	})
	return Assessment{Verdict: VerdictUnknown, Source: SourceConfig, Confidence: ConfidenceLow, Evidence: ev}
}

// appendTrafficConflict 流量判定与域名解析冲突时追加「流量优先」证据说明。
func appendTrafficConflict(ev []EvidenceItem, in EvidenceInput, verdict string) []EvidenceItem {
	switch verdict {
	case VerdictPublic:
		if in.DNSResult == DNSPrivateOnly || in.DNSResult == DNSNXDomain {
			ev = append(ev, EvidenceItem{
				Type:    "traffic_priority",
				Summary: fmt.Sprintf("域名 %s 不可公网解析，与公网来源流量证据冲突，以实际观测流量为准", in.Hostname),
			})
		}
	case VerdictInternal, VerdictPartner:
		if in.DNSResult == DNSPublic {
			ev = append(ev, EvidenceItem{
				Type:    "traffic_priority",
				Summary: fmt.Sprintf("域名 %s 公网可解析，与窗口内实际观测来源（%s）冲突，以实际观测流量为准", in.Hostname, verdictLabel(verdict)),
			})
		}
	}
	return ev
}

// listenSummary 监听配置证据文案（含域名与端口；端口未知标注「未登记」）。
func listenSummary(in EvidenceInput) string {
	port := func(p *int) string {
		if p == nil || *p <= 0 {
			return "未登记"
		}
		return fmt.Sprintf("%d", *p)
	}
	mode := in.DeploymentMode
	if mode == "" {
		mode = "未知"
	}
	return fmt.Sprintf("应用域名 %s 监听 HTTP:%s HTTPS:%s（部署模式 %s）",
		in.Hostname, port(in.HTTPPort), port(in.HTTPSPort), mode)
}

// dnsResultLabel DNS 判定结果中文（证据文案用）。
func dnsResultLabel(r string) string {
	switch r {
	case DNSNXDomain:
		return "NXDOMAIN/无公网地址记录"
	case DNSPrivateOnly:
		return "仅解析到内网地址"
	case DNSPublic:
		return "解析到公网地址"
	case DNSError:
		return "查询失败"
	}
	return strings.ToLower(r)
}
