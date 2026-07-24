// Package ainoise AI 自动降噪：后台周期把安全事件按确定性指纹聚类为降噪簇，
// 超阈值簇可选经 LLM 做误报评分，疑似误报簇生成 DRAFT 推荐（人工审核）。
// 边界：聚类/计数/折叠全自动；不自动修改 security_events.disposition_status、
// 不自动封禁、不自动启用例外；涉及处置的产物一律 DRAFT。
package ainoise

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strconv"
	"strings"
)

// 事件来源。
const (
	SourceWAF = "WAF"
	SourceAPI = "API"
)

// 簇状态。
const (
	StatusActive     = "ACTIVE"
	StatusSuppressed = "SUPPRESSED"
	StatusResolved   = "RESOLVED"
)

// AI 判定。
const (
	VerdictTruePositive        = "TRUE_POSITIVE"
	VerdictLikelyFalsePositive = "LIKELY_FALSE_POSITIVE"
	VerdictUnknown             = "UNKNOWN"
)

var (
	numericSegment = regexp.MustCompile(`^\d+$`)
	uuidSegment    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hexSegment     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
)

// NormalizeURI 归一化请求路径：去查询串与 fragment；
// 纯数字段 → {n}，UUID 段 → {uuid}，≥16 位 hex/hash 段 → {h}。
// 幂等：对已归一化的输入再次调用结果不变。
func NormalizeURI(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	if raw == "" {
		return "/"
	}
	segs := strings.Split(raw, "/")
	for i, s := range segs {
		switch {
		case s == "":
		case numericSegment.MatchString(s):
			segs[i] = "{n}"
		case uuidSegment.MatchString(s):
			segs[i] = "{uuid}"
		case hexSegment.MatchString(s):
			segs[i] = "{h}"
		}
	}
	return strings.Join(segs, "/")
}

// Fingerprint 计算确定性降噪指纹：
// sha256(source|host|normalized_uri|rule_id或detector_code|client_ip)。
// rule_id 优先于 detector_code（同一事件只取一个判别维度）。
func Fingerprint(source, host, normalizedURI string, ruleID *int, detectorCode, clientIP string) string {
	key := ""
	if ruleID != nil {
		key = "rule:" + strconv.Itoa(*ruleID)
	} else if detectorCode != "" {
		key = "detector:" + detectorCode
	}
	sum := sha256.Sum256([]byte(strings.Join([]string{
		source, strings.ToLower(strings.TrimSpace(host)), normalizedURI, key, strings.TrimSpace(clientIP),
	}, "|")))
	return hex.EncodeToString(sum[:])
}
