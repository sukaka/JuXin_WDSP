// vulnref.go CNNVD/CVE 漏洞编号校验（WAF 规则 CNNVD 兼容性 P1，
// docs/CNNVD_COMPATIBILITY_DESIGN.md §2.1）：格式正则 + 大写归一 + 去重。
package validation

import (
	"fmt"
	"regexp"
	"strings"
)

// 编号格式（冻结契约）：CNNVD-YYYYMM-NNN…（序号 ≥3 位）；CVE-YYYY-NNNN…（序号 ≥4 位）。
var (
	cnnvdIDPattern = regexp.MustCompile(`^CNNVD-\d{6}-\d{3,}$`)
	cveIDPattern   = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
)

// MaxVulnIDsPerRule 单条规则允许标注的同类编号上限（防止 JSONB 数组无界膨胀）。
const MaxVulnIDsPerRule = 20

// NormalizeCNNVDIDs 校验并规范化 CNNVD 编号数组：去空白、大写归一、去重（保序）。
// 任一元素非法即整体报错（中文错误信息直接面向 API 响应）。
func NormalizeCNNVDIDs(ids []string) ([]string, error) {
	return normalizeVulnIDs(ids, cnnvdIDPattern, "CNNVD", "CNNVD-202401-2345")
}

// NormalizeCVEIDs 校验并规范化 CVE 编号数组：去空白、大写归一、去重（保序）。
func NormalizeCVEIDs(ids []string) ([]string, error) {
	return normalizeVulnIDs(ids, cveIDPattern, "CVE", "CVE-2024-0001")
}

// ValidateCNNVDID 校验单个 CNNVD 编号并返回大写归一值。
func ValidateCNNVDID(id string) (string, error) {
	norm, err := normalizeVulnIDs([]string{id}, cnnvdIDPattern, "CNNVD", "CNNVD-202401-2345")
	if err != nil {
		return "", err
	}
	return norm[0], nil
}

// ValidateCVEID 校验单个 CVE 编号并返回大写归一值；空串原样返回（可选字段）。
func ValidateCVEID(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", nil
	}
	norm, err := normalizeVulnIDs([]string{id}, cveIDPattern, "CVE", "CVE-2024-0001")
	if err != nil {
		return "", err
	}
	return norm[0], nil
}

func normalizeVulnIDs(ids []string, pattern *regexp.Regexp, label, example string) ([]string, error) {
	if len(ids) == 0 {
		return []string{}, nil
	}
	if len(ids) > MaxVulnIDsPerRule {
		return nil, fmt.Errorf("%s编号数量超限（最多 %d 个）", label, MaxVulnIDsPerRule)
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, raw := range ids {
		v := strings.ToUpper(strings.TrimSpace(raw))
		if !pattern.MatchString(v) {
			return nil, fmt.Errorf("%s编号格式非法 %q（应为 %s 形式）", label, raw, example)
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out, nil
}
