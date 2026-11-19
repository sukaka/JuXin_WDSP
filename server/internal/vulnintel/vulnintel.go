// Package vulnintel 提供漏洞情报提醒（VULN_INTEL MVP）：
// NVD 每日同步 PHP 相关漏洞（纯下行）、离线 JSON 导入、技术栈订阅去重提醒
// （VULN_INTEL_NEW 系统告警）、应用技术栈映射维护与订阅设置。
//
// 边界（docs/VULN_INTEL_DESIGN.md 全量能力留作后续迭代）：
//   - 在线同步仅访问硬编码 NVD API 2.0 地址，不接受自定义 URL；
//   - 只提醒，不自动创建 WAF 规则、虚拟补丁或阻断动作；
//   - 技术栈首版手动维护（application_technologies）。
package vulnintel

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 来源词表。
const (
	SourceNVD    = "NVD"
	SourceManual = "MANUAL"
)

// 级别词表（severity 由最高 CVSS 分值派生，见 SeverityFromScore）。
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityNone     = "NONE"
)

// 同步状态词表。
const (
	SyncStatusIdle    = "IDLE"
	SyncStatusSuccess = "SUCCESS"
	SyncStatusFailed  = "FAILED"
)

// 字段上限（防御性截断，错误不静默——超限在导入校验期拒绝）。
const (
	MaxTitleLen   = 500
	MaxSummaryLen = 20000
	MaxReferences = 50
	MaxRefLen     = 2048
	// MaxRawBytes 是 raw_json 截断上限（保留追溯证据同时防止超大载荷落库）。
	MaxRawBytes = 64 * 1024
)

// 错误。
var (
	ErrNotFound     = errors.New("vuln advisory not found")
	ErrInvalidInput = errors.New("invalid vuln intel input")
	ErrSyncRunning  = errors.New("vuln intel sync already running")
)

// cvePattern 校验 CVE 编号（归一化为大写后匹配）。
var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,7}$`)

// techPattern 校验技术名（与 application_technologies_name_chk 同口径：小写 1-64）。
var techPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,63}$`)

// Advisory 是一条漏洞情报。
type Advisory struct {
	ID             uuid.UUID  `json:"id"`
	CVEID          string     `json:"cve_id"`
	Title          string     `json:"title"`
	Summary        string     `json:"summary"`
	Severity       string     `json:"severity"`
	CVSSScore      *float64   `json:"cvss_score"`
	PublishedAt    *time.Time `json:"published_at"`
	LastModifiedAt *time.Time `json:"last_modified_at"`
	TechTags       []string   `json:"tech_tags"`
	References     []string   `json:"references"`
	Source         string     `json:"source"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// SyncState 是某情报源的同步状态（vuln_intel_sync_state 行）。
type SyncState struct {
	Source          string     `json:"source"`
	LastSyncAt      *time.Time `json:"last_sync_at"`
	LastWindowStart *time.Time `json:"last_window_start"`
	LastWindowEnd   *time.Time `json:"last_window_end"`
	RecordsUpserted int        `json:"records_upserted"`
	Status          string     `json:"status"`
	FailureMessage  string     `json:"failure_message"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// AppRef 是受影响应用投影（提醒文案与详情交叉查询用）。
type AppRef struct {
	ID   uuid.UUID `json:"application_id"`
	Code string    `json:"code"`
	Name string    `json:"name"`
}

// TechAsset 是应用技术栈映射项（tech-assets 接口契约）。
type TechAsset struct {
	ApplicationID uuid.UUID `json:"application_id"`
	Code          string    `json:"code"`
	Name          string    `json:"name"`
	TechTags      []string  `json:"tech_tags"`
}

// NormalizeCVE 归一化 CVE 编号（去空白、大写）。
func NormalizeCVE(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}

// ValidateCVE 校验 CVE 编号形态。
func ValidateCVE(cveID string) error {
	if !cvePattern.MatchString(cveID) {
		return fmt.Errorf("%w: cve_id 形态非法（期望 CVE-YYYY-NNNN+）: %q", ErrInvalidInput, cveID)
	}
	return nil
}

// ValidateTechName 校验技术名（小写 1-64，字符集 a-z0-9._+-）。
func ValidateTechName(tech string) error {
	if !techPattern.MatchString(tech) {
		return fmt.Errorf("%w: tech_name 仅允许小写字母开头的 a-z0-9._+-（1-64 字符）: %q", ErrInvalidInput, tech)
	}
	return nil
}

// IsValidSeverity 校验级别词表。
func IsValidSeverity(s string) bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityNone:
		return true
	}
	return false
}

// IsValidSource 校验来源词表。
func IsValidSource(s string) bool {
	return s == SourceNVD || s == SourceManual
}

// SeverityFromScore 按最高 CVSS 分值派生级别（确定性映射）。
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// severityRank 返回级别序（NONE/未知为 0，任何 min_severity 都不放行）。
func severityRank(s string) int {
	switch strings.ToUpper(s) {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// SeverityGte 判断情报级别是否达到订阅最低级别。
func SeverityGte(severity, minSeverity string) bool {
	return severityRank(severity) >= severityRank(minSeverity) && severityRank(severity) > 0
}

// ValidateReferenceURL 校验漏洞参考链接仅允许 http:// 或 https:// 协议，
// 拒绝 javascript:/data:/file:/ftp: 等危险或非 Web 协议以及控制字符。
func ValidateReferenceURL(raw string) error {
	for i := 0; i < len(raw); i++ {
		if raw[i] < 0x20 || raw[i] == 0x7f {
			return fmt.Errorf("%w: reference URL 包含非法控制字符", ErrInvalidInput)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: reference URL 格式非法: %v", ErrInvalidInput, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: reference URL 仅允许 http:// 或 https:// 协议: %q", ErrInvalidInput, u.Scheme)
	}
	if strings.TrimSpace(u.Host) == "" {
		return fmt.Errorf("%w: reference URL 缺少主机名", ErrInvalidInput)
	}
	return nil
}

// ValidateAdvisory 校验并归一化情报条目（导入/同步共用入口）。
// 归一化：cve_id 大写、tech_tags 去重排序、空切片非 nil。
func ValidateAdvisory(a *Advisory) error {
	a.CVEID = NormalizeCVE(a.CVEID)
	if err := ValidateCVE(a.CVEID); err != nil {
		return err
	}
	a.Title = strings.TrimSpace(a.Title)
	if a.Title == "" {
		a.Title = a.CVEID
	}
	if len(a.Title) > MaxTitleLen {
		return fmt.Errorf("%w: title 超过 %d 字符上限", ErrInvalidInput, MaxTitleLen)
	}
	if len(a.Summary) > MaxSummaryLen {
		return fmt.Errorf("%w: summary 超过 %d 字符上限", ErrInvalidInput, MaxSummaryLen)
	}
	a.Severity = strings.ToUpper(strings.TrimSpace(a.Severity))
	if !IsValidSeverity(a.Severity) {
		return fmt.Errorf("%w: severity 词表非法: %q", ErrInvalidInput, a.Severity)
	}
	if a.CVSSScore != nil && (*a.CVSSScore < 0 || *a.CVSSScore > 10) {
		return fmt.Errorf("%w: cvss_score 须在 [0,10] 区间", ErrInvalidInput)
	}
	if a.PublishedAt != nil && a.LastModifiedAt != nil && a.LastModifiedAt.Before(*a.PublishedAt) {
		return fmt.Errorf("%w: last_modified_at 早于 published_at", ErrInvalidInput)
	}
	if len(a.References) > MaxReferences {
		return fmt.Errorf("%w: references 超过 %d 条上限", ErrInvalidInput, MaxReferences)
	}
	seenRef := map[string]bool{}
	refs := make([]string, 0, len(a.References))
	for _, ref := range a.References {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if len(ref) > MaxRefLen {
			return fmt.Errorf("%w: 单条 reference 超过 %d 字符上限", ErrInvalidInput, MaxRefLen)
		}
		if err := ValidateReferenceURL(ref); err != nil {
			return err
		}
		if seenRef[ref] {
			continue
		}
		seenRef[ref] = true
		refs = append(refs, ref)
	}
	a.References = refs
	if len(a.TechTags) == 0 {
		return fmt.Errorf("%w: tech_tags 不能为空（无订阅归属的情报不入库）", ErrInvalidInput)
	}
	seenTech := map[string]bool{}
	tags := make([]string, 0, len(a.TechTags))
	for _, tag := range a.TechTags {
		tag = strings.ToLower(strings.TrimSpace(tag))
		if err := ValidateTechName(tag); err != nil {
			return err
		}
		if seenTech[tag] {
			continue
		}
		seenTech[tag] = true
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	a.TechTags = tags
	if !IsValidSource(a.Source) {
		return fmt.Errorf("%w: source 词表非法: %q", ErrInvalidInput, a.Source)
	}
	return nil
}

// HasTech 判断情报是否归属某技术标签。
func (a *Advisory) HasTech(tech string) bool {
	for _, t := range a.TechTags {
		if t == tech {
			return true
		}
	}
	return false
}
