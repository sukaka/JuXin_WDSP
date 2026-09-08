// evidence.go 证据引用与风险校验（事实必须可追溯）。
package aiorchestrator

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// EvidenceItem 一条证据（Tool 结果或查询记录）。
type EvidenceItem struct {
	ID      string      `json:"id"`      // 引用编号 E1..En
	Source  string      `json:"source"`  // 来源（tool code / query 描述）
	Summary string      `json:"summary"` // 一句话摘要
	Detail  interface{} `json:"detail,omitempty"`
}

// EvidenceSet 证据集。
type EvidenceSet struct {
	items []EvidenceItem
}

// NewEvidenceSet 创建证据集。
func NewEvidenceSet() *EvidenceSet { return &EvidenceSet{} }

// Add 追加证据，返回引用编号。
func (s *EvidenceSet) Add(source, summary string, detail interface{}) string {
	id := fmt.Sprintf("E%d", len(s.items)+1)
	s.items = append(s.items, EvidenceItem{ID: id, Source: source, Summary: summary, Detail: detail})
	return id
}

// Items 全部证据。
func (s *EvidenceSet) Items() []EvidenceItem {
	out := make([]EvidenceItem, len(s.items))
	copy(out, s.items)
	return out
}

// ContainsID 引用编号是否存在。
func (s *EvidenceSet) ContainsID(id string) bool {
	for _, it := range s.items {
		if it.ID == id {
			return true
		}
	}
	return false
}

// Count 证据数量。
func (s *EvidenceSet) Count() int { return len(s.items) }

// citationRe 引用格式 [E1] / [E1,E2] / [E12]。
var citationRe = regexp.MustCompile(`\[((?:E\d+)(?:\s*[,，、]\s*E\d+)*)\]`)

// ValidateCitations 校验回答中的引用是否全部存在于证据集。
// 返回 (清理后回答, 无效引用列表)。无效引用的标注被移除（不静默删除内容，追加不确定性声明）。
func (s *EvidenceSet) ValidateCitations(answer string) (string, []string) {
	var invalid []string
	cleaned := citationRe.ReplaceAllStringFunc(answer, func(m string) string {
		inner := citationRe.FindStringSubmatch(m)[1]
		parts := regexp.MustCompile(`[,，、]`).Split(inner, -1)
		valid := []string{}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if s.ContainsID(p) {
				valid = append(valid, p)
			} else {
				invalid = append(invalid, p)
			}
		}
		if len(valid) == 0 {
			return ""
		}
		sort.Strings(valid)
		return "[" + strings.Join(valid, ",") + "]"
	})
	return cleaned, invalid
}

// ComposeEvidenceBlock 生成证据列表文本（供回答尾部）。
func (s *EvidenceSet) ComposeEvidenceBlock() string {
	if len(s.items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n**证据引用**\n")
	for _, it := range s.items {
		b.WriteString(fmt.Sprintf("- [%s] %s：%s\n", it.ID, evidenceSourceDisplayName(it.Source), it.Summary))
	}
	return b.String()
}

func evidenceSourceDisplayName(source string) string {
	names := map[string]string{
		"security_event.get":           "安全事件详情",
		"security_event.search":        "安全事件查询",
		"security_event.statistics":    "安全事件统计",
		"statistics.security_overview": "安全态势概览",
		"statistics.top_source_ips":    "攻击源 IP 排行",
		"log.query":                    "日志查询",
	}
	if name, ok := names[source]; ok {
		return name
	}
	return source
}
