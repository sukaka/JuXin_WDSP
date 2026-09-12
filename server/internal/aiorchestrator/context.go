// context.go 上下文预算管理与自动压缩。
package aiorchestrator

import (
	"strings"
)

// CompressionThresholds 压缩阈值（按模型上下文窗口比例）。
type CompressionThresholds struct {
	Warn      float64 // 预警（默认 0.70）
	Compress  float64 // 自动压缩（默认 0.80）
	ForceTrim float64 // 强制裁剪（默认 0.90）
}

// DefaultThresholds 默认阈值。
func DefaultThresholds() CompressionThresholds {
	return CompressionThresholds{Warn: 0.70, Compress: 0.80, ForceTrim: 0.90}
}

// ContextState 会话上下文状态。
type ContextState struct {
	Summary     string // 历史摘要（压缩产物）
	RecentCount int    // 最近保留消息数
	TokenCount  int    // 当前估算 Token
	Compressed  int    // 已压缩次数
}

// BudgetResult 预算检查结果。
type BudgetResult struct {
	Usage        float64 // 当前使用比例
	NeedWarn     bool
	NeedCompress bool
	NeedTrim     bool
}

// CheckBudget 检查上下文使用是否触发阈值。
func CheckBudget(tokens, contextWindow int, th CompressionThresholds) BudgetResult {
	if contextWindow <= 0 {
		contextWindow = 8192
	}
	usage := float64(tokens) / float64(contextWindow)
	return BudgetResult{
		Usage:        usage,
		NeedWarn:     usage >= th.Warn,
		NeedCompress: usage >= th.Compress,
		NeedTrim:     usage >= th.ForceTrim,
	}
}

// EstimateTokens 粗略 Token 估算。
func EstimateTokens(s string) int {
	cjk, other := 0, 0
	for _, r := range s {
		if r > 0x2E7F {
			cjk++
		} else {
			other++
		}
	}
	return cjk*2/3 + other/4 + 1
}

// CompressResult 压缩结果。
type CompressResult struct {
	Summary          string
	BeforeTokens     int
	AfterTokens      int
	PreservedRefs    []string
	DroppedMessages  int
	RetainedMessages int
}

// Compress 确定性压缩：保留最近 keepRecent 条消息与全部证据引用，旧消息生成摘要。
// 约束：不丢失 用户明确要求/权限安全约束/当前任务目标/时间范围/已确认事实/未完成步骤/关键证据引用。
func Compress(messages []ContextMessage, keepRecent int, maxSummaryLen int) CompressResult {
	if keepRecent <= 0 {
		keepRecent = 6
	}
	res := CompressResult{}
	if len(messages) <= keepRecent {
		res.RetainedMessages = len(messages)
		for _, m := range messages {
			res.BeforeTokens += EstimateTokens(m.Content)
		}
		res.AfterTokens = res.BeforeTokens
		return res
	}
	old := messages[:len(messages)-keepRecent]
	recent := messages[len(messages)-keepRecent:]
	var sb strings.Builder
	sb.WriteString("【此前会话摘要】")
	// 提取旧消息中的关键信息（用户问题与证据引用）
	var refs []string
	refRe := citationRe
	for i, m := range old {
		res.BeforeTokens += EstimateTokens(m.Content)
		for _, c := range refRe.FindAllString(m.Content, -1) {
			refs = append(refs, c)
		}
		if m.Role == "user" {
			sb.WriteString("用户问" + itoa(i+1) + "：" + truncateRunes(m.Content, 80) + "；")
		}
	}
	if len(refs) > 0 {
		// 去重引用
		seen := map[string]bool{}
		uniq := []string{}
		for _, r := range refs {
			if !seen[r] {
				seen[r] = true
				uniq = append(uniq, r)
			}
		}
		sb.WriteString("涉及证据：" + strings.Join(uniq, " "))
		res.PreservedRefs = uniq
	}
	res.Summary = truncateRunes(sb.String(), maxSummaryLen)
	res.AfterTokens = EstimateTokens(res.Summary)
	for _, m := range recent {
		res.AfterTokens += EstimateTokens(m.Content)
	}
	res.DroppedMessages = len(old)
	res.RetainedMessages = len(recent)
	return res
}

// ContextMessage 上下文消息。
type ContextMessage struct {
	Role    string
	Content string
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
