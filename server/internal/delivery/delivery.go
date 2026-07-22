// Package delivery 提供交付检查：执行 ≥20 项交付检查、落库与导出。
//
// 检查项分关键/非关键：任一关键项 FAIL → 整体 FAIL；
// 无关键 FAIL 但存在 WARNING 或非关键 FAIL → 整体 WARNING；否则 PASS。
package delivery

import (
	"errors"
	"fmt"
)

// 检查结果
const (
	ResultPass    = "PASS"
	ResultWarning = "WARNING"
	ResultFail    = "FAIL"
	ResultNA      = "NOT_APPLICABLE"
)

// 整体结果
const (
	OverallPending = "PENDING"
	OverallPass    = "PASS"
	OverallWarning = "WARNING"
	OverallFail    = "FAIL"
)

// 检查类别
const (
	CategoryRuntime    = "运行状态"
	CategorySecurity   = "安全配置"
	CategoryAccount    = "账号权限"
	CategoryProtection = "防护能力"
	CategoryCompliance = "合规交付"
	CategoryQuality    = "质量保障"
)

// 错误
var (
	ErrNotFound      = errors.New("delivery check not found")
	ErrInvalidFormat = errors.New("invalid export format")
)

// ItemResult 单项检查结果（落 delivery_check_results）。
type ItemResult struct {
	Key      string                 `json:"item_key"`
	Name     string                 `json:"item_name"`
	Category string                 `json:"category"`
	Critical bool                   `json:"critical"`
	Result   string                 `json:"result"`
	Message  string                 `json:"message"`
	Details  map[string]interface{} `json:"details,omitempty"`
}

// Overall 计算整体结果（纯函数，单测直接覆盖）：
//   - 任一关键项 FAIL → FAIL
//   - 否则任一 WARNING 或非关键 FAIL → WARNING
//   - 否则 PASS（NOT_APPLICABLE 不参与判定）
func Overall(items []ItemResult) string {
	warn := false
	for _, it := range items {
		switch it.Result {
		case ResultFail:
			if it.Critical {
				return OverallFail
			}
			warn = true
		case ResultWarning:
			warn = true
		}
	}
	if warn {
		return OverallWarning
	}
	return OverallPass
}

// Counts 统计各结果数量（PASS/WARNING/FAIL；NOT_APPLICABLE 计入总数但不计入三档）。
func Counts(items []ItemResult) (pass, warning, fail int) {
	for _, it := range items {
		switch it.Result {
		case ResultPass:
			pass++
		case ResultWarning:
			warning++
		case ResultFail:
			fail++
		}
	}
	return pass, warning, fail
}

// Check 交付检查项定义。
type Check struct {
	Key      string
	Name     string
	Category string
	Critical bool
	// Run 执行检查，返回结果/消息/细节。内部错误必须返回 FAIL 或 WARNING 并说明原因，不得静默。
	Run func(ctx *RunContext) ItemResult
}

// item 构造单项结果。
func (c Check) item(result, message string, details map[string]interface{}) ItemResult {
	if len(message) > 500 {
		message = message[:500]
	}
	return ItemResult{
		Key: c.Key, Name: c.Name, Category: c.Category, Critical: c.Critical,
		Result: result, Message: message, Details: details,
	}
}

// pass / warn / fail / na 便捷构造。
func (c Check) pass(msg string, details map[string]interface{}) ItemResult {
	return c.item(ResultPass, msg, details)
}
func (c Check) warn(msg string, details map[string]interface{}) ItemResult {
	return c.item(ResultWarning, msg, details)
}
func (c Check) fail(msg string, details map[string]interface{}) ItemResult {
	return c.item(ResultFail, msg, details)
}
func (c Check) na(msg string) ItemResult {
	return c.item(ResultNA, msg, nil)
}

// failErr 内部错误转 FAIL（不静默吞错）。
func (c Check) failErr(prefix string, err error) ItemResult {
	return c.item(ResultFail, fmt.Sprintf("%s：%v", prefix, err), nil)
}
