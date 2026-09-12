package reports

import (
	"fmt"
	"strings"
	"time"
)

// DefaultReportNoFormat 默认报告编号格式。
const DefaultReportNoFormat = "JZ-{YYYYMM}-{SEQ}"

// FormatReportNo 按模板格式渲染报告编号。
// 支持的占位符：
//   - {YYYYMM}：报告请求时间所属年月（UTC，如 202607）
//   - {SEQ}：该月序号（至少4位，不足补零）
//
// 其余内容原样保留；空格式回退为默认格式。
func FormatReportNo(format string, t time.Time, seq int) string {
	if format == "" {
		format = DefaultReportNoFormat
	}
	if seq < 0 {
		seq = 0
	}
	out := strings.ReplaceAll(format, "{YYYYMM}", t.UTC().Format("200601"))
	out = strings.ReplaceAll(out, "{SEQ}", fmt.Sprintf("%04d", seq))
	return out
}
