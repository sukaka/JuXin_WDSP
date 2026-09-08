// observe.go 响应结构观测提取（P0-06 响应 Schema 学习生产方）：
// 从响应相位 JSON 解析产物中提取一级字段路径→类型，与 status_code/content_type/
// body_size 组成 ResponseObservation，供管理面按 端点×状态码 合并学习响应 Schema。
// 证据纪律：只含字段路径与类型标签，绝不含值；体量护栏防超大报文撑爆事件。
package response

import (
	"sort"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// 响应结构观测体量护栏。
const (
	// MaxObservedFields 一级字段收录上限（超出按路径排序截断并置 Truncated）。
	MaxObservedFields = 64
	// maxObservedPathLen 单字段路径长度上限（与采集端 structured_path 列宽对齐；
	// 超长路径属异常报文，跳过并置 Truncated，不截断拼出错误 Schema）。
	maxObservedPathLen = 512
)

// BuildObservation 从 ParsedBody（JSON 字段路径→类型全集）提取一级字段观测：
//   - 仅一级：路径不含 "."（users、users[] 属一级；users[].id 等更深层不收录）；
//     根数组的元素形态 "[]" 视为一级；根标量/空对象无一级字段，返回 nil（无观测）；
//   - 护栏：一级字段数 > MaxObservedFields 时按路径排序截断（确定性），
//     路径超 maxObservedPathLen 跳过；两种情形均置 Truncated 说明；
//   - fields 为空（非 JSON/解析失败/空对象）返回 nil，调用方零行为变化。
func BuildObservation(status int, contentType string, bodySize int64, fields map[string]string) *dsctx.ResponseObservation {
	if len(fields) == 0 {
		return nil
	}
	paths := make([]string, 0, len(fields))
	for p := range fields {
		// p == "" 为根值占位（根数组/根标量），非字段；含 "." 为更深层路径
		if p == "" || strings.Contains(p, ".") {
			continue
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		return nil
	}
	sort.Strings(paths) // 确定性顺序（截断可重现）
	obs := &dsctx.ResponseObservation{
		StatusCode:  status,
		ContentType: contentType,
		BodySize:    bodySize,
		Fields:      make(map[string]string, min(len(paths), MaxObservedFields)),
		FieldCount:  len(paths),
	}
	for _, p := range paths {
		if len(obs.Fields) >= MaxObservedFields {
			obs.Truncated = true
			break
		}
		if len(p) > maxObservedPathLen {
			obs.Truncated = true
			continue
		}
		obs.Fields[p] = fields[p]
	}
	if len(obs.Fields) == 0 {
		return nil // 全部路径超长等极端情形：无有效观测
	}
	return obs
}
