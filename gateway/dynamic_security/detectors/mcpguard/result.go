// result.go 结果检查（§1.7/D7 + §5 批次 B2 线契约逐字冻结——B2 直接消费）。
//
// 承诺边界：只对能在转发前完成检查的范围承诺阻断——
//   - 非流式 JSON 响应（缓冲捕获完整）：output_schema 校验（mcp.result_schema_violation）
//   - 值级敏感规则复用（mcp.result_sensitive_value，证据路径+data_type+长度
//     不落值——location=json 与请求侧同一编译产物）；
//   - PROTECT 违规（双闸）→ blocked=true（挂点侧抑制未外发响应，返回 §1.11
//     -32014 错误对象——干净阻断零字节泄漏；SSE 逐消息链同函数判定，该条不发）；
//   - output_schema 缺席 → Schema 校验 SKIPPED（结构预算在协议层照判）；
//     含不支持关键字 → 降级不冒充（不产生 Schema 违规判定）；
//   - data_classification 进证据（CONFIDENTIAL 工具结果命中敏感规则时 severity
//     升级 MEDIUM→HIGH——定级不升动作，动作仍由模式双闸定）；
//   - UNKNOWN 恒不阻断：结果形态不可解析/目录缺席 → 放行（false 返回）不冒充判定。
package mcpguard

import (
	"encoding/json"
	"strconv"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser/mcprpc"
)

// 结果检查预算（遍历护栏——与请求侧扫描预算同思想）。
const (
	maxResultWalkFields = 256 // 结果 JSON 遍历产出字段上限
	maxResultWalkDepth  = 8   // 结果 JSON 遍历深度上限
	maxResultFindings   = 5   // 敏感命中明细上限
)

// EvaluateResult 结果检查（线契约逐字冻结，§5 批次 B2）：
// msg 为请求消息（工具名提取与上下文）；result 为 JSON-RPC 响应 result 成员原文
// （挂点侧提取——非流式经 response 解析产物再序列化，SSE 逐条事件 data 提取）；
// cfg 为单端点作用域配置（ForEndpoint 产物）；valueRules 为值级敏感规则编译产物
// （与请求侧同一编译缓存，location=json）。
// 返回 blocked=true：PROTECT 双闸全真有违规命中（挂点侧阻断/抑制）；否则 false
// （OBSERVE 记录或 UNKNOWN 放行——恒不阻断红线）。
func EvaluateResult(ctx *dsctx.RequestContext, msg *mcprpc.Message, result json.RawMessage, cfg *Config, valueRules []detectors.CompiledSensitiveValueRule, engineProtect bool) (blocked bool) {
	if ctx == nil || msg == nil || cfg == nil {
		return false
	}
	ep := cfg.resolvedEndpoint("")
	if ep == nil || ep.Catalog == nil {
		return false // 未绑定/目录缺席——零行为不冒充判定
	}
	toolName, ok := toolNameFromParams(msg.Params)
	if !ok {
		return false // 工具名不可判定——UNKNOWN 放行
	}
	tool, found := ep.Catalog.Tools[toolName]
	if !found {
		return false // 工具不在册（请求链已判定；结果侧不重复产出）
	}
	doubleGate := ep.Mode == ModeProtect && engineProtect
	blockedOut := false

	// 结果 JSON 解码一次（Schema 校验与值级遍历共用；ParseMessage 口径外输入
	// （响应侧）——解码失败按 UNKNOWN 放行不冒充判定）
	var resultDoc any
	if err := json.Unmarshal(result, &resultDoc); err != nil {
		return false
	}

	// ① output_schema 校验（冻结子集；缺席 SKIPPED、降级不冒充）
	if tool.OutputSchema != nil && !tool.OutputDegraded {
		if violations := ValidateSchema(tool.OutputSchema, resultDoc); len(violations) > 0 {
			first := violations[0]
			blockedOut = rcAddResultFinding(ctx, doubleGate, "mcp.result_schema_violation",
				map[string]string{
					"tool": truncateString(toolName, 128), "rule": first.Rule, "path": first.Path,
					"count": strconv.Itoa(len(violations)),
				})
		}
	}

	// ② 值级敏感规则遍历（location=json；证据路径+data_type+长度不落值；
	// data_classification 联动——CONFIDENTIAL 命中 severity MEDIUM→HIGH）
	if len(valueRules) > 0 {
		scans := 0
		fields := 0
		hits := 0
		walkResultValues(resultDoc, "", 1, &fields, func(path, val string) bool {
			dataType, level, hit := detectors.MatchSensitiveValueRule(val, "json", valueRules, &scans)
			if !hit {
				return true
			}
			hits++
			if hits <= maxResultFindings {
				severity := "MEDIUM"
				if tool.DataClassification == ClassificationConfidential {
					severity = "HIGH" // 定级不升动作（§1.7：动作仍由模式双闸定）
				}
				evidence := map[string]string{
					"tool": truncateString(toolName, 128), "path": path,
					"data_type": dataType, "value_len": strconv.Itoa(len(val)),
					"data_classification": tool.DataClassification,
				}
				if level != "" {
					evidence["level"] = level
				}
				if rcAddResultFindingSev(ctx, doubleGate, "mcp.result_sensitive_value", severity, evidence) {
					blockedOut = true
				}
			}
			return hits < maxResultFindings && scans < 512
		})
	}
	return blockedOut
}

// rcAddResultFinding 结果侧违规 Finding（双闸全真 Category=BLOCK + mcp_error_code
// -32014 注入（apiprotect 非流式抑制分流）；否则 OBSERVE 拟动作）。返回是否定案。
func rcAddResultFinding(ctx *dsctx.RequestContext, doubleGate bool, ruleID string, evidence map[string]string) bool {
	return rcAddResultFindingSev(ctx, doubleGate, ruleID, "HIGH", evidence)
}

// rcAddResultFindingSev 带严重度的结果侧违规 Finding。
func rcAddResultFindingSev(ctx *dsctx.RequestContext, doubleGate bool, ruleID, severity string, evidence map[string]string) bool {
	category := "OBSERVE"
	if doubleGate {
		category = "BLOCK"
	}
	evidence["mcp_error_code"] = strconv.Itoa(CodeResultBlocked)
	evidence["mcp_http_status"] = "403"
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "mcpguard",
		RuleID:     ruleID,
		Category:   category,
		Severity:   severity,
		Confidence: 1.0,
		Evidence:   evidence,
	})
	return doubleGate
}

// walkResultValues 结果 JSON 标量叶子遍历（点路径回调；预算护栏——
// 字段数/深度双上限；字符串值原样供值级规则求值（规则内 4096 rune 自封顶）；
// 数值/布尔转文本求值（词表命中面与请求侧 JSONValues 同口径）；
// 回调返回 false 即停止（命中预算耗尽）。
func walkResultValues(v any, path string, depth int, fields *int, visit func(path, val string) bool) {
	if v == nil || depth > maxResultWalkDepth || *fields >= maxResultWalkFields {
		return
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			*fields++
			if *fields > maxResultWalkFields {
				return
			}
			walkResultValues(t[k], joinPath(path, k), depth+1, fields, visit)
		}
	case []any:
		for i, el := range t {
			*fields++
			if *fields > maxResultWalkFields {
				return
			}
			walkResultValues(el, path+"["+itoaIndex(i)+"]", depth+1, fields, visit)
		}
	case string:
		if !visit(path, t) {
			return
		}
	case float64:
		visit(path, strconv.FormatFloat(t, 'g', -1, 64))
	case bool:
		visit(path, strconv.FormatBool(t))
	}
}

// sortStrings 键排序（事件确定性——map 遍历序抖动不可重现，authzcheck sort 先例）。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ExtractResultMember JSON-RPC 响应 result 成员提取（挂点侧共用——
// 非流式 response 解析产物（any）/SSE 事件 data 原文两形态入口）：
// any 形态经确定性再序列化供 EvaluateResult；result 缺席（错误对象等）→ false。
func ExtractResultMember(doc any) (json.RawMessage, bool) {
	obj, ok := doc.(map[string]any)
	if !ok {
		return nil, false
	}
	result, ok := obj["result"]
	if !ok {
		return nil, false
	}
	raw, err := json.Marshal(result)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// ExtractResultMemberRaw JSON-RPC 响应原文 result 成员提取（SSE 事件 data 原文形态；
// 非对象/无 result → false——错误对象不冒充工具结果）。
func ExtractResultMemberRaw(data []byte) (json.RawMessage, bool) {
	var doc struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	if len(doc.Result) == 0 {
		return nil, false
	}
	return doc.Result, true
}

// IsSSEContentType text/event-stream 判定（挂点侧捕获模式分流）。
func IsSSEContentType(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "text/event-stream")
}
