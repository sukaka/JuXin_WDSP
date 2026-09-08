// mcp.go MCP（Model Context Protocol）内容级检测（W12-GW / P2-04 续，任务书 §154）：
//   - JSON-RPC method 词表核对：请求体 jsonrpc + method 形态已由分类器确认（/mcp 路径
//   - jsonrpc 字段），此处核对 method 是否在 MCP 标准方法词表——词表外方法
//     → llm.mcp_unknown_method OBSERVE/LOW（自定义扩展方法属正常生态，仅观察不阻断）；
//   - tools/call 参数值敏感检测：params.arguments 下留存标量值命中值级敏感规则
//     （复用 SensitiveValueRules，location=json）→ llm.mcp_sensitive_arg OBSERVE/MEDIUM，
//     证据只含工具名/规则名（data_type），不落参数名与参数值；
//   - 响应侧不落原文只统计：MCP 响应为 JSON-RPC result/error（无 usage 字段），
//     响应相位沿用 EnrichLLMResponse 既有统计补全（token 缺失容忍、stream 标记），
//     不新增任何原文采集。
//
// 解析护栏说明：parser 仅留存标量值（截断 256 字符）且数组只走首个元素，
// arguments 深层嵌套/数组成员在此口径下可能漏检（信号级 OBSERVE，不阻断），v1 接受；
// tools/call 频率异常留给行为侧（本检测器不做计数）。
package detectors

import (
	"sort"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// maxMCPMethodLen 方法名长度上限（与 api_llm_observations.mcp_method 列宽 128 对齐）。
const maxMCPMethodLen = 128

// maxMCPToolNameLen 工具名长度上限（证据字段，防异常实现超长值）。
const maxMCPToolNameLen = 128

// maxMCPSensitiveArgMatches 单请求 tools/call 参数值命中明细上限（防事件膨胀）。
const maxMCPSensitiveArgMatches = 5

// mcpMethodToolsCall tools/call 方法名（参数值敏感检测仅对该方法生效）。
const mcpMethodToolsCall = "tools/call"

// mcpArgsPrefix tools/call 参数对象路径前缀（parser 点路径口径；数组段记 []）。
const mcpArgsPrefix = "params.arguments"

// mcpKnownMethods MCP 标准方法词表（初始化/通知/工具/资源/提示词/补全/日志/
// 服务器反向请求全量收录；词表外方法为未知方法信号——仅 OBSERVE/LOW）。
var mcpKnownMethods = map[string]bool{
	"initialize": true, "ping": true,
	"notifications/initialized": true, "notifications/cancelled": true,
	"notifications/progress": true, "notifications/message": true,
	"notifications/resources/updated": true, "notifications/resources/list_changed": true,
	"notifications/tools/list_changed": true, "notifications/prompts/list_changed": true,
	"notifications/roots/list_changed": true,
	"tools/list":                       true, "tools/call": true,
	"resources/list": true, "resources/read": true,
	"resources/subscribe": true, "resources/unsubscribe": true,
	"resources/templates/list": true,
	"prompts/list":             true, "prompts/get": true,
	"completion/complete": true, "logging/setLevel": true,
	"roots/list": true, "sampling/createMessage": true, "elicitation/create": true,
}

// CheckMCP MCP 内容级检测：method 词表核对 + tools/call 参数值敏感检测 +
// 观测扩展（llm_observation.mcp_method）。仅分类器识别为 MCP 形态时由管线调用；
// valueRules 为发布通道下发值级敏感规则的编译产物（nil/空 = 参数值检测零行为，
// method 词表核对与观测扩展不受影响——识别与观测不依赖规则下发）。
func CheckMCP(ctx *dsctx.RequestContext, p *parser.Parsed, valueRules []CompiledSensitiveValueRule) {
	if ctx == nil || p == nil || !p.IsJSON {
		return
	}
	method := truncateMCPString(strings.TrimSpace(p.JSONValues["method"]), maxMCPMethodLen)
	if method != "" {
		// 观测扩展：method 写入 mcp_method（含词表外方法，如实记录调用面）；
		// 无 method 的报文为 JSON-RPC 响应对象（result/error）或畸形报文，非调用，不记录不判定
		if obs := ctx.GetLLMObservation(); obs != nil {
			out := *obs
			out.MCPMethod = method
			ctx.SetLLMObservation(&out)
		}
		if !mcpKnownMethods[method] {
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "llm",
				RuleID:     "llm.mcp_unknown_method",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "mcp json-rpc method not in known vocabulary",
				Evidence:   map[string]string{"method": method},
				ScoreDelta: 5,
			})
		}
	}
	// tools/call 参数值敏感检测（值级规则未下发时零行为）
	if method != mcpMethodToolsCall || len(valueRules) == 0 {
		return
	}
	checkMCPSensitiveArgs(ctx, p, valueRules)
}

// checkMCPSensitiveArgs tools/call 参数值检测：params.arguments 下留存标量值
// （含 arguments 本身为字符串的退化形态）逐值匹配值级敏感规则（location=json）。
// 证据只含工具名/规则名（data_type），不落参数名与参数值；命中上限 5 条防事件膨胀。
func checkMCPSensitiveArgs(ctx *dsctx.RequestContext, p *parser.Parsed, rules []CompiledSensitiveValueRule) {
	tool := truncateMCPString(strings.TrimSpace(p.JSONValues["params.name"]), maxMCPToolNameLen)
	paths := make([]string, 0, len(p.JSONValues))
	for path := range p.JSONValues {
		if path == mcpArgsPrefix || strings.HasPrefix(path, mcpArgsPrefix+".") {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths) // 确定性顺序（事件可重现）
	scans := 0          // 值×规则求值计数（复用 maxSensitiveValueScans 上限，防 CPU 放大）
	n := 0
	for _, path := range paths {
		if n >= maxMCPSensitiveArgMatches || scans >= maxSensitiveValueScans {
			return
		}
		r, ok := matchValueRules(p.JSONValues[path], "json", rules, &scans)
		if !ok {
			continue
		}
		evidence := map[string]string{"data_type": r.dataType}
		if tool != "" {
			evidence["tool"] = tool
		}
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "llm",
			RuleID:     "llm.mcp_sensitive_arg",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "sensitive value observed in mcp tool call arguments",
			Evidence:   evidence,
			ScoreDelta: 10,
		})
		n++
	}
}

// truncateMCPString 按字符截断（防超长值越列宽；按 rune 防截断多字节字符）。
func truncateMCPString(s string, max int) string {
	if r := []rune(s); len(r) > max {
		return string(r[:max])
	}
	return s
}
