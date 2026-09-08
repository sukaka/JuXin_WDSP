// llm.go LLM API 安全检测（P2-04 首批，任务书 §152-154）：
//   - 请求侧观测：model 标识 / prompt 存在性 / 体量桶 / stream 标记（数据最小化，不落原文）；
//   - Prompt Injection 信号 v1：user/system 消息文本词表匹配（中英常见形态，大小写不敏感；
//     误报纪律：仅 OBSERVE/LOW，证据只含命中规则名与消息序号，不落原文）；
//   - 未授权模型：发布通道下发 api_llm_allowed_models 非空时，请求 model 不在名单
//     → llm.unauthorized_model OBSERVE/MEDIUM（缺省不下发不判定）；
//   - 响应侧补全：model / usage.total_tokens（OpenAI 兼容字段，缺失容忍）。
//
// 解析护栏说明：parser 仅留存标量值（截断 256 字符）且数组只走首个元素，
// 词表匹配在 messages[0].content / prompt / input 等留存值上进行——
// 数据最小化优先，v1 接受此口径下的漏检（信号级 OBSERVE，不阻断）。
package detectors

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/jiuzhang-waf/gateway/dynamic_security/classifier"
	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/parser"
)

// maxLLMModelLen 模型标识长度上限（事件/落库列宽 128）。
const maxLLMModelLen = 128

// maxLLMInjectionMatches 单请求注入词表命中明细上限（防事件膨胀）。
const maxLLMInjectionMatches = 5

// llmInjectionRules Prompt Injection 词表 v1（编译期正则表，RE2 线性时间）。
// 收录原则：中英常见高置信形态（指令覆盖/越狱/DAN/系统提示词窃取），
// 宁漏勿滥——命中仅 OBSERVE/LOW 信号，误报代价可控、不落原文。
var llmInjectionRules = []struct {
	name string
	re   *regexp.Regexp
}{
	{"ignore_previous_instructions", regexp.MustCompile(`(?i)ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|directions?)`)},
	{"disregard_instructions", regexp.MustCompile(`(?i)disregard\s+(all\s+|any\s+|the\s+)?(previous\s+|prior\s+|above\s+)?(instructions?|prompts?|rules?)`)},
	{"forget_or_override_instructions", regexp.MustCompile(`(?i)(forget|override|bypass|disable)\s+(all\s+|your\s+|the\s+)?(previous\s+|prior\s+)?(instructions?|rules?|restrictions?|guardrails?|safety\s+(rules?|filters?))`)},
	{"jailbreak_keyword", regexp.MustCompile(`(?i)\bjail\s?break\b`)},
	{"dan_mode", regexp.MustCompile(`(?i)(do\s+anything\s+now|\bdan\b\s+(mode|jailbreak|prompt))`)},
	{"reveal_system_prompt", regexp.MustCompile(`(?i)(reveal|show|print|repeat|leak|output)\s+(me\s+|your\s+|the\s+)?(system|initial|original|full|hidden)\s+(prompt|instructions?|rules?)`)},
	{"cn_ignore_instructions", regexp.MustCompile(`忽略(你)?(之前|以前|上述|以上|所有|全部|先前).{0,6}(指令|指示|命令|要求|设定)`)},
	{"cn_reveal_system_prompt", regexp.MustCompile(`(泄露|透露|输出|打印|重复).{0,6}(系统提示词|系统指令|初始指令|提示词)`)},
}

// llmPromptValuePaths 参与注入词表匹配的留存标量路径（JSONValues 键）。
// messages 数组仅首个元素可见（parser 护栏），message_index 恒为 "0"（如实记录口径）。
var llmPromptValuePaths = map[string]bool{
	"messages[].content":        true, // chat/messages 形态首条消息文本
	"messages[].content[].text": true, // 结构化 content 分片文本
	"prompt":                    true, // completions 形态
	"input":                     true, // embeddings/audio 形态
	"system":                    true, // 旧版 chat system 字段
	"instructions":              true, // Responses API 形态
}

// PromptLenBucket prompt 体量桶（近似口径：chat 请求体以 prompt 为主体，
// 数据最小化下以请求体大小分桶，不逐字统计原文长度）。
// 取值稳定（落库列宽 16）：XS ≤512 / S ≤4K / M ≤32K / L ≤256K / XL >256K。
func PromptLenBucket(bodySize int) string {
	switch {
	case bodySize <= 512:
		return "XS"
	case bodySize <= 4<<10:
		return "S"
	case bodySize <= 32<<10:
		return "M"
	case bodySize <= 256<<10:
		return "L"
	default:
		return "XL"
	}
}

// CheckLLM LLM 端点请求侧检测：产出 llm_observation（请求侧字段），
// 跑 Prompt Injection 词表与未授权模型判定。仅识别为 LLM 端点时由管线调用。
// allowedModels 为发布通道下发名单（nil/空 = 不判定未授权模型，零行为）。
func CheckLLM(ctx *dsctx.RequestContext, p *parser.Parsed, llm classifier.LLMResult, allowedModels []string) {
	if ctx == nil || p == nil || !llm.IsLLM {
		return
	}
	obs := &dsctx.LLMObservation{
		Model:         truncateLLMModel(p.JSONValues["model"]),
		PromptPresent: llmPromptPresent(p),
		Stream:        strings.EqualFold(strings.TrimSpace(p.JSONValues["stream"]), "true"),
	}
	// 体量桶仅对 prompt 文本主体（JSON 体）有意义；multipart 上传体是文件，不产桶
	if obs.PromptPresent && p.IsJSON && p.BodySize > 0 {
		obs.PromptLenBucket = PromptLenBucket(p.BodySize)
	}
	ctx.SetLLMObservation(obs)

	checkLLMPromptInjection(ctx, p)
	checkLLMAllowedModel(ctx, obs.Model, allowedModels)
}

// llmPromptPresent prompt 形态字段存在性（messages 数组 / prompt / input 非空；只认存在性不含内容）。
func llmPromptPresent(p *parser.Parsed) bool {
	if p.JSONFields["messages"] == "array" {
		return true
	}
	if strings.TrimSpace(p.JSONValues["prompt"]) != "" || strings.TrimSpace(p.JSONValues["input"]) != "" {
		return true
	}
	// multipart 上传形态（audio/images）：prompt part 存在即视为携带 prompt
	for _, part := range p.MultipartParts {
		if strings.EqualFold(part.FieldName, "prompt") {
			return true
		}
	}
	return false
}

// checkLLMPromptInjection 对留存 prompt 标量做词表匹配（确定性顺序，命中上限 5 条；
// 证据只含规则名/消息序号/角色，不落原文）。
func checkLLMPromptInjection(ctx *dsctx.RequestContext, p *parser.Parsed) {
	if len(p.JSONValues) == 0 {
		return
	}
	paths := make([]string, 0, len(p.JSONValues))
	for path := range p.JSONValues {
		if llmPromptValuePaths[path] {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths) // 确定性顺序（事件可重现）
	role := strings.TrimSpace(p.JSONValues["messages[].role"])
	n := 0
	for _, path := range paths {
		value := p.JSONValues[path]
		if value == "" {
			continue
		}
		for _, rule := range llmInjectionRules {
			if n >= maxLLMInjectionMatches {
				return
			}
			if !rule.re.MatchString(value) {
				continue
			}
			evidence := map[string]string{"rule": rule.name}
			if strings.HasPrefix(path, "messages[]") {
				// parser 数组只走首元素：可见消息序号恒为 0（口径如实记录）
				evidence["message_index"] = "0"
				if role != "" {
					evidence["role"] = role
				}
			} else {
				evidence["field"] = path
			}
			ctx.AddMatch(dsctx.DetectorMatch{
				Detector:   "llm",
				RuleID:     "llm.prompt_injection",
				Category:   "OBSERVE",
				Severity:   "LOW",
				Message:    "prompt injection pattern observed",
				Evidence:   evidence,
				ScoreDelta: 5,
			})
			n++
			break // 同一文本只记首条命中规则（一词一证，防同值多规则刷屏）
		}
	}
}

// checkLLMAllowedModel 未授权模型判定：名单非空且请求声明了 model 时，
// model 不在名单 → OBSERVE/MEDIUM；model 缺失不判（缺失容忍，不误伤未声明模型的兼容实现）。
func checkLLMAllowedModel(ctx *dsctx.RequestContext, model string, allowedModels []string) {
	if len(allowedModels) == 0 || model == "" {
		return
	}
	for _, allowed := range allowedModels {
		if model == strings.TrimSpace(allowed) {
			return
		}
	}
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "llm",
		RuleID:     "llm.unauthorized_model",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "llm model not in allowed list",
		Evidence:   map[string]string{"model": model},
		ScoreDelta: 15,
	})
}

// llmResponseUsage OpenAI 兼容响应窄提取结构（只取 model 与 usage.total_tokens，
// 其余字段（含 choices 文本）不进入内存结构，数据最小化）。
type llmResponseUsage struct {
	Model string `json:"model"`
	Usage struct {
		TotalTokens int `json:"total_tokens"`
	} `json:"usage"`
}

// EnrichLLMResponse 响应相位 LLM 观测补全：SSE/流式响应标记 stream；
// 完整捕获的 JSON 响应提取 model / usage.total_tokens（缺失容忍，截断体不解析）。
// 仅请求相位已识别 LLM 端点（观测存在）时生效，否则零行为。
//
// 解析复用（任务书原则 2.1）：调用方已解码响应体时（如响应相位 response.ParseJSON），
// 经可选末参 parsedRoot 传入解码根值（至多一个；nil 表示调用方已判定非 JSON/解析失败），
// 本函数不再对 body 二次 Unmarshal；parsedRoot 缺省时退化为对 body 的一次窄提取
// （兼容未预解析的调用方）。
func EnrichLLMResponse(ctx *dsctx.RequestContext, contentType string, body []byte, truncated, streamed bool, parsedRoot ...any) {
	obs := ctx.GetLLMObservation()
	if obs == nil {
		return
	}
	out := *obs
	ct := strings.ToLower(contentType)
	if streamed || strings.Contains(ct, "text/event-stream") {
		out.Stream = true
	}
	if !truncated && !streamed {
		if len(parsedRoot) > 0 {
			// 复用调用方解码根值（零二次解析；根值非对象/字段缺失按缺失容忍）
			model, tokens := extractLLMUsageFromParsed(parsedRoot[0])
			if out.Model == "" && model != "" {
				out.Model = truncateLLMModel(model)
			}
			if tokens > 0 {
				out.TotalTokens = tokens
			}
		} else if len(body) > 0 &&
			(strings.Contains(ct, "json") || strings.HasPrefix(strings.TrimSpace(string(body)), "{")) {
			var usage llmResponseUsage
			if err := json.Unmarshal(body, &usage); err == nil {
				if out.Model == "" {
					out.Model = truncateLLMModel(usage.Model)
				}
				if usage.Usage.TotalTokens > 0 {
					out.TotalTokens = usage.Usage.TotalTokens
				}
			}
			// 解析失败容忍（非标准兼容实现）：保留请求侧观测，不产错误
		}
	}
	ctx.SetLLMObservation(&out)
}

// extractLLMUsageFromParsed 从已解码的响应 JSON 根值窄提取 model / usage.total_tokens
// （数字兼容 json.Number 与 float64 两种解码形态；非对象/类型不符按缺失容忍返回零值）。
func extractLLMUsageFromParsed(root any) (string, int) {
	obj, ok := root.(map[string]any)
	if !ok {
		return "", 0
	}
	model, _ := obj["model"].(string)
	tokens := 0
	if usage, ok := obj["usage"].(map[string]any); ok {
		switch n := usage["total_tokens"].(type) {
		case json.Number:
			if i, err := n.Int64(); err == nil && i > 0 {
				tokens = int(i)
			}
		case float64:
			if n > 0 {
				tokens = int(n)
			}
		}
	}
	return model, tokens
}

// truncateLLMModel 模型标识截断（列宽 128；防异常网关/客户端超长值，按 rune 防截断多字节字符）。
func truncateLLMModel(model string) string {
	model = strings.TrimSpace(model)
	if r := []rune(model); len(r) > maxLLMModelLen {
		model = string(r[:maxLLMModelLen])
	}
	return model
}
