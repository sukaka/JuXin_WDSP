// tool_pinning.go Phase 9C-1 MCP 工具定义固定与投毒检测（Rug Pull / Tool Poisoning 防护）：
//   - ComputeToolDefinitionHash：确定性 SHA-256 摘要（与 server/internal/apimcp 逐字节对齐）；
//   - EvaluateToolsListResult：在 tools/list 响应相位解析 result.tools[]（上限 256 个），
//     检测描述中的不可见 Unicode Tag / 零宽 / BiDi 覆盖及隐藏提示词劫持指令（mcp.tool_description_poisoning），
//     检测未入库 APPROVED 工具声明（mcp.unregistered_tool_advertised），
//     对已固定 PinnedDefinitionHash 的目录工具执行常量时间比对检测定义漂移（mcp.tool_definition_drift，Rug Pull）；
//   - 证据红线：绝不记录原始提示词或工具描述文本——仅记工具名、摘要前缀、规则 ID 与字符/模式类别。
package mcpguard

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

// DefinitionHashPrefix 工具定义固定摘要域前缀（与 server/internal/apimcp 冻结对齐）。
const DefinitionHashPrefix = "mcp-def-sha256:v1:"

const (
	maxToolsListInspect      = 256
	maxDescriptionScanRunes  = 16384
	maxToolsListRuleFindings = 32
)

// canonicalSchemaJSON 规范化 JSON 序列化（与 server/internal/apimcp 逐字节一致）：
// 空或 "null" 归一为 "null"；合法 JSON 经 encoding/json 解码为 any 再 Marshal（递归键排序、无空白）；
// 非法 JSON 回退去除首尾空白的原切片（避免与 null 发生静默碰撞）。
func canonicalSchemaJSON(raw json.RawMessage) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return []byte("null")
	}
	var v any
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return trimmed
	}
	if v == nil {
		return []byte("null")
	}
	out, err := json.Marshal(v)
	if err != nil {
		return trimmed
	}
	return out
}

// ComputeToolDefinitionHash 计算 MCP 工具定义固定摘要：
// "mcp-def-sha256:v1:" + hex(sha256(name + "\x00" + description + "\x00" + canonical_json(input_schema)))。
// name 与 description 保持原始字节不裁剪，确保尾部空白或不可见字符篡改（Rug Pull）可被检出。
func ComputeToolDefinitionHash(name, description string, inputSchema json.RawMessage) string {
	canon := canonicalSchemaJSON(inputSchema)
	h := sha256.New()
	_, _ = h.Write([]byte(name))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(description))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write(canon)
	return DefinitionHashPrefix + hex.EncodeToString(h.Sum(nil))
}

// hashPrefixForEvidence 受控摘要前缀（去域前缀取前 16 位 hex，不泄露原文且便于排障比对）。
func hashPrefixForEvidence(h string) string {
	s := strings.TrimPrefix(strings.TrimSpace(h), DefinitionHashPrefix)
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// toolDescriptionOverridePatterns 工具描述隐藏提示词劫持模式（RE2 线性时间，零回溯风险）。
var toolDescriptionOverridePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<\s*/?\s*(important|system|instructions?|hidden)\s*>`),
	regexp.MustCompile(`(?i)(<\|im_start\|>|<<\s*sys\s*>>|\[/?inst\])`),
	regexp.MustCompile(`(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|directives?)`),
	regexp.MustCompile(`(?i)\boverride\s+(all\s+)?(system\s+)?(prompts?|instructions?|policies|policy|rules?)`),
	regexp.MustCompile(`(?i)\b(do\s+not|don't|never)\s+(tell|inform|mention|show|reveal|disclose)\s+(to\s+)?(the\s+)?user\b`),
	regexp.MustCompile(`(?i)\bbefore\s+(using|calling|invoking|running)\s+this\s+tool\b.{0,160}\b(read|pass|include|send|exfiltrate|upload|forward|cat|ssh|env|secret|token|key)\b`),
	regexp.MustCompile(`(?i)\b(silently|secretly|covertly)\s+(send|exfiltrate|read|forward|upload|include|pass|call|invoke)\b`),
	regexp.MustCompile(`(?i)\b(new|updated)\s+system\s+(instructions?|prompt|directive)\b`),
	regexp.MustCompile(`(?i)\byou\s+must\s+(always\s+)?(first\s+)?(read|exfiltrate|send|ignore|bypass|override)\b`),
	regexp.MustCompile(`(忽略(之前|以上|所有|系统)(的)?(指令|提示词?|规则)|不要告诉用户|秘密(发送|读取|上传)|隐藏指令)`),
}

// isInvisibleUnicodeTag 判定 Unicode Tags 块字符（U+E0000..U+E007F，经典 ASCII 走私载体）。
func isInvisibleUnicodeTag(r rune) bool {
	return r >= 0xE0000 && r <= 0xE007F
}

// isZeroWidthRune 判定零宽隐藏字符（U+200B/200C/200D/FEFF/2060）。
func isZeroWidthRune(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060:
		return true
	default:
		return false
	}
}

// isBiDiOverrideRune 判定双向文本覆盖/隔离控制字符（U+202A..U+202E, U+2066..U+2069）。
func isBiDiOverrideRune(r rune) bool {
	return (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
}

// isSmuggledInvisibleRune 判定任一需清洗的不可见走私字符（Tag / 零宽 / BiDi）。
func isSmuggledInvisibleRune(r rune) bool {
	return isInvisibleUnicodeTag(r) || isZeroWidthRune(r) || isBiDiOverrideRune(r)
}

// detectInvisibleUnicodeClasses 扫描字符串中的不可见 Unicode 类别（返回去重稳定排序类别名）。
func detectInvisibleUnicodeClasses(s string) []string {
	var hasTag, hasZW, hasBiDi bool
	for _, r := range s {
		if !hasTag && isInvisibleUnicodeTag(r) {
			hasTag = true
		} else if !hasZW && isZeroWidthRune(r) {
			hasZW = true
		} else if !hasBiDi && isBiDiOverrideRune(r) {
			hasBiDi = true
		}
		if hasTag && hasZW && hasBiDi {
			break
		}
	}
	var out []string
	if hasBiDi {
		out = append(out, "bidi_override")
	}
	if hasTag {
		out = append(out, "unicode_tag")
	}
	if hasZW {
		out = append(out, "zero_width")
	}
	return out
}

// stripSmuggledInvisibleRunes 清除字符串中的 Unicode Tag / 零宽 / BiDi 覆盖字符，返回清洗结果及是否改动。
func stripSmuggledInvisibleRunes(s string) (string, bool) {
	hasAny := false
	for _, r := range s {
		if isSmuggledInvisibleRune(r) {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if !isSmuggledInvisibleRune(r) {
			b.WriteRune(r)
		}
	}
	return b.String(), true
}

// truncateRunes 按 rune 截断，供正则扫描限幅防止超长字符串消耗过多 CPU。
func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i]
		}
		count++
	}
	return s
}

// matchesDescriptionOverride 检查描述（含去不可见字符后的规范串）是否命中隐藏提示词劫持模式。
func matchesDescriptionOverride(raw, stripped string) bool {
	s1 := truncateRunes(raw, maxDescriptionScanRunes)
	s2 := truncateRunes(stripped, maxDescriptionScanRunes)
	for _, re := range toolDescriptionOverridePatterns {
		if re.MatchString(s1) || (s2 != s1 && re.MatchString(s2)) {
			return true
		}
	}
	return false
}

// mcpWireTool tools/list 响应单条工具声明解包形态（兼容标准 camelCase inputSchema 与 snake_case）。
type mcpWireTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	InputSnake  json.RawMessage `json:"input_schema"`
}

func (wt mcpWireTool) effectiveInputSchema() json.RawMessage {
	if len(bytes.TrimSpace(wt.InputSchema)) > 0 {
		return wt.InputSchema
	}
	if len(bytes.TrimSpace(wt.InputSnake)) > 0 {
		return wt.InputSnake
	}
	return nil
}

// EvaluateToolsListResult 检查 tools/list 响应的 result 成员：
//  1. 解析 result.tools[]（有界上限 256）；
//  2. 描述投毒检测（Unicode Tag / 零宽 / BiDi 覆盖 / 隐藏提示词劫持指令 → mcp.tool_description_poisoning HIGH）；
//  3. 未入册工具检测（不在 APPROVED 目录中 → mcp.unregistered_tool_advertised MEDIUM）；
//  4. 定义固定漂移检测（Rug Pull：目录工具 PinnedDefinitionHash 非空且 PinEnforcement!=OFF 时
//     重算摘要并常量时间比对 → mcp.tool_definition_drift HIGH；
//     (tool.PinEnforcement=="PROTECT" || ep.Mode==ModeProtect) && engineProtect → BLOCK -32014）；
//  5. 若端点 ResponseGuardMode==SANITIZE 且未阻断，清洗描述中不可见字符并返回 sanitizedBody。
func EvaluateToolsListResult(ctx *dsctx.RequestContext, resultRaw json.RawMessage, cfg *Config, engineProtect bool) (blocked bool, sanitizedBody []byte) {
	if ctx == nil || cfg == nil || len(bytes.TrimSpace(resultRaw)) == 0 {
		return false, nil
	}
	ep := cfg.resolvedEndpoint("")
	if ep == nil {
		return false, nil
	}

	var parsed struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(resultRaw, &parsed); err != nil || len(parsed.Tools) == 0 {
		return false, nil
	}

	respMode := NormalizeResponseGuardMode(ep.ResponseGuardMode)
	limit := len(parsed.Tools)
	if limit > maxToolsListInspect {
		limit = maxToolsListInspect
	}

	poisonFindings := 0
	unregFindings := 0
	driftFindings := 0
	sanitizedDescs := map[int]string{}

	for i := 0; i < limit; i++ {
		var wt mcpWireTool
		if err := json.Unmarshal(parsed.Tools[i], &wt); err != nil {
			continue
		}
		toolName := strings.TrimSpace(wt.Name)
		if toolName == "" {
			continue
		}

		// 1. 工具描述投毒检测（不可见 Unicode 字符 + 隐藏提示词覆盖指令）
		if wt.Description != "" {
			scanDesc := truncateRunes(wt.Description, maxDescriptionScanRunes)
			invisClasses := detectInvisibleUnicodeClasses(scanDesc)
			strippedDesc, strippedChanged := stripSmuggledInvisibleRunes(wt.Description)
			hasPromptOverride := matchesDescriptionOverride(wt.Description, strippedDesc)

			if len(invisClasses) > 0 || hasPromptOverride {
				classes := append([]string(nil), invisClasses...)
				if hasPromptOverride {
					classes = append(classes, "prompt_override")
				}
				sort.Strings(classes)

				canSanitizeOnly := respMode == ResponseGuardSanitize && len(invisClasses) > 0 && !hasPromptOverride
				if respMode == ResponseGuardSanitize && strippedChanged {
					sanitizedDescs[i] = strippedDesc
				}

				shouldBlock := !canSanitizeOnly && engineProtect && (ep.Mode == ModeProtect || respMode == ResponseGuardProtect)
				if poisonFindings < maxToolsListRuleFindings {
					poisonFindings++
					ev := map[string]string{
						"tool":    truncateString(toolName, 128),
						"rule":    "tool_description_poisoning",
						"classes": strings.Join(classes, ","),
					}
					if respMode == ResponseGuardSanitize && strippedChanged {
						ev["sanitized"] = "true"
					}
					if rcAddResultFinding(ctx, shouldBlock, "mcp.tool_description_poisoning", ev) {
						blocked = true
					}
				} else if shouldBlock {
					blocked = true
				}
			}
		}

		// 2 & 3. 目录对照：未登记工具声明 + 定义固定漂移（Rug Pull）
		if ep.Catalog == nil {
			continue
		}
		catTool, found := ep.Catalog.Tools[toolName]
		if !found {
			if unregFindings < maxToolsListRuleFindings {
				unregFindings++
				ctx.AddMatch(dsctx.DetectorMatch{
					Detector:   "mcpguard",
					RuleID:     "mcp.unregistered_tool_advertised",
					Category:   "OBSERVE",
					Severity:   "MEDIUM",
					Message:    "unregistered mcp tool advertised in tools/list response",
					Confidence: 1.0,
					Evidence: map[string]string{
						"tool":    truncateString(toolName, 128),
						"catalog": ep.Catalog.Name,
						"rule":    "unregistered_tool_advertised",
					},
				})
			}
			continue
		}

		pinned := strings.TrimSpace(catTool.PinnedDefinitionHash)
		if pinned == "" {
			continue
		}
		pinEnf := NormalizePinEnforcement(catTool.PinEnforcement)
		if pinEnf == PinEnforcementOff {
			continue
		}
		actualHash := ComputeToolDefinitionHash(wt.Name, wt.Description, wt.effectiveInputSchema())
		if subtle.ConstantTimeCompare([]byte(actualHash), []byte(pinned)) != 1 {
			shouldBlock := (pinEnf == PinEnforcementProtect || ep.Mode == ModeProtect) && engineProtect
			if driftFindings < maxToolsListRuleFindings {
				driftFindings++
				ev := map[string]string{
					"tool":                 truncateString(toolName, 128),
					"catalog":              ep.Catalog.Name,
					"rule":                 "tool_definition_drift",
					"expected_hash_prefix": hashPrefixForEvidence(pinned),
					"actual_hash_prefix":   hashPrefixForEvidence(actualHash),
					"pin_enforcement":      pinEnf,
				}
				if rcAddResultFinding(ctx, shouldBlock, "mcp.tool_definition_drift", ev) {
					blocked = true
				}
			} else if shouldBlock {
				blocked = true
			}
		}
	}

	if blocked {
		return true, nil
	}

	// SANITIZE 模式回写清洗后的 tools[].description（保留 tools[] 其他协议字段如 annotations / nextCursor）
	if respMode == ResponseGuardSanitize && len(sanitizedDescs) > 0 {
		if cleaned, ok := applySanitizedToolDescriptions(resultRaw, sanitizedDescs); ok {
			return false, cleaned
		}
	}
	return false, nil
}

// applySanitizedToolDescriptions 按索引替换 result.tools[i].description，完整保留其余 JSON 成员。
func applySanitizedToolDescriptions(resultRaw json.RawMessage, replacements map[int]string) ([]byte, bool) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(resultRaw, &root); err != nil || root == nil {
		return nil, false
	}
	rawTools, ok := root["tools"]
	if !ok {
		return nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return nil, false
	}
	changed := false
	for idx, cleanDesc := range replacements {
		if idx < 0 || idx >= len(tools) {
			continue
		}
		var item map[string]json.RawMessage
		if err := json.Unmarshal(tools[idx], &item); err != nil || item == nil {
			continue
		}
		encoded, err := json.Marshal(cleanDesc)
		if err != nil {
			continue
		}
		item["description"] = encoded
		updatedItem, err := json.Marshal(item)
		if err != nil {
			continue
		}
		tools[idx] = updatedItem
		changed = true
	}
	if !changed {
		return nil, false
	}
	updatedTools, err := json.Marshal(tools)
	if err != nil {
		return nil, false
	}
	root["tools"] = updatedTools
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false
	}
	return out, true
}
