// indirect_prompt.go Phase 9C-1 响应侧间接提示词注入扫描与清洗：
// 对 tools/call、resources/read、prompts/get 的 JSON-RPC result 文本叶子执行有界遍历
// （depth <= 8, fields <= 256, max 4096 runes/field）：
//   - Unicode Tag / 零宽 / BiDi 覆盖字符走私 → mcp.result_unicode_smuggling
//   - 间接提示词劫持模式 → mcp.result_indirect_prompt_injection
//   - Markdown 外链查询串数据外带 ![...](https://...?...) → mcp.result_markdown_exfil
//
// 模式行为：
//   - OFF：零行为；
//   - OBSERVE：记录 OBSERVE Finding，不阻断不改写；
//   - SANITIZE：记录 OBSERVE Finding，同时从字符串叶子中清洗不可见 Unicode Tag/BiDi/零宽字符并返回清洗后 JSON；
//   - PROTECT（需 engineProtect 双闸）：命中即以 CodeResultBlocked (-32014) 阻断。
//
// 证据红线：绝不记录原始响应文本、提示词原文或外带 URL，仅记录目标名、字段点路径、类别与规则 ID。
package mcpguard

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
)

const (
	maxIndirectWalkDepth  = 8
	maxIndirectWalkFields = 256
	maxIndirectFieldRunes = 4096
	maxIndirectFindings   = 8
)

type namedIndirectPattern struct {
	class string
	re    *regexp.Regexp
}

// indirectPromptPatterns 间接提示词劫持模式表（RE2 线性时间，零回溯风险）。
var indirectPromptPatterns = []namedIndirectPattern{
	{
		class: "instruction_override",
		re:    regexp.MustCompile(`(?i)\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|earlier|system)\s+(instructions?|prompts?|rules?|directives?|context)\b`),
	},
	{
		class: "system_role_injection",
		re:    regexp.MustCompile(`(?i)(<\s*/?\s*(important|system|instructions?)\s*>|<\|im_start\|>|<<\s*sys\s*>>|\[/?inst\]|\bsystem\s+prompt\s*:)`),
	},
	{
		class: "covert_directive",
		re:    regexp.MustCompile(`(?i)\b((do\s+not|don't|never)\s+(tell|inform|mention|show|reveal|disclose)\s+(to\s+)?(the\s+)?user|(silently|secretly|covertly)\s+(send|exfiltrate|forward|upload|call|invoke|pass))\b`),
	},
	{
		class: "policy_bypass",
		re:    regexp.MustCompile(`(?i)\b(instead\s+of\s+answering|new\s+system\s+instructions?|you\s+are\s+now\s+in\s+(developer|admin|unrestricted)\s+mode|bypass\s+(all\s+)?(safety|security|policy|restrictions?))\b`),
	},
	{
		class: "cn_instruction_override",
		re:    regexp.MustCompile(`(忽略(之前|以上|所有|系统)(的)?(指令|提示词?|规则)|不要告诉用户|秘密(发送|读取|上传)|绕过(安全|权限|策略))`),
	},
}

// markdownExfilPattern Markdown 图片外链查询参数数据外带（![alt](https://host/path?query)）。
var markdownExfilPattern = regexp.MustCompile(`(?i)!\[[^\]]{0,256}\]\(\s*<?https?://[^)\s>]+\?[^)\s>]+>?\s*\)`)

// ScanAndSanitizeResult 扫描并按端点 ResponseGuardMode 处置 MCP 响应 result：
//   - OFF：返回 (false, nil)；
//   - OBSERVE：记录命中 Finding（OBSERVE），返回 (false, nil)；
//   - SANITIZE：记录命中 Finding（OBSERVE），清洗不可见 Unicode Tag/BiDi/零宽字符并返回修改后的 json.RawMessage；
//   - PROTECT：engineProtect==true 时命中返回 (true, nil) 并写 BLOCK -32014 Finding；否则降级 OBSERVE。
func ScanAndSanitizeResult(ctx *dsctx.RequestContext, toolOrMethod string, resultRaw json.RawMessage, ep *Endpoint, engineProtect bool) (blocked bool, sanitized json.RawMessage) {
	if ctx == nil || ep == nil || len(bytes.TrimSpace(resultRaw)) == 0 {
		return false, nil
	}
	mode := NormalizeResponseGuardMode(ep.ResponseGuardMode)
	if mode == ResponseGuardOff {
		return false, nil
	}

	var doc any
	if err := json.Unmarshal(resultRaw, &doc); err != nil {
		return false, nil // UNKNOWN 形态不阻断不改写
	}

	protectBlock := mode == ResponseGuardProtect && engineProtect
	target := truncateString(strings.TrimSpace(toolOrMethod), 128)
	if target == "" {
		target = "unknown"
	}

	state := &indirectScanState{
		ctx:          ctx,
		target:       target,
		mode:         mode,
		protectBlock: protectBlock,
		doSanitize:   mode == ResponseGuardSanitize,
	}

	doc = state.walk(doc, "", 1)

	if state.blocked {
		return true, nil
	}
	if state.doSanitize && state.modified {
		out, err := json.Marshal(doc)
		if err != nil {
			return false, nil
		}
		return false, json.RawMessage(out)
	}
	return false, nil
}

type indirectScanState struct {
	ctx          *dsctx.RequestContext
	target       string
	mode         string
	protectBlock bool
	doSanitize   bool

	fields   int
	findings int
	blocked  bool
	modified bool
}

func (st *indirectScanState) walk(v any, path string, depth int) any {
	if v == nil || depth > maxIndirectWalkDepth || st.fields >= maxIndirectWalkFields {
		return v
	}
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			st.fields++
			if st.fields > maxIndirectWalkFields {
				return t
			}
			updated := st.walk(t[k], joinPath(path, k), depth+1)
			if st.doSanitize {
				t[k] = updated
			}
		}
		return t
	case []any:
		for i := range t {
			st.fields++
			if st.fields > maxIndirectWalkFields {
				return t
			}
			updated := st.walk(t[i], path+"["+itoaIndex(i)+"]", depth+1)
			if st.doSanitize {
				t[i] = updated
			}
		}
		return t
	case string:
		return st.inspectString(t, path)
	default:
		return v
	}
}

func (st *indirectScanState) inspectString(s, path string) string {
	if s == "" {
		return s
	}
	scanRaw := truncateRunes(s, maxIndirectFieldRunes)
	invisClasses := detectInvisibleUnicodeClasses(scanRaw)

	out := s
	strippedForScan := scanRaw
	if len(invisClasses) > 0 {
		strippedFull, changed := stripSmuggledInvisibleRunes(s)
		if changed {
			strippedForScan = truncateRunes(strippedFull, maxIndirectFieldRunes)
			if st.doSanitize {
				out = strippedFull
				st.modified = true
			}
		}
		ev := map[string]string{
			"target":  st.target,
			"path":    truncateString(path, 128),
			"classes": strings.Join(invisClasses, ","),
			"rule":    "result_unicode_smuggling",
			"mode":    st.mode,
		}
		if st.doSanitize && changed {
			ev["sanitized"] = "true"
		}
		st.emit("mcp.result_unicode_smuggling", ev)
	}

	if class := matchIndirectPromptPattern(scanRaw, strippedForScan); class != "" {
		ev := map[string]string{
			"target":        st.target,
			"path":          truncateString(path, 128),
			"pattern_class": class,
			"rule":          "result_indirect_prompt_injection",
			"mode":          st.mode,
		}
		st.emit("mcp.result_indirect_prompt_injection", ev)
	}

	if markdownExfilPattern.MatchString(strippedForScan) || (strippedForScan != scanRaw && markdownExfilPattern.MatchString(scanRaw)) {
		ev := map[string]string{
			"target":        st.target,
			"path":          truncateString(path, 128),
			"pattern_class": "markdown_image_query_exfil",
			"rule":          "result_markdown_exfil",
			"mode":          st.mode,
		}
		st.emit("mcp.result_markdown_exfil", ev)
	}

	return out
}

func (st *indirectScanState) emit(ruleID string, evidence map[string]string) {
	if st.protectBlock {
		st.blocked = true
	}
	if st.findings >= maxIndirectFindings {
		return
	}
	st.findings++
	rcAddResultFinding(st.ctx, st.protectBlock, ruleID, evidence)
}

func matchIndirectPromptPattern(raw, stripped string) string {
	for _, p := range indirectPromptPatterns {
		if p.re.MatchString(stripped) || (raw != stripped && p.re.MatchString(raw)) {
			return p.class
		}
	}
	return ""
}
