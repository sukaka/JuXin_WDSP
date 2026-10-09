// schema.go MCP 工具 input/output Schema 冻结子集编译与求值
// （NG-MCP §1.6/D6 冻结：type/properties/required/additionalProperties/items/enum
// 六关键字，不宣称完整 JSON Schema）。
//
//   - 缺省未知字段策略=关闭世界（additionalProperties 缺省按 false 处置——
//     目录已审核即白名单语义）；
//   - 不支持关键字（$ref/$defs/anyOf/oneOf/pattern/format/min*/max*）：编译期登记，
//     该 Schema 整体降级（运行期不冒充完整校验——覆盖 PARTIAL 如实，结构预算与
//     重复键在协议层照判不误断）；$id/$schema/$comment/description/title/default/
//     examples 等注解性关键字容忍忽略（不降级）；
//   - required 按成员存在性判定（null 值成员视为存在——JSON Schema 语义）；
//   - 类型不符才是 type_mismatch；默认值不冒充缺失；
//   - enum 等值按确定性 JSON 序列化逐字节比对（数值 1 与 1.0 不等价——
//     文本形态敏感，登记为已知口径）；
//   - 证据纪律：规则名+字段点路径，不落值。
package mcpguard

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strings"
)

// Schema 冻结子集编译产物（装配期只读）。
type Schema struct {
	Type                 string // object/array/string/number/integer/boolean/null（空=不约束类型）
	Properties           map[string]*Schema
	Required             []string
	AdditionalProperties *bool // nil = 缺省关闭世界（按 false 处置）
	Items                *Schema
	Enum                 []json.RawMessage // 确定性序列化成员（等值逐字节比对）
}

// unsupportedSchemaKeywords 不支持关键字词表（编译期登记降级；min*/max* 前缀族）。
var unsupportedSchemaKeywords = []string{"$ref", "$defs", "anyOf", "oneOf", "allOf", "not", "pattern", "format",
	"patternProperties", "propertyNames", "dependencies", "dependentRequired", "dependentSchemas",
	"contains", "if", "then", "else", "const", "uniqueItems"}

// annotationSchemaKeywords 注解性关键字（容忍忽略不降级）。
var annotationSchemaKeywords = map[string]bool{
	"$id": true, "$schema": true, "$comment": true, "title": true, "description": true,
	"default": true, "examples": true, "readOnly": true, "writeOnly": true, "deprecated": true,
}

// DetectUnsupportedKeywords 原始 Schema 对象键扫描（任一命中即降级；返回命中键名
// 稳定序，上限 8——证据登记与 PARTIAL 判定的共同输入）。非对象形态（bool/数组/
// 标量/非法 JSON）按不降级处理（编译器另行拒绝）。
func DetectUnsupportedKeywords(raw json.RawMessage) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil
	}
	var out []string
	for k := range obj {
		switch {
		case annotationSchemaKeywords[k]:
			continue
		case containsKeyword(unsupportedSchemaKeywords, k):
			out = append(out, k)
		case strings.HasPrefix(k, "min") || strings.HasPrefix(k, "max"):
			out = append(out, k)
		}
	}
	sort.Strings(out)
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

func containsKeyword(set []string, k string) bool {
	for _, s := range set {
		if s == k {
			return true
		}
	}
	return false
}

// CompileSchema 编译冻结子集（非对象/非合法 JSON 返回 nil——调用侧按缺席处理）。
func CompileSchema(raw json.RawMessage) *Schema {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var head struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required"`
		AdditionalProperties *bool                      `json:"additionalProperties"`
		Items                json.RawMessage            `json:"items"`
		Enum                 []json.RawMessage          `json:"enum"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil
	}
	s := &Schema{
		Type:                 head.Type,
		Required:             head.Required,
		AdditionalProperties: head.AdditionalProperties,
		Enum:                 head.Enum,
	}
	switch s.Type {
	case "", "object", "array", "string", "number", "integer", "boolean", "null":
	default:
		return nil // 词表外类型：非法 Schema 按缺席处理（不猜义）
	}
	if len(head.Properties) > 0 {
		s.Properties = make(map[string]*Schema, len(head.Properties))
		for k, sub := range head.Properties {
			s.Properties[k] = CompileSchema(sub)
		}
	}
	if len(bytes.TrimSpace(head.Items)) > 0 {
		s.Items = CompileSchema(head.Items)
	}
	return s
}

// SchemaViolation 一条 Schema 违规（证据三元：规则/路径——不落值）。
type SchemaViolation struct {
	Rule string // type_mismatch|required_missing|unknown_field|enum_violation
	Path string // 字段点路径（根为空串）
}

// maxSchemaViolations 违规收集上限（防报告膨胀）。
const maxSchemaViolations = 8

// ValidateSchema 参数值按冻结子集校验（arguments 为解码后的 arguments 成员；
// 违规按文档序产出，达上限截断）。schema 为 nil 时零行为（调用侧按缺席跳过）。
func ValidateSchema(schema *Schema, args any) []SchemaViolation {
	if schema == nil {
		return nil
	}
	var out []SchemaViolation
	validateValue(schema, args, "", &out)
	return out
}

// validateValue 递归校验（path 为当前值点路径——根为空串，成员级 .name，
// 数组级 [i]——与 mcprpc 重复键路径形态一致）。
func validateValue(s *Schema, v any, path string, out *[]SchemaViolation) {
	if s == nil || len(*out) >= maxSchemaViolations {
		return
	}
	// 类型核对（空=不约束）
	if s.Type != "" && !jsonTypeMatches(s.Type, v) {
		addSchemaViolation(out, "type_mismatch", path)
		return // 类型不符即短路本值（属下校验无意义）
	}
	switch s.Type {
	case "object":
		obj, _ := v.(map[string]any)
		if obj == nil {
			return // 类型不符已在上方短路；空类型约束的对象关键字不展开
		}
		// required：成员存在性（null 视为存在——JSON Schema 语义）
		for _, req := range s.Required {
			if _, ok := obj[req]; !ok {
				addSchemaViolation(out, "required_missing", joinPath(path, req))
			}
		}
		// properties：已知成员递归
		for name, sub := range s.Properties {
			if val, ok := obj[name]; ok {
				validateValue(sub, val, joinPath(path, name), out)
			}
		}
		// additionalProperties：缺省关闭世界（nil 按 false 处置）
		closedWorld := s.AdditionalProperties == nil || !*s.AdditionalProperties
		if closedWorld {
			for name := range obj {
				if s.Properties == nil || s.Properties[name] == nil {
					addSchemaViolation(out, "unknown_field", joinPath(path, name))
				}
			}
		}
	case "array":
		arr, _ := v.([]any)
		if arr == nil {
			return
		}
		if s.Items != nil {
			for i, el := range arr {
				validateValue(s.Items, el, path+"["+itoaIndex(i)+"]", out)
			}
		}
	case "":
		// 无类型约束：enum 仍求值；其余关键字不展开
	}
	// enum：成员等值（确定性序列化逐字节比对）
	if len(s.Enum) > 0 {
		if !enumContains(s.Enum, v) {
			addSchemaViolation(out, "enum_violation", path)
		}
	}
}

// jsonTypeMatches 类型核对（integer=float64 且值为整数——encoding/json 口径）。
func jsonTypeMatches(typ string, v any) bool {
	switch typ {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f) && !math.IsInf(f, 0)
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	default:
		return false
	}
}

// enumContains 确定性序列化逐字节比对（数值形态敏感：1 与 1.0 不等价——已知口径）。
func enumContains(set []json.RawMessage, v any) bool {
	raw, err := json.Marshal(v)
	if err != nil {
		return false
	}
	for _, e := range set {
		if bytes.Equal(bytes.TrimSpace(e), raw) {
			return true
		}
	}
	return false
}

// joinPath 成员点路径（根级不带前导点）。
func joinPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func addSchemaViolation(out *[]SchemaViolation, rule, path string) {
	if len(*out) >= maxSchemaViolations {
		return
	}
	*out = append(*out, SchemaViolation{Rule: rule, Path: path})
}

// itoaIndex 非负整数十进制（本包内部小助手）。
func itoaIndex(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
