// spec_jsonschema.go 阶段8 §33：JSON Schema（draft-07 / 2020-12）规范导入解析。
// JSON Schema 描述数据而非 HTTP 端点，按任务书要求解析为"端点 + 字段模型"：
// 根 schema 与 $defs/definitions 中的每个 object 子 schema 各生成一条合成端点
// （Method=SCHEMA，Path=/_schema/<名称>），其 properties 展开为 BODY 字段参数。
// 仅支持 draft-07 与 2020-12，其余 draft 明确报 ErrSpecUnsupportedJSONSchemaDraft（HTTP 层 400）。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 覆盖。
package apisecurity

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// JSON Schema 解析错误。
var (
	// ErrSpecUnsupportedJSONSchemaDraft $schema 声明的 draft 非 draft-07 / 2020-12。
	ErrSpecUnsupportedJSONSchemaDraft = errors.New("unsupported json schema draft")
	// ErrSpecInvalidJSONSchema 文档缺少可解析的 object/properties 定义。
	ErrSpecInvalidJSONSchema = errors.New("invalid json schema document")
)

// jsonSchemaSupportedDrafts 支持的 $schema 标识子串（draft-07 / 2020-12）。
var jsonSchemaSupportedDrafts = []string{"draft-07", "draft/2020-12"}

// jsonSchemaSlugInvalid 端点路径名中需替换为 "-" 的字符。
var jsonSchemaSlugInvalid = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// ParseJSONSchema 解析 JSON Schema 文档为操作清单（根 schema + $defs/definitions 子 schema）。
func ParseJSONSchema(doc map[string]any) ([]SpecOperation, error) {
	if s, ok := doc["$schema"].(string); ok {
		supported := false
		for _, d := range jsonSchemaSupportedDrafts {
			if strings.Contains(s, d) {
				supported = true
				break
			}
		}
		if !supported {
			return nil, fmt.Errorf("%w: 仅支持 draft-07 与 2020-12（$schema=%q）", ErrSpecUnsupportedJSONSchemaDraft, truncateRefValue(s))
		}
	}
	ops := []SpecOperation{}
	if op, ok := jsonSchemaOp(schemaTitle(doc), doc); ok {
		ops = append(ops, op)
	}
	// draft 2020-12 用 $defs，draft-07 用 definitions；两者并存时都解析
	for _, key := range []string{"$defs", "definitions"} {
		defs, ok := doc[key].(map[string]any)
		if !ok {
			continue
		}
		for name, defRaw := range defs {
			def, ok := defRaw.(map[string]any)
			if !ok {
				continue
			}
			if op, ok := jsonSchemaOp(name, def); ok {
				ops = append(ops, op)
			}
		}
	}
	if len(ops) == 0 {
		return nil, fmt.Errorf("%w: 缺少 object 类型的 properties 定义", ErrSpecInvalidJSONSchema)
	}
	sort.Slice(ops, func(i, j int) bool { return ops[i].Key < ops[j].Key })
	return ops, nil
}

// jsonSchemaOp 单个 object schema → 合成端点 + BODY 字段参数。
// 非 object 或无 properties 的 schema 返回 ok=false（由调用方决定是否整体报错）。
func jsonSchemaOp(title string, schema map[string]any) (SpecOperation, bool) {
	properties, ok := schema["properties"].(map[string]any)
	if !ok || len(properties) == 0 {
		return SpecOperation{}, false
	}
	t, _ := schema["type"].(string)
	if t != "" && t != "object" {
		return SpecOperation{}, false
	}
	requiredSet := map[string]bool{}
	for _, r := range stringSlice(schema["required"]) {
		requiredSet[r] = true
	}
	params := make([]SpecParam, 0, len(properties))
	for propName, propRaw := range properties {
		prop, _ := propRaw.(map[string]any)
		params = append(params, SpecParam{
			Name:     propName,
			In:       "BODY",
			Type:     schemaTypeOf(prop),
			Required: requiredSet[propName],
		})
	}
	sort.Slice(params, func(i, j int) bool { return params[i].Name < params[j].Name })
	path := "/_schema/" + jsonSchemaSlug(title)
	return SpecOperation{Method: "SCHEMA", Path: path, Key: "SCHEMA " + path, Params: params}, true
}

// schemaTitle 根 schema 标题（title 字段，缺省 root）。
func schemaTitle(doc map[string]any) string {
	if title, _ := doc["title"].(string); strings.TrimSpace(title) != "" {
		return title
	}
	return "root"
}

// jsonSchemaSlug 端点路径名清洗：非法字符折叠为 "-"，去首尾 "-"，上限 200 字符，空回退 root。
func jsonSchemaSlug(title string) string {
	s := jsonSchemaSlugInvalid.ReplaceAllString(strings.TrimSpace(title), "-")
	s = strings.Trim(s, "-")
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		return "root"
	}
	return s
}
