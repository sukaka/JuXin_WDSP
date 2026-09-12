// spec_formats.go 阶段8 §33 规范导入扩展：
// 统一解析入口 ParseSpecContent（JSON / YAML / GraphQL SDL 字节 → 格式 + 规范化文档 + 操作清单），
// YAML 安全解码（禁止自定义标签、节点/深度/别名预算防炸弹）、外部 $ref 引用拒绝（不发起网络请求）。
// 各格式解析器见 spec_postman.go / spec_jsonschema.go / spec_graphql.go；
// OpenAPI 3 / Swagger 2.0 仍由 spec_version.go 的 ParseSpecDocument 处理。
// 解析为纯逻辑（不依赖 DB），由 spec_formats_test.go 等覆盖。
package apisecurity

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// 扩展规范格式（api_import_specs.format，列宽 VARCHAR(32) 无 CHECK 约束，无需迁移）。
const (
	SpecFormatJSONSchema = "jsonschema"
	SpecFormatPostman    = "postman"
	SpecFormatGraphQL    = "graphql"
)

// 扩展格式解析错误（HTTP 层统一映射为 400 并给出明确原因）。
var (
	// ErrSpecUnsupportedFormat 无法识别为任何支持的规范格式。
	ErrSpecUnsupportedFormat = errors.New("unsupported spec format")
	// ErrSpecInvalidJSON JSON 文档反序列化失败。
	ErrSpecInvalidJSON = errors.New("invalid json document")
	// ErrSpecInvalidYAML YAML 文档解析失败（语法错误/自定义标签/非字符串键/别名循环等）。
	ErrSpecInvalidYAML = errors.New("invalid yaml document")
	// ErrSpecTooLarge 文档超过大小上限。
	ErrSpecTooLarge = errors.New("spec document too large")
	// ErrSpecTooComplex 文档节点数/嵌套深度超出安全限制（防解析炸弹）。
	ErrSpecTooComplex = errors.New("spec document too complex")
	// ErrSpecExternalRef 含外部 $ref 引用（http(s)://、文件路径等），仅允许 #/ 文档内引用。
	ErrSpecExternalRef = errors.New("external $ref not allowed")
	// ErrSpecInvalidGraphQL GraphQL SDL 无法解析出任何 Query/Mutation 操作。
	ErrSpecInvalidGraphQL = errors.New("invalid graphql schema")
)

// 解析安全限制。
const (
	specJSONMaxDepth = 128    // JSON 最大嵌套深度
	specYAMLMaxNodes = 100000 // YAML 解码最大输出节点数（含别名展开）
	specYAMLMaxDepth = 64     // YAML 最大嵌套深度
)

// ParseSpecContent 规范导入统一解析入口：
// 输入原始字节（粘贴上传 / URL 拉取均已在外层做 16MiB 限制，此处防御性复检），
// 依次尝试 JSON → YAML → GraphQL SDL，返回格式标识、规范化文档与操作清单。
// normalized：openapi3/swagger2 为 OAS3 规范化文档；jsonschema/postman 为源文档；
// graphql 为 {"x-wdsp-spec-format":"graphql","sdl":...} 包装（spec_json 为 JSONB，须可 JSON 序列化）。
func ParseSpecContent(body []byte) (format string, normalized map[string]any, ops []SpecOperation, err error) {
	if len(body) > specImportMaxBytes {
		return "", nil, nil, fmt.Errorf("%w: 超过大小上限（16MiB）", ErrSpecTooLarge)
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return "", nil, nil, fmt.Errorf("%w: 空文档", ErrSpecUnsupportedFormat)
	}
	var doc map[string]any
	if trimmed[0] == '{' || trimmed[0] == '[' {
		// 明确 JSON 形态：解析失败即拒绝，不再回退 YAML/GraphQL
		if jsonDepthExceeded(trimmed) {
			return "", nil, nil, fmt.Errorf("%w: JSON 嵌套深度超过 %d", ErrSpecTooComplex, specJSONMaxDepth)
		}
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return "", nil, nil, fmt.Errorf("%w: %v", ErrSpecInvalidJSON, err)
		}
		if doc == nil {
			return "", nil, nil, fmt.Errorf("%w: 顶层必须为 JSON 对象", ErrSpecInvalidJSON)
		}
	} else {
		// YAML（安全解码）；非映射顶层（如纯文本/SDL）回退 GraphQL SDL
		doc, err = decodeSpecYAML(trimmed)
		if err != nil {
			if looksLikeGraphQLSDL(string(trimmed)) {
				return parseGraphQLContent(trimmed)
			}
			return "", nil, nil, err
		}
	}
	return parseSpecJSONDoc(doc)
}

// parseSpecJSONDoc 对已解码为 map 的 JSON 族文档做格式识别与分发：
// openapi3 / swagger2（ParseSpecDocument）/ postman / jsonschema；
// 先做外部 $ref 扫描（所有 JSON 族格式统一拒绝非 #/ 引用，绝不发起网络请求）。
func parseSpecJSONDoc(doc map[string]any) (format string, normalized map[string]any, ops []SpecOperation, err error) {
	if err := rejectExternalRefs(doc); err != nil {
		return "", nil, nil, err
	}
	switch detectExtendedSpecFormat(doc) {
	case SpecFormatOpenAPI3, SpecFormatSwagger2:
		return ParseSpecDocument(doc)
	case SpecFormatPostman:
		ops, err := ParsePostmanCollection(doc)
		if err != nil {
			return "", nil, nil, err
		}
		return SpecFormatPostman, doc, ops, nil
	case SpecFormatJSONSchema:
		ops, err := ParseJSONSchema(doc)
		if err != nil {
			return "", nil, nil, err
		}
		return SpecFormatJSONSchema, doc, ops, nil
	}
	return "", nil, nil, ErrSpecUnsupportedFormat
}

// parseGraphQLContent GraphQL SDL 入口：解析失败即 400（文档形态已确认为 SDL）。
func parseGraphQLContent(sdl []byte) (string, map[string]any, []SpecOperation, error) {
	ops, err := ParseGraphQLSDL(string(sdl))
	if err != nil {
		return "", nil, nil, err
	}
	normalized := map[string]any{
		"x-wdsp-spec-format": SpecFormatGraphQL,
		"sdl":                string(sdl),
	}
	return SpecFormatGraphQL, normalized, ops, nil
}

// detectExtendedSpecFormat 扩展格式识别：openapi3 / swagger2 / postman / jsonschema / ""。
// postman：info 为对象且 item 为数组（版本在 ParsePostmanCollection 内校验）；
// jsonschema：$schema 指向 json-schema.org（draft 在 ParseJSONSchema 内校验）。
func detectExtendedSpecFormat(doc map[string]any) string {
	if f := DetectSpecFormat(doc); f != "" {
		return f
	}
	if _, ok := doc["info"].(map[string]any); ok {
		if _, ok := doc["item"].([]any); ok {
			return SpecFormatPostman
		}
	}
	if s, ok := doc["$schema"].(string); ok && strings.Contains(s, "json-schema.org") {
		return SpecFormatJSONSchema
	}
	return ""
}

// ---------- 外部 $ref 拒绝 ----------

// rejectExternalRefs 递归扫描文档中的 "$ref" 键：仅允许 "#/..." 文档内引用，
// 其余（http(s)://、相对/绝对文件路径、// 协议相对）一律拒绝——解析器不展开引用，
// 更不允许由此发起任何网络/文件访问。
func rejectExternalRefs(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if k == "$ref" {
				if s, ok := val.(string); ok && !strings.HasPrefix(s, "#") {
					return fmt.Errorf("%w: %s", ErrSpecExternalRef, truncateRefValue(s))
				}
			}
			if err := rejectExternalRefs(val); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range t {
			if err := rejectExternalRefs(item); err != nil {
				return err
			}
		}
	}
	return nil
}

// truncateRefValue 错误信息中的引用值截断（避免超长值撑爆响应）。
func truncateRefValue(s string) string {
	if len(s) > 128 {
		return s[:128] + "…"
	}
	return s
}

// jsonDepthExceeded JSON 括号深度预扫描（字符串/转义感知），超过 specJSONMaxDepth 返回 true。
func jsonDepthExceeded(b []byte) bool {
	depth := 0
	inStr := false
	esc := false
	for _, c := range b {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > specJSONMaxDepth {
				return true
			}
		case '}', ']':
			depth--
		}
	}
	return false
}

// ---------- YAML 安全解码 ----------

// yamlAllowedScalarTags 允许的 YAML 标量标签（yaml.v3 节点标签为短形式 !!str 等；
// !!binary 与一切自定义标签（!foo、!!python/object 等）一律拒绝，防类型混淆与解析炸弹）。
var yamlAllowedScalarTags = map[string]bool{
	"!!str": true, "tag:yaml.org,2002:str": true,
	"!!int": true, "tag:yaml.org,2002:int": true,
	"!!float": true, "tag:yaml.org,2002:float": true,
	"!!bool": true, "tag:yaml.org,2002:bool": true,
	"!!null": true, "tag:yaml.org,2002:null": true,
	"!!timestamp": true, "tag:yaml.org,2002:timestamp": true,
}

// yamlIsStringTag 字符串标量标签判定（映射键必须满足）。
func yamlIsStringTag(tag string) bool {
	return tag == "!!str" || tag == "tag:yaml.org,2002:str"
}

// yamlIsMergeKey 合并键（<<）标签判定。
func yamlIsMergeKey(n *yaml.Node) bool {
	return n.Tag == "!!merge" || n.Tag == "tag:yaml.org,2002:merge" || n.Value == "<<"
}

// yamlIsMapTag / yamlIsSeqTag 映射/序列节点标签判定（自定义标签一律拒绝）。
func yamlIsMapTag(tag string) bool {
	return tag == "!!map" || tag == "tag:yaml.org,2002:map"
}

func yamlIsSeqTag(tag string) bool {
	return tag == "!!seq" || tag == "tag:yaml.org,2002:seq"
}

// yamlNodeBudget YAML 解码输出预算：节点总数上限约束别名展开（billion laughs 防护）。
type yamlNodeBudget struct{ remaining int }

func (b *yamlNodeBudget) spend(n int) error {
	b.remaining -= n
	if b.remaining < 0 {
		return fmt.Errorf("%w: YAML 节点数超过 %d", ErrSpecTooComplex, specYAMLMaxNodes)
	}
	return nil
}

// decodeSpecYAML 安全 YAML 解码：单文档、自定义标签拒绝、节点/深度预算、别名循环检测，
// 输出仅含 JSON 可序列化类型（map[string]any / []any / string / float64 / bool / nil / time.Time）。
// 顶层必须为映射，否则返回 ErrSpecUnsupportedFormat（由调用方决定是否回退 SDL）。
func decodeSpecYAML(body []byte) (map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(body))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSpecInvalidYAML, err)
	}
	// 拒绝多文档（避免 trailing 文档被静默忽略造成语义歧义）
	var extra yaml.Node
	if err := dec.Decode(&extra); err == nil && extra.Kind != 0 {
		return nil, fmt.Errorf("%w: 仅支持单文档 YAML", ErrSpecInvalidYAML)
	}
	if root.Kind == 0 {
		return nil, fmt.Errorf("%w: 空文档", ErrSpecUnsupportedFormat)
	}
	budget := &yamlNodeBudget{remaining: specYAMLMaxNodes}
	v, err := yamlNodeToAny(&root, 0, budget, map[*yaml.Node]bool{})
	if err != nil {
		return nil, err
	}
	doc, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: 顶层必须为映射", ErrSpecUnsupportedFormat)
	}
	return doc, nil
}

// yamlNodeToAny 递归转换 YAML 节点树。active 记录展开中的别名锚点，检测别名循环。
func yamlNodeToAny(n *yaml.Node, depth int, budget *yamlNodeBudget, active map[*yaml.Node]bool) (any, error) {
	if n == nil {
		return nil, nil
	}
	if depth > specYAMLMaxDepth {
		return nil, fmt.Errorf("%w: YAML 嵌套深度超过 %d", ErrSpecTooComplex, specYAMLMaxDepth)
	}
	if err := budget.spend(1); err != nil {
		return nil, err
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return yamlNodeToAny(n.Content[0], depth+1, budget, active)
	case yaml.AliasNode:
		if active[n.Alias] {
			return nil, fmt.Errorf("%w: 检测到别名循环", ErrSpecInvalidYAML)
		}
		active[n.Alias] = true
		defer delete(active, n.Alias)
		return yamlNodeToAny(n.Alias, depth+1, budget, active)
	case yaml.SequenceNode:
		if !yamlIsSeqTag(n.Tag) {
			return nil, fmt.Errorf("%w: 不允许的 YAML 标签 %s", ErrSpecInvalidYAML, n.Tag)
		}
		out := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			v, err := yamlNodeToAny(c, depth+1, budget, active)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.MappingNode:
		return yamlMappingToAny(n, depth, budget, active)
	case yaml.ScalarNode:
		if !yamlAllowedScalarTags[n.Tag] {
			return nil, fmt.Errorf("%w: 不允许的 YAML 标签 %s", ErrSpecInvalidYAML, n.Tag)
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, fmt.Errorf("%w: 标量解码失败 %v", ErrSpecInvalidYAML, err)
		}
		return v, nil
	}
	return nil, fmt.Errorf("%w: 未知节点类型 %d", ErrSpecInvalidYAML, n.Kind)
}

// yamlMappingToAny 映射节点转换：自定义标签拒绝；键必须为字符串标量；支持 "<<" 合并键
// （显式键优先；合并源为映射或映射序列，序列靠前元素优先）。
func yamlMappingToAny(n *yaml.Node, depth int, budget *yamlNodeBudget, active map[*yaml.Node]bool) (any, error) {
	if !yamlIsMapTag(n.Tag) {
		return nil, fmt.Errorf("%w: 不允许的 YAML 标签 %s", ErrSpecInvalidYAML, n.Tag)
	}
	out := make(map[string]any, len(n.Content)/2)
	merges := []any{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		keyNode, valNode := n.Content[i], n.Content[i+1]
		v, err := yamlNodeToAny(valNode, depth+1, budget, active)
		if err != nil {
			return nil, err
		}
		if yamlIsMergeKey(keyNode) {
			merges = append(merges, v)
			continue
		}
		if keyNode.Kind != yaml.ScalarNode || !yamlIsStringTag(keyNode.Tag) {
			return nil, fmt.Errorf("%w: 映射键必须为字符串", ErrSpecInvalidYAML)
		}
		out[keyNode.Value] = v
	}
	for _, mv := range merges {
		mergeYAMLMap(out, mv)
	}
	return out, nil
}

// mergeYAMLMap 将合并源（映射或映射序列）中尚未存在的键并入 out。
func mergeYAMLMap(out map[string]any, mv any) {
	switch m := mv.(type) {
	case map[string]any:
		for k, v := range m {
			if _, ok := out[k]; !ok {
				out[k] = v
			}
		}
	case []any:
		for _, item := range m {
			if im, ok := item.(map[string]any); ok {
				for k, v := range im {
					if _, ok := out[k]; !ok {
						out[k] = v
					}
				}
			}
		}
	}
}
