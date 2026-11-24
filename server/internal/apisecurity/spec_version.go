// spec_version.go API 安全补全第三波（W3-C 规范中心增强，P0-12）：
// 规范格式识别（OpenAPI 3 / Swagger 2.0）、Swagger 2.0 → OpenAPI 3 最小映射转换、
// 操作级参数、响应与认证声明提取（参数用于 CHANGED 级跨版本对比，响应/认证用于按需审计）、版本状态机存储与 URL 导入（SSRF 防护）。
// 解析/转换/对比为纯逻辑（不依赖 DB），由 spec_version_test.go / spec_audit_test.go 覆盖。
//
// 扩展格式（阶段8 §33）：YAML 及 JSON Schema / Postman Collection v2.1 / GraphQL SDL
// 由 spec_formats.go / spec_postman.go / spec_jsonschema.go / spec_graphql.go 处理，
// 统一入口为 ParseSpecContent。
package apisecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// 规范格式（api_import_specs.format）。
const (
	SpecFormatOpenAPI3 = "openapi3"
	SpecFormatSwagger2 = "swagger2"
)

// 规范版本状态（api_import_specs.status，迁移 000046 CHECK 约束）。
const (
	SpecStatusDraft      = "DRAFT"      // 草稿（预留，导入流程不直接产生）
	SpecStatusActive     = "ACTIVE"     // 当前生效版本（同名唯一，部分唯一索引保证）
	SpecStatusHistorical = "HISTORICAL" // 被新版取代的历史版本
	SpecStatusInvalid    = "INVALID"    // 标记为无效（预留）
	SpecStatusArchived   = "ARCHIVED"   // 归档（预留）
)

// 跨版本 CHANGED 级对比的变化类型（SpecChange.change_type）。
const (
	ChangeEndpointAdded   = "ENDPOINT_ADDED"
	ChangeEndpointRemoved = "ENDPOINT_REMOVED"
	ChangeParamAdded      = "PARAM_ADDED"
	ChangeParamRemoved    = "PARAM_REMOVED"
	ChangeTypeChanged     = "TYPE_CHANGED"
	ChangeRequiredChanged = "REQUIRED_CHANGED"
)

// 规范版本/导入相关错误。
var (
	// ErrSpecNotSwagger2 文档缺少 swagger: "2.0" 版本声明。
	ErrSpecNotSwagger2 = errors.New("not a Swagger 2.0 document")
	// ErrSpecAlreadyActive 目标版本已是 ACTIVE（激活接口映射为 409）。
	ErrSpecAlreadyActive = errors.New("spec version already active")
	// ErrSpecFetchDenied URL 导入目标被 SSRF 防护拒绝（HTTP 层映射为 400）。
	ErrSpecFetchDenied = errors.New("spec fetch url denied")
)

// SpecParam 规范操作级参数（CHANGED 对比的最小单元）。
type SpecParam struct {
	Name     string `json:"name"`
	In       string `json:"in"` // PATH / QUERY / HEADER / COOKIE / BODY（大写）
	Type     string `json:"type"`
	Required bool   `json:"required"`
}

// SpecSecurityScheme 认证方案目录中供审计判定的最小声明，不包含方案参数名或凭据值。
type SpecSecurityScheme struct {
	Type string `json:"type,omitempty"`
	In   string `json:"in,omitempty"`
}

// SpecOperation 规范解析出的单个操作（端点 + 参数集合 + 响应声明 + 有效认证要求）。
type SpecOperation struct {
	Method                 string                        `json:"method"` // 大写 HTTP 方法
	Path                   string                        `json:"path"`   // 原始路径，{param} 保留原样
	Key                    string                        `json:"key"`    // METHOD + 空格 + path
	Params                 []SpecParam                   `json:"params"` // 按 (In, Name) 排序，保证确定性
	ResponseStatuses       []string                      `json:"response_statuses,omitempty"`
	ResponseSemanticsKnown bool                          `json:"response_semantics_known,omitempty"`
	SecurityRequirements   []string                      `json:"security_requirements,omitempty"`
	SecuritySchemes        map[string]SpecSecurityScheme `json:"security_schemes,omitempty"`
	SecuritySemanticsKnown bool                          `json:"security_semantics_known,omitempty"`
}

// SpecChange 跨版本 CHANGED 级对比的一条变化。
type SpecChange struct {
	EndpointKey string `json:"endpoint_key"`
	ChangeType  string `json:"change_type"`
	ParamIn     string `json:"param_in,omitempty"`
	ParamName   string `json:"param_name,omitempty"`
	Before      string `json:"before,omitempty"` // 旧值（类型名或 "true"/"false"）
	After       string `json:"after,omitempty"`  // 新值
}

// ---------- 格式识别与统一解析入口 ----------

// DetectSpecFormat 识别规范文档格式：openapi3 / swagger2 / ""（不支持）。
func DetectSpecFormat(doc map[string]any) string {
	if v, _ := doc["openapi"].(string); strings.HasPrefix(v, "3.") {
		return SpecFormatOpenAPI3
	}
	if v, _ := doc["swagger"].(string); v == "2.0" {
		return SpecFormatSwagger2
	}
	return ""
}

// ParseSpecDocument 统一解析入口：识别格式（Swagger 2.0 先做最小映射转换），
// 返回格式标识、规范化后的 OpenAPI 3 文档与操作列表。
// normalized 用于内容哈希与落库（下游一律按 OAS3 处理，重读时无需再次转换）。
func ParseSpecDocument(doc map[string]any) (format string, normalized map[string]any, ops []SpecOperation, err error) {
	format = DetectSpecFormat(doc)
	switch format {
	case SpecFormatOpenAPI3:
		normalized = doc
	case SpecFormatSwagger2:
		normalized, err = ConvertSwagger2ToOpenAPI3(doc)
		if err != nil {
			return "", nil, nil, err
		}
	default:
		return "", nil, nil, ErrSpecNotOpenAPI3
	}
	ops, err = parseSpecOperations(normalized, format == SpecFormatOpenAPI3)
	if err != nil {
		return "", nil, nil, err
	}
	return format, normalized, ops, nil
}

// ---------- Swagger 2.0 → OpenAPI 3 最小映射 ----------

// ConvertSwagger2ToOpenAPI3 Swagger 2.0 → OpenAPI 3 最小映射转换：
// host/basePath/schemes → servers；paths 下 query/header/path 参数的扁平 type
// 收拢为 schema；body/formData 参数映射为 requestBody；responses.schema → content。
// 仅保证端点/参数/响应骨架可供统一解析，不逐字段搬运（definitions 等原样忽略）；
// securityDefinitions/security 不转换，认证目录语义保持未知。
func ConvertSwagger2ToOpenAPI3(doc map[string]any) (map[string]any, error) {
	version, _ := doc["swagger"].(string)
	if version != "2.0" {
		return nil, ErrSpecNotSwagger2
	}
	out := map[string]any{"openapi": "3.0.0"}
	if info, ok := doc["info"]; ok {
		out["info"] = info
	} else {
		out["info"] = map[string]any{}
	}
	// servers：schemes（缺省 http）× host + basePath；host 缺省时退化为相对 basePath
	schemes := stringSlice(doc["schemes"])
	if len(schemes) == 0 {
		schemes = []string{"http"}
	}
	host, _ := doc["host"].(string)
	basePath, _ := doc["basePath"].(string)
	servers := make([]any, 0, len(schemes))
	for _, scheme := range schemes {
		u := basePath
		if host != "" {
			u = scheme + "://" + host + basePath
		}
		servers = append(servers, map[string]any{"url": u})
	}
	out["servers"] = servers
	// 请求体媒体类型（consumes 首个，缺省 application/json）
	consumes := stringSlice(doc["consumes"])
	bodyMediaType := "application/json"
	if len(consumes) > 0 {
		bodyMediaType = consumes[0]
	}
	if paths, ok := doc["paths"].(map[string]any); ok {
		out["paths"] = convertSwagger2Paths(paths, bodyMediaType)
	}
	return out, nil
}

// convertSwagger2Paths 逐路径转换 Path Item（parameters 与各色 method 操作）。
func convertSwagger2Paths(paths map[string]any, bodyMediaType string) map[string]any {
	out := make(map[string]any, len(paths))
	for path, itemRaw := range paths {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue
		}
		newItem := map[string]any{}
		if params, ok := item["parameters"].([]any); ok {
			newItem["parameters"] = convertSwagger2Params(params, bodyMediaType)
		}
		for key, opRaw := range item {
			if !openAPI3Methods[strings.ToLower(key)] {
				continue
			}
			op, ok := opRaw.(map[string]any)
			if !ok {
				continue
			}
			newItem[key] = convertSwagger2Operation(op, bodyMediaType)
		}
		out[path] = newItem
	}
	return out
}

// convertSwagger2Operation 转换单个操作：parameters 拆分常规/body/formData，responses 收拢 schema。
func convertSwagger2Operation(op map[string]any, bodyMediaType string) map[string]any {
	out := map[string]any{}
	if v, ok := op["summary"]; ok {
		out["summary"] = v
	}
	if v, ok := op["description"]; ok {
		out["description"] = v
	}
	if v, ok := op["operationId"]; ok {
		out["operationId"] = v
	}
	if v, ok := op["tags"]; ok {
		out["tags"] = v
	}
	if params, ok := op["parameters"].([]any); ok {
		regular, body, formData := splitSwagger2Params(params)
		if len(regular) > 0 {
			out["parameters"] = convertSwagger2Params(regular, bodyMediaType)
		}
		if rb := swagger2RequestBody(body, formData, bodyMediaType); rb != nil {
			out["requestBody"] = rb
		}
	}
	if responses, ok := op["responses"].(map[string]any); ok {
		out["responses"] = convertSwagger2Responses(responses)
	}
	return out
}

// splitSwagger2Params 按 in 拆分 Swagger 2.0 参数：常规（query/header/path）/ body / formData。
func splitSwagger2Params(params []any) (regular, body, formData []any) {
	for _, pRaw := range params {
		p, ok := pRaw.(map[string]any)
		if !ok {
			continue
		}
		switch in, _ := p["in"].(string); in {
		case "body":
			body = append(body, p)
		case "formData":
			formData = append(formData, p)
		default:
			regular = append(regular, p)
		}
	}
	return regular, body, formData
}

// convertSwagger2Params 常规参数：扁平 type/format/items 收拢为 schema 对象。
func convertSwagger2Params(params []any, bodyMediaType string) []any {
	out := make([]any, 0, len(params))
	for _, pRaw := range params {
		p, ok := pRaw.(map[string]any)
		if !ok {
			continue
		}
		np := map[string]any{}
		for _, k := range []string{"name", "in", "description", "required"} {
			if v, ok := p[k]; ok {
				np[k] = v
			}
		}
		schema := map[string]any{}
		for _, k := range []string{"type", "format", "items", "enum", "default"} {
			if v, ok := p[k]; ok {
				schema[k] = v
			}
		}
		if len(schema) > 0 {
			np["schema"] = schema
		}
		out = append(out, np)
	}
	return out
}

// swagger2RequestBody body / formData 参数映射为 OAS3 requestBody。
// body 优先（Swagger 2.0 规范中二者互斥）；formData 收拢为表单对象 schema。
func swagger2RequestBody(body, formData []any, bodyMediaType string) map[string]any {
	if len(body) > 0 {
		p, _ := body[0].(map[string]any)
		schema := map[string]any{}
		if m, ok := p["schema"].(map[string]any); ok {
			schema = m
		}
		required, _ := p["required"].(bool)
		return map[string]any{
			"required": required,
			"content":  map[string]any{bodyMediaType: map[string]any{"schema": schema}},
		}
	}
	if len(formData) > 0 {
		properties := map[string]any{}
		required := []any{}
		for _, pRaw := range formData {
			p, ok := pRaw.(map[string]any)
			if !ok {
				continue
			}
			name, _ := p["name"].(string)
			if name == "" {
				continue
			}
			prop := map[string]any{}
			for _, k := range []string{"type", "format", "items"} {
				if v, ok := p[k]; ok {
					prop[k] = v
				}
			}
			// type: file → OAS3 string/binary
			if prop["type"] == "file" {
				prop["type"] = "string"
				prop["format"] = "binary"
			}
			properties[name] = prop
			if req, _ := p["required"].(bool); req {
				required = append(required, name)
			}
		}
		schema := map[string]any{"type": "object", "properties": properties}
		if len(required) > 0 {
			schema["required"] = required
		}
		return map[string]any{
			"required": len(required) > 0,
			"content": map[string]any{
				"application/x-www-form-urlencoded": map[string]any{"schema": schema},
			},
		}
	}
	return nil
}

// convertSwagger2Responses 响应最小映射：description 透传，schema 收拢为 content。
func convertSwagger2Responses(responses map[string]any) map[string]any {
	out := make(map[string]any, len(responses))
	for code, rRaw := range responses {
		r, ok := rRaw.(map[string]any)
		if !ok {
			continue
		}
		nr := map[string]any{}
		if d, ok := r["description"]; ok {
			nr["description"] = d
		} else {
			nr["description"] = ""
		}
		if schema, ok := r["schema"]; ok {
			nr["content"] = map[string]any{
				"application/json": map[string]any{"schema": schema},
			}
		}
		out[code] = nr
	}
	return out
}

// ---------- OpenAPI 3 操作级参数、响应与认证声明解析 ----------

// ParseSpecOperations 解析 OpenAPI 3 文档，提取每个 path+method 的操作、参数集合、响应状态及有效认证要求
// （路径级 parameters 与操作级合并，操作级同 (name,in) 覆盖路径级；requestBody
// 首个媒体类型的 object schema 提取一级 properties 为 BODY 参数）。
// 操作未声明 security 时继承全局声明，显式空数组表示公开操作并覆盖全局声明。
// $ref 引用不展开（解析范围外的引用参数跳过，属文档化限制而非错误）。
func ParseSpecOperations(doc map[string]any) ([]SpecOperation, error) {
	return parseSpecOperations(doc, true)
}

func parseSpecOperations(doc map[string]any, securitySemanticsKnown bool) ([]SpecOperation, error) {
	version, _ := doc["openapi"].(string)
	if !strings.HasPrefix(version, "3.") {
		return nil, ErrSpecNotOpenAPI3
	}
	paths, ok := doc["paths"].(map[string]any)
	if !ok || len(paths) == 0 {
		return nil, ErrSpecNoPaths
	}
	globalSecurityRequirements := parseSpecSecurityRequirements(doc["security"])
	securitySchemes := parseSpecSecuritySchemes(doc)
	out := make([]SpecOperation, 0, len(paths))
	for path, itemRaw := range paths {
		item, ok := itemRaw.(map[string]any)
		if !ok {
			continue // 非对象 Path Item 跳过
		}
		pathParams := parseOAS3Params(item["parameters"])
		for method := range item {
			if !openAPI3Methods[strings.ToLower(method)] {
				continue
			}
			op, _ := item[method].(map[string]any) // 非对象操作按无参数处理
			m := strings.ToUpper(method)
			params := mergeSpecParams(pathParams, parseOAS3Params(op["parameters"]))
			params = append(params, parseRequestBodyParams(op["requestBody"])...)
			sort.Slice(params, func(i, j int) bool {
				if params[i].In != params[j].In {
					return params[i].In < params[j].In
				}
				return params[i].Name < params[j].Name
			})
			responseStatuses, responseSemanticsKnown := parseSpecResponseStatuses(op["responses"])
			securityRequirements := globalSecurityRequirements
			if raw, exists := op["security"]; exists {
				securityRequirements = parseSpecSecurityRequirements(raw)
			}
			parsed := SpecOperation{
				Method: m, Path: path, Key: m + " " + path, Params: params,
				ResponseStatuses: responseStatuses, ResponseSemanticsKnown: responseSemanticsKnown,
			}
			if securitySemanticsKnown {
				parsed.SecurityRequirements = securityRequirements
				parsed.SecuritySchemes = securitySchemes
				parsed.SecuritySemanticsKnown = true
			}
			out = append(out, parsed)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

func parseSpecSecuritySchemes(doc map[string]any) map[string]SpecSecurityScheme {
	components, _ := doc["components"].(map[string]any)
	rawSchemes, _ := components["securitySchemes"].(map[string]any)
	schemes := make(map[string]SpecSecurityScheme, len(rawSchemes))
	for name, raw := range rawSchemes {
		var parsed SpecSecurityScheme
		if scheme, ok := raw.(map[string]any); ok {
			parsed.Type, _ = scheme["type"].(string)
			parsed.In, _ = scheme["in"].(string)
		}
		schemes[name] = parsed
	}
	return schemes
}

func parseSpecSecurityRequirements(raw any) []string {
	requirements, ok := raw.([]any)
	if !ok {
		return nil
	}
	names := make(map[string]struct{})
	for _, rawRequirement := range requirements {
		requirement, ok := rawRequirement.(map[string]any)
		if !ok {
			continue
		}
		for name := range requirement {
			if name != "" {
				names[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(names))
	for name := range names {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func parseSpecResponseStatuses(raw any) ([]string, bool) {
	responses, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	statuses := make([]string, 0, len(responses))
	for status := range responses {
		statuses = append(statuses, strings.ToUpper(status))
	}
	sort.Strings(statuses)
	return statuses, true
}

// parseOAS3Params 解析 OAS3 parameters 数组（$ref 参数跳过）。
func parseOAS3Params(raw any) []SpecParam {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]SpecParam, 0, len(list))
	for _, pRaw := range list {
		p, ok := pRaw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := p["name"].(string)
		in, _ := p["in"].(string)
		if name == "" || in == "" {
			continue // $ref 参数无内联 name/in，跳过
		}
		out = append(out, SpecParam{
			Name:     name,
			In:       strings.ToUpper(in),
			Type:     schemaTypeOf(p["schema"]),
			Required: boolOf(p["required"]),
		})
	}
	return out
}

// parseRequestBodyParams 提取 OAS3 requestBody 一级 properties 为 BODY 参数。
// 媒体类型优先 application/json，否则取键序首个；仅 object schema 的一级属性。
func parseRequestBodyParams(raw any) []SpecParam {
	rb, ok := raw.(map[string]any)
	if !ok {
		return nil
	}
	content, ok := rb["content"].(map[string]any)
	if !ok || len(content) == 0 {
		return nil
	}
	mediaTypes := make([]string, 0, len(content))
	for mt := range content {
		mediaTypes = append(mediaTypes, mt)
	}
	sort.Strings(mediaTypes)
	chosen := mediaTypes[0]
	for _, mt := range mediaTypes {
		if mt == "application/json" {
			chosen = mt
			break
		}
	}
	media, ok := content[chosen].(map[string]any)
	if !ok {
		return nil
	}
	schema, ok := media["schema"].(map[string]any)
	if !ok {
		return nil
	}
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		return nil
	}
	requiredSet := map[string]bool{}
	for _, r := range stringSlice(schema["required"]) {
		requiredSet[r] = true
	}
	out := make([]SpecParam, 0, len(properties))
	for name, propRaw := range properties {
		prop, _ := propRaw.(map[string]any)
		out = append(out, SpecParam{
			Name:     name,
			In:       "BODY",
			Type:     schemaTypeOf(prop),
			Required: requiredSet[name],
		})
	}
	return out
}

// schemaTypeOf 取 schema 的 type；$ref 引用标记为 "$ref"，缺失为空串。
func schemaTypeOf(raw any) string {
	schema, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	if t, _ := schema["type"].(string); t != "" {
		return t
	}
	if _, ok := schema["$ref"].(string); ok {
		return "$ref"
	}
	return ""
}

// mergeSpecParams 合并路径级与操作级参数：操作级同 (In, Name) 覆盖路径级。
func mergeSpecParams(pathLevel, opLevel []SpecParam) []SpecParam {
	if len(pathLevel) == 0 {
		return opLevel
	}
	opKeys := make(map[string]bool, len(opLevel))
	for _, p := range opLevel {
		opKeys[p.In+" "+p.Name] = true
	}
	out := make([]SpecParam, 0, len(pathLevel)+len(opLevel))
	for _, p := range pathLevel {
		if !opKeys[p.In+" "+p.Name] {
			out = append(out, p)
		}
	}
	return append(out, opLevel...)
}

// ---------- 跨版本 CHANGED 级对比 ----------

// DiffSpecOperations 跨版本对比两个操作集合：
// 端点增删（ENDPOINT_ADDED/REMOVED）+ 同 path+method 的参数增删、
// 类型变化（TYPE_CHANGED）、required 变化（REQUIRED_CHANGED）。
// 结果按 (EndpointKey, ParamIn, ParamName, ChangeType) 排序，保证确定性。
func DiffSpecOperations(oldOps, newOps []SpecOperation) []SpecChange {
	oldByKey := make(map[string]SpecOperation, len(oldOps))
	for _, op := range oldOps {
		oldByKey[op.Key] = op
	}
	newByKey := make(map[string]SpecOperation, len(newOps))
	for _, op := range newOps {
		newByKey[op.Key] = op
	}
	changes := []SpecChange{}
	for _, old := range oldOps {
		if _, ok := newByKey[old.Key]; !ok {
			changes = append(changes, SpecChange{EndpointKey: old.Key, ChangeType: ChangeEndpointRemoved})
		}
	}
	for _, newOp := range newOps {
		old, ok := oldByKey[newOp.Key]
		if !ok {
			changes = append(changes, SpecChange{EndpointKey: newOp.Key, ChangeType: ChangeEndpointAdded})
			continue
		}
		changes = append(changes, diffSpecParams(old, newOp)...)
	}
	sort.Slice(changes, func(i, j int) bool {
		a, b := changes[i], changes[j]
		if a.EndpointKey != b.EndpointKey {
			return a.EndpointKey < b.EndpointKey
		}
		if a.ParamIn != b.ParamIn {
			return a.ParamIn < b.ParamIn
		}
		if a.ParamName != b.ParamName {
			return a.ParamName < b.ParamName
		}
		return a.ChangeType < b.ChangeType
	})
	return changes
}

// diffSpecParams 同端点两个版本的参数级对比。
func diffSpecParams(oldOp, newOp SpecOperation) []SpecChange {
	oldParams := make(map[string]SpecParam, len(oldOp.Params))
	for _, p := range oldOp.Params {
		oldParams[p.In+" "+p.Name] = p
	}
	newParams := make(map[string]SpecParam, len(newOp.Params))
	for _, p := range newOp.Params {
		newParams[p.In+" "+p.Name] = p
	}
	changes := []SpecChange{}
	for _, p := range oldOp.Params {
		if _, ok := newParams[p.In+" "+p.Name]; !ok {
			changes = append(changes, SpecChange{
				EndpointKey: oldOp.Key, ChangeType: ChangeParamRemoved,
				ParamIn: p.In, ParamName: p.Name, Before: p.Type,
			})
		}
	}
	for _, p := range newOp.Params {
		old, ok := oldParams[p.In+" "+p.Name]
		if !ok {
			changes = append(changes, SpecChange{
				EndpointKey: newOp.Key, ChangeType: ChangeParamAdded,
				ParamIn: p.In, ParamName: p.Name, After: p.Type,
			})
			continue
		}
		if old.Type != p.Type {
			changes = append(changes, SpecChange{
				EndpointKey: newOp.Key, ChangeType: ChangeTypeChanged,
				ParamIn: p.In, ParamName: p.Name, Before: old.Type, After: p.Type,
			})
		}
		if old.Required != p.Required {
			changes = append(changes, SpecChange{
				EndpointKey: newOp.Key, ChangeType: ChangeRequiredChanged,
				ParamIn: p.In, ParamName: p.Name,
				Before: fmt.Sprintf("%t", old.Required), After: fmt.Sprintf("%t", p.Required),
			})
		}
	}
	return changes
}

// ---------- 规范名解析 ----------

// resolveSpecName 规范版本链标识解析：显式 name > file_name > info.title > unnamed-<hash8>。
// 结果裁剪至 255 字符（api_import_specs.name 列上限）。
func resolveSpecName(reqName, fileName string, doc map[string]any, contentHash string) string {
	if name := truncateSpecName(reqName); name != "" {
		return name
	}
	if name := truncateSpecName(fileName); name != "" {
		return name
	}
	if info, ok := doc["info"].(map[string]any); ok {
		if title, _ := info["title"].(string); title != "" {
			if name := truncateSpecName(title); name != "" {
				return name
			}
		}
	}
	return "unnamed-" + contentHash[:8]
}

// truncateSpecName 去空白并截断至 255 字符。
func truncateSpecName(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}

// ---------- URL 导入（SSRF 防护） ----------

// specFetchTimeout URL 导入整体超时。
const specFetchTimeout = 10 * time.Second

// ssrfDeniedCIDRs 禁止访问的保留/内网网段（net.IP 内置判定之外的补充）：
// 0.0.0.0/8 本网络、100.64.0.0/10 运营商 NAT、198.18.0.0/15 基准测试、240.0.0.0/4 保留。
var ssrfDeniedCIDRs = mustParseCIDRs([]string{
	"0.0.0.0/8",
	"100.64.0.0/10",
	"198.18.0.0/15",
	"240.0.0.0/4",
})

func mustParseCIDRs(list []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(list))
	for _, s := range list {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			panic("invalid CIDR: " + s)
		}
		out = append(out, n)
	}
	return out
}

// checkPublicIP 校验目标 IP 必须为公网地址：
// 拒绝回环/私网/链路本地/组播/未指定及 ssrfDeniedCIDRs 网段（IPv4 映射 IPv6 一并归一）。
func checkPublicIP(ip net.IP) error {
	if ip == nil {
		return fmt.Errorf("%w: 空地址", ErrSpecFetchDenied)
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("%w: 内网/保留地址 %s", ErrSpecFetchDenied, ip)
	}
	for _, n := range ssrfDeniedCIDRs {
		if n.Contains(ip) {
			return fmt.Errorf("%w: 保留网段 %s", ErrSpecFetchDenied, ip)
		}
	}
	return nil
}

// validateSpecFetchURL 校验导入 URL：仅 http/https、主机可解析且全部解析结果为公网地址。
func validateSpecFetchURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil {
		return nil, fmt.Errorf("%w: URL 解析失败", ErrSpecFetchDenied)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%w: 仅支持 http/https", ErrSpecFetchDenied)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%w: 缺少主机名", ErrSpecFetchDenied)
	}
	if ip := net.ParseIP(host); ip != nil {
		if err := checkPublicIP(ip); err != nil {
			return nil, err
		}
		return u, nil
	}
	// 域名：解析全部 A/AAAA 记录逐一校验（任一内网地址即拒绝）
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%w: 主机名解析失败", ErrSpecFetchDenied)
	}
	for _, ip := range ips {
		if err := checkPublicIP(ip); err != nil {
			return nil, err
		}
	}
	return u, nil
}

// specFetchTransport 带 SSRF 防护的 Transport：拨号时重新解析并校验目标 IP，
// 直接连接已校验的地址，规避校验与连接之间的 DNS 重绑定。
func specFetchTransport() *http.Transport {
	dialer := &net.Dialer{Timeout: specFetchTimeout}
	return &http.Transport{
		TLSHandshakeTimeout: specFetchTimeout,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("%w: 地址解析失败", ErrSpecFetchDenied)
			}
			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil || len(ips) == 0 {
				return nil, fmt.Errorf("%w: 主机名解析失败", ErrSpecFetchDenied)
			}
			for _, ip := range ips {
				if err := checkPublicIP(ip); err != nil {
					return nil, err
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		},
	}
}

// newSpecFetchClient URL 导入 HTTP 客户端：SSRF 防护 Transport + 超时 + 重定向再校验。
func newSpecFetchClient() *http.Client {
	return &http.Client{
		Transport: specFetchTransport(),
		Timeout:   specFetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("%w: 重定向次数过多", ErrSpecFetchDenied)
			}
			_, err := validateSpecFetchURL(req.URL.String())
			return err
		},
	}
}

// fetchSpecDocument 从 URL 拉取规范文档：先校验 URL，再经防护客户端下载，
// 状态码须为 2xx，大小上限 specImportMaxBytes（与粘贴导入一致）。
func fetchSpecDocument(ctx context.Context, rawURL string, headers map[string]string) ([]byte, error) {
	u, err := validateSpecFetchURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("构造请求失败: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := newSpecFetchClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("拉取规范失败: 上游状态码 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, specImportMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("读取规范内容失败: %w", err)
	}
	if len(body) > specImportMaxBytes {
		return nil, fmt.Errorf("规范文档超过大小上限（16MiB）")
	}
	return body, nil
}

// ---------- 版本状态机存储 ----------

// GetLatestSpecByName 同名最高版本规范（含 spec_json；不存在返回 nil, nil）。
func (s *Store) GetLatestSpecByName(ctx context.Context, name string) (*ImportSpec, error) {
	var it ImportSpec
	err := s.db.QueryRow(ctx, `
SELECT id, name, version_no, status, parent_id, activated_at, format, file_name, content_hash,
       spec_json, endpoint_count, imported_by, created_at, source
FROM api_import_specs WHERE name = $1 ORDER BY version_no DESC LIMIT 1`, name).
		Scan(&it.ID, &it.Name, &it.VersionNo, &it.Status, &it.ParentID, &it.ActivatedAt,
			&it.Format, &it.FileName, &it.ContentHash, &it.SpecJSON, &it.EndpointCount,
			&it.ImportedBy, &it.CreatedAt, &it.Source)
	if err != nil {
		if isNoRows(err) {
			return nil, nil
		}
		return nil, err
	}
	return &it, nil
}

// GetSpecContent 规范详情（含 spec_json 大字段，跨版本 diff 用）。
func (s *Store) GetSpecContent(ctx context.Context, id uuid.UUID) (*ImportSpec, error) {
	var it ImportSpec
	err := s.db.QueryRow(ctx, `
SELECT id, name, version_no, status, parent_id, activated_at, format, file_name, content_hash,
       spec_json, endpoint_count, imported_by, created_at, source
FROM api_import_specs WHERE id = $1`, id).
		Scan(&it.ID, &it.Name, &it.VersionNo, &it.Status, &it.ParentID, &it.ActivatedAt,
			&it.Format, &it.FileName, &it.ContentHash, &it.SpecJSON, &it.EndpointCount,
			&it.ImportedBy, &it.CreatedAt, &it.Source)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &it, nil
}

// ActivateSpec 激活指定规范版本：同名当前 ACTIVE 降为 HISTORICAL，目标版本置 ACTIVE。
// 目标已是 ACTIVE 返回 ErrSpecAlreadyActive（409）；不存在返回 ErrNotFound。
func (s *Store) ActivateSpec(ctx context.Context, id uuid.UUID) (*ImportSpec, error) {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var name, status string
	err = tx.QueryRow(ctx, `SELECT name, status FROM api_import_specs WHERE id = $1 FOR UPDATE`, id).
		Scan(&name, &status)
	if err != nil {
		if isNoRows(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if status == SpecStatusActive {
		return nil, ErrSpecAlreadyActive
	}
	if _, err := tx.Exec(ctx, `
UPDATE api_import_specs SET status = $2 WHERE name = $1 AND status = 'ACTIVE'`,
		name, SpecStatusHistorical); err != nil {
		return nil, err
	}
	var it ImportSpec
	err = tx.QueryRow(ctx, `
UPDATE api_import_specs SET status = $2, activated_at = now() WHERE id = $1
RETURNING id, name, version_no, status, parent_id, activated_at, format, file_name, content_hash,
          endpoint_count, imported_by, created_at, source`,
		id, SpecStatusActive).
		Scan(&it.ID, &it.Name, &it.VersionNo, &it.Status, &it.ParentID, &it.ActivatedAt,
			&it.Format, &it.FileName, &it.ContentHash, &it.EndpointCount, &it.ImportedBy, &it.CreatedAt, &it.Source)
	if err != nil {
		return nil, err
	}
	return &it, tx.Commit(ctx)
}

// registerSpecEndpointsTx 将规范端点登记为 api_endpoints 候选（来源：规范导入）。
// 语义对齐 apiassets.UpsertDiscovery 的插入分支，但冲突时不做任何更新
// （不增加 hit_count、不覆盖已有资产状态），仅补 MISSING_IN_RUNTIME 的登记。
// 冲突键为迁移 000137 的复合唯一索引 uq_api_endpoints_scope（NULLS NOT DISTINCT）：
// 归属四列未显式提供，取默认值 application_id/domain_id/application_binding_id=NULL、
// host=”，protocol_type='REST'，规范登记的端点在统一归属（空）维度下按 endpoint_key 幂等。
// 返回实际新登记数量。
func registerSpecEndpointsTx(ctx context.Context, tx pgx.Tx, ops []SpecOperation) (int, error) {
	registered := 0
	for _, op := range ops {
		ct, err := tx.Exec(ctx, `
INSERT INTO api_endpoints (http_method, normalized_path, raw_path_example,
  directory_path, endpoint_key, api_confidence, is_api, hit_count, asset_status)
VALUES ($1, $2, $2, $3, $4, 1, TRUE, 0, 'DISCOVERED')
ON CONFLICT (application_id, domain_id, application_binding_id, host, endpoint_key, protocol_type) DO NOTHING`,
			op.Method, op.Path, specDirectoryOf(op.Path), op.Key)
		if err != nil {
			return registered, err
		}
		registered += int(ct.RowsAffected())
	}
	return registered, nil
}

// specDirectoryOf 目录派生（与 apiassets.DirectoryOf 语义一致，本地实现避免跨包依赖）：
// normalized_path 去掉最后一段（/test/php/login → /test/php；/users/{id} → /users）。
func specDirectoryOf(normalizedPath string) string {
	i := strings.LastIndex(normalizedPath, "/")
	if i <= 0 {
		return ""
	}
	return normalizedPath[:i]
}

// ---------- 通用小工具 ----------

// stringSlice 任意值转字符串数组（非数组或元素非字符串的跳过）。
func stringSlice(raw any) []string {
	list, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// boolOf 任意值转布尔（缺失/非布尔为 false）。
func boolOf(raw any) bool {
	b, _ := raw.(bool)
	return b
}

// parseStoredSpecOperations 从落库的规范化文档重新解析操作列表（CHANGED 对比/跨版本 diff/审计用）。
// openapi3/swagger2 落库内容已规范化为 OAS3，直接 ParseSpecOperations；
// 其余扩展格式按 format 调对应解析器或读取脱敏操作骨架。
// 解析失败视为内部数据异常。
func parseStoredSpecOperations(spec *ImportSpec) ([]SpecOperation, error) {
	var doc map[string]any
	if err := json.Unmarshal(spec.SpecJSON, &doc); err != nil {
		return nil, fmt.Errorf("已存规范文档反序列化失败: %w", err)
	}
	switch spec.Format {
	case SpecFormatPostman:
		return ParsePostmanCollection(doc)
	case SpecFormatJSONSchema:
		return ParseJSONSchema(doc)
	case SpecFormatGraphQL:
		sdl, _ := doc["sdl"].(string)
		return ParseGraphQLSDL(sdl)
	case SpecFormatProtobuf:
		if srcs := stringSlice(doc["sources"]); len(srcs) > 0 {
			ops, _, err := ParseProtobufSet(srcs)
			return ops, err
		}
		raw, _ := doc["raw"].(string)
		ops, _, err := ParseProtobuf(raw)
		return ops, err
	case SpecFormatWSDL, SpecFormatXSD:
		raw, _ := doc["raw"].(string)
		_, _, ops, err := parseSpecXML([]byte(raw))
		return ops, err
	case SpecFormatRAML:
		inner, _ := doc["doc"].(map[string]any)
		ops, _, err := ParseRAML(inner)
		return ops, err
	case SpecFormatAPIB:
		raw, _ := doc["raw"].(string)
		ops, _, err := ParseAPIB(raw)
		return ops, err
	case SpecFormatHAR:
		return parseStoredHAROperations(doc)
	case SpecFormatAsyncAPI:
		return ParseAsyncAPI(doc)
	default:
		return ParseSpecOperations(doc)
	}
}
