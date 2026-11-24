package apisecurity

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	SpecAuditPathParameterMissing     = "PATH_PARAMETER_MISSING"
	SpecAuditPathParameterNotRequired = "PATH_PARAMETER_NOT_REQUIRED"
	SpecAuditPathParameterUndeclared  = "PATH_PARAMETER_UNDECLARED"
	SpecAuditSensitiveQueryParameter  = "SENSITIVE_QUERY_PARAMETER"
	SpecAuditSuccessResponseMissing   = "SUCCESS_RESPONSE_MISSING"
	SpecAuditErrorResponseMissing     = "ERROR_RESPONSE_MISSING"
	SpecAuditSecuritySchemeUndefined  = "SECURITY_SCHEME_UNDEFINED"
	SpecAuditAPIKeyInQuery            = "API_KEY_IN_QUERY"

	specAuditMaxItems = 500
)

// SpecAuditItem 一条规范声明审计发现，仅包含参数名或认证方案名与定位元数据。
type SpecAuditItem struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	EndpointKey string `json:"endpoint_key"`
	ParamIn     string `json:"param_in"`
	ParamName   string `json:"param_name"`
	Message     string `json:"message"`
}

// SpecAuditResult 按需审计结果；计数基于完整发现集，Items 最多返回 500 条。
type SpecAuditResult struct {
	SpecID         uuid.UUID       `json:"spec_id"`
	Format         string          `json:"format"`
	OperationCount int             `json:"operation_count"`
	IssueCount     int             `json:"issue_count"`
	HighCount      int             `json:"high_count"`
	MediumCount    int             `json:"medium_count"`
	Items          []SpecAuditItem `json:"items"`
	Truncated      bool            `json:"truncated"`
}

var specPathPlaceholderPattern = regexp.MustCompile(`\{([^{}]+)\}`)

var sensitiveQueryParameterNames = map[string]struct{}{
	"password":    {},
	"passwd":      {},
	"pwd":         {},
	"token":       {},
	"accesstoken": {},
	"secret":      {},
	"apikey":      {},
}

// AuditSpecOperations 对解析后的操作执行确定性的路径、参数、响应与鉴权安全声明审计。
func AuditSpecOperations(specID uuid.UUID, format string, ops []SpecOperation) SpecAuditResult {
	result := SpecAuditResult{
		SpecID:         specID,
		Format:         format,
		OperationCount: len(ops),
		Items:          []SpecAuditItem{},
	}
	allItems := make([]SpecAuditItem, 0)
	for _, op := range ops {
		placeholders := map[string]struct{}{}
		for _, match := range specPathPlaceholderPattern.FindAllStringSubmatch(op.Path, -1) {
			placeholders[match[1]] = struct{}{}
		}
		pathParams := map[string]struct{}{}
		for _, param := range op.Params {
			if param.In != "PATH" {
				continue
			}
			pathParams[param.Name] = struct{}{}
			if !param.Required {
				allItems = append(allItems, SpecAuditItem{
					RuleID: SpecAuditPathParameterNotRequired, Severity: "MEDIUM",
					EndpointKey: op.Key, ParamIn: "PATH", ParamName: param.Name,
					Message: "PATH 参数 required 必须为 true",
				})
			}
			if _, ok := placeholders[param.Name]; !ok {
				allItems = append(allItems, SpecAuditItem{
					RuleID: SpecAuditPathParameterUndeclared, Severity: "MEDIUM",
					EndpointKey: op.Key, ParamIn: "PATH", ParamName: param.Name,
					Message: "PATH 参数未出现在路径占位中",
				})
			}
		}
		for name := range placeholders {
			if _, ok := pathParams[name]; !ok {
				allItems = append(allItems, SpecAuditItem{
					RuleID: SpecAuditPathParameterMissing, Severity: "HIGH",
					EndpointKey: op.Key, ParamIn: "PATH", ParamName: name,
					Message: "路径占位缺少对应的 PATH 参数声明",
				})
			}
		}
		allItems = append(allItems, auditSpecResponseDeclarations(op)...)
		if format == SpecFormatOpenAPI3 {
			allItems = append(allItems, auditSpecSecurityDeclarations(op)...)
		}
		if op.Method != http.MethodGet && op.Method != http.MethodDelete {
			continue
		}
		for _, param := range op.Params {
			if param.In == "QUERY" && isSensitiveQueryParameterName(param.Name) {
				allItems = append(allItems, SpecAuditItem{
					RuleID: SpecAuditSensitiveQueryParameter, Severity: "HIGH",
					EndpointKey: op.Key, ParamIn: "QUERY", ParamName: param.Name,
					Message: "敏感参数不应通过 GET/DELETE 查询参数传递",
				})
			}
		}
	}

	sort.Slice(allItems, func(i, j int) bool {
		a, b := allItems[i], allItems[j]
		if a.EndpointKey != b.EndpointKey {
			return a.EndpointKey < b.EndpointKey
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.ParamName != b.ParamName {
			return a.ParamName < b.ParamName
		}
		if a.ParamIn != b.ParamIn {
			return a.ParamIn < b.ParamIn
		}
		return a.Message < b.Message
	})
	result.IssueCount = len(allItems)
	for _, item := range allItems {
		switch item.Severity {
		case "HIGH":
			result.HighCount++
		case "MEDIUM":
			result.MediumCount++
		}
	}
	result.Truncated = len(allItems) > specAuditMaxItems
	if len(allItems) > specAuditMaxItems {
		allItems = allItems[:specAuditMaxItems]
	}
	result.Items = append(result.Items, allItems...)
	return result
}

func auditSpecResponseDeclarations(op SpecOperation) []SpecAuditItem {
	if !op.ResponseSemanticsKnown {
		return nil
	}
	hasSuccess, hasError := false, false
	for _, status := range op.ResponseStatuses {
		if strings.EqualFold(status, "default") {
			hasError = true
			continue
		}
		switch specResponseStatusFamily(status) {
		case '2':
			hasSuccess = true
		case '4', '5':
			hasError = true
		}
	}
	items := make([]SpecAuditItem, 0, 2)
	if !hasSuccess {
		items = append(items, SpecAuditItem{
			RuleID: SpecAuditSuccessResponseMissing, Severity: "HIGH", EndpointKey: op.Key,
			Message: "响应声明缺少明确的 2xx 成功响应",
		})
	}
	if !hasError {
		items = append(items, SpecAuditItem{
			RuleID: SpecAuditErrorResponseMissing, Severity: "MEDIUM", EndpointKey: op.Key,
			Message: "响应声明缺少 default、4xx 或 5xx 错误响应",
		})
	}
	return items
}

func auditSpecSecurityDeclarations(op SpecOperation) []SpecAuditItem {
	if !op.SecuritySemanticsKnown {
		return nil
	}
	items := make([]SpecAuditItem, 0, len(op.SecurityRequirements))
	seen := make(map[string]struct{}, len(op.SecurityRequirements))
	for _, name := range op.SecurityRequirements {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		scheme, defined := op.SecuritySchemes[name]
		if !defined {
			items = append(items, SpecAuditItem{
				RuleID: SpecAuditSecuritySchemeUndefined, Severity: "HIGH",
				EndpointKey: op.Key, ParamName: name,
				Message: "操作安全要求引用的认证方案未在 components.securitySchemes 中定义",
			})
			continue
		}
		if scheme.Type == "apiKey" && scheme.In == "query" {
			items = append(items, SpecAuditItem{
				RuleID: SpecAuditAPIKeyInQuery, Severity: "HIGH",
				EndpointKey: op.Key, ParamIn: "QUERY", ParamName: name,
				Message: "操作实际引用的 apiKey 认证方案通过 QUERY 参数传递",
			})
		}
	}
	return items
}

func specResponseStatusFamily(status string) byte {
	status = strings.ToUpper(status)
	if len(status) != 3 {
		return 0
	}
	if status[1:] == "XX" {
		return status[0]
	}
	for i := 1; i < len(status); i++ {
		if status[i] < '0' || status[i] > '9' {
			return 0
		}
	}
	if status[0] < '0' || status[0] > '9' {
		return 0
	}
	return status[0]
}

func isSensitiveQueryParameterName(name string) bool {
	normalized := strings.Map(func(r rune) rune {
		if r == '_' || r == '-' || r == '.' || unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, name)
	_, ok := sensitiveQueryParameterNames[normalized]
	return ok
}

func auditStoredSpec(spec *ImportSpec) (SpecAuditResult, error) {
	var ops []SpecOperation
	var err error
	switch spec.Format {
	case "", SpecFormatOpenAPI3, SpecFormatSwagger2:
		_, _, ops, err = ParseSpecContent(spec.SpecJSON)
	default:
		ops, err = parseStoredSpecOperations(spec)
	}
	if err != nil {
		return SpecAuditResult{}, fmt.Errorf("解析已存规范失败: %w", err)
	}
	if spec.Format != SpecFormatOpenAPI3 {
		// Swagger 最小转换与各类扩展格式不携带 OpenAPI 3 认证目录，不能按空目录推断。
		for i := range ops {
			ops[i].SecuritySemanticsKnown = false
		}
	}
	return AuditSpecOperations(spec.ID, spec.Format, ops), nil
}

// GetSpecAudit GET /api/v1/api-security/specs/{id}/audit
// 按需读取并解析已导入规范，只读计算，不返回参数值、凭据值或完整规范。
func (h *Handler) GetSpecAudit(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规范ID")
		return
	}
	spec, err := h.store.GetSpecContent(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "规范不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	result, err := auditStoredSpec(spec)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, result)
}
