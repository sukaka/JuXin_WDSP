// Package apimcp MCP 工具目录管理面（NG-MCP G1 批次 B1，设计
// docs/nextgen/NG-MCP-g1-toolcall.md §1.3/§1.14 D3/D14）：
// 目录（服务身份维度）+工具行（tool_hash 审批绑定不可变摘要）+审核状态机
// （导入与变更恒落 PENDING_REVIEW——旧审批不继承）+绑定（应用×endpoint_path×
// 目录×模式）。权限复用 api_spec.read/manage（目录与 gRPC 描述符同属接口契约
// 资产域，零新增权限点）；写操作 HIGH 审计。
package apimcp

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 词表（设计冻结）。
const (
	ProtocolVersionDefault = "2025-11-25"

	StatusEnabled  = "ENABLED"
	StatusDisabled = "DISABLED"

	ReviewPending  = "PENDING_REVIEW"
	ReviewApproved = "APPROVED"
	ReviewRejected = "REJECTED"

	RiskLow    = "LOW"
	RiskMedium = "MEDIUM"
	RiskHigh   = "HIGH" // 导入缺省（未定级按高风险对待，与待审核语义同向）

	ClassPublic       = "PUBLIC"
	ClassInternal     = "INTERNAL"
	ClassConfidential = "CONFIDENTIAL"
	ClassUnknown      = "UNKNOWN" // 导入缺省

	ModeObserve = "OBSERVE"
	ModeProtect = "PROTECT"

	// ArgConstraint 两种确定性约束（设计 §1.4 第 4 条）
	ArgKindPathPrefix   = "path_prefix"
	ArgKindDomainSuffix = "domain_suffix"

	maxNameLen         = 128
	maxServiceIdentLen = 256
	maxToolVersionLen  = 128
	maxEndpointPathLen = 1024
	maxDescriptionLen  = 65536 // 描述全文入 tool_hash 的体量上限（防畸形载荷；规范化 sha256 仍确定性）
	maxPreviewLen      = 512   // description_preview 截断（仅管理面展示，永不为证据）
	maxSchemaBytes     = 65536 // 单 schema JSONB 体量上限（与 success_rule 同量纲先例）
)

// 哨兵错误（handler 映射 400/404/409 精确区分）。
var (
	ErrNotFound          = errors.New("mcp catalog not found")
	ErrDuplicateName     = errors.New("mcp catalog name already exists")
	ErrBindingNotFound   = errors.New("mcp binding not found")
	ErrBindingDuplicate  = errors.New("mcp binding already exists for (application, endpoint_path)")
	ErrCatalogNotFound   = errors.New("referenced mcp catalog not found")
	ErrAppNotFound       = errors.New("referenced application not found")
	ErrVersionConflict   = errors.New("mcp version conflict（乐观锁不匹配，请刷新后重试）")
	ErrCatalogInUse      = errors.New("mcp catalog is referenced by bindings（先解绑再删除）")
	ErrReviewActionVocab = errors.New("review action 词表外（APPROVED|REJECTED）")
)

// ValidationError 载荷校验错误（400；与存储错误显式区分——apigrpcdesc 同形态）。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalidf(format string, args ...any) error {
	return &ValidationError{Msg: fmt.Sprintf(format, args...)}
}

// ArgConstraint 参数范围约束行（设计 §1.4：G1 两种确定性约束）。
type ArgConstraint struct {
	Field string   `json:"field"`           // 参数字段点路径（如 path/url）
	Kind  string   `json:"kind"`            // path_prefix|domain_suffix
	Allow []string `json:"allow,omitempty"` // 允许前缀/后缀集合（非空）
}

// ToolInput 工具行写入载荷（导入/整体再导入共用）。
type ToolInput struct {
	ToolName           string          `json:"tool_name"`
	ToolVersion         string          `json:"tool_version"`
	Description         string          `json:"description"`                    // 规范化描述全文（入 tool_hash；preview 截断另存）
	PreserveDescription bool            `json:"preserve_description,omitempty"` // 再导入未重填描述时保留存量 description_digest/preview
	InputSchema         *map[string]any `json:"input_schema"`
	OutputSchema       *map[string]any `json:"output_schema"`
	CapabilityTags     []string        `json:"capability_tags"`
	RiskLevel          string          `json:"risk_level"`          // 导入缺省 HIGH
	DataClassification string          `json:"data_classification"` // 导入缺省 UNKNOWN
	AllowedPrincipals  []string        `json:"allowed_principals"`
	AllowedRoles       []string        `json:"allowed_roles"`
	AllowedTenants     []string        `json:"allowed_tenants"`
	ApprovalRequired   bool            `json:"approval_required"`
	MaxCallsPerMinute  int             `json:"max_calls_per_minute"`
	ArgConstraints     []ArgConstraint `json:"arg_constraints"`
}

// CatalogInput 目录写入载荷（POST 导入 / PUT 整体再导入，整体替换语义）。
type CatalogInput struct {
	Name            string      `json:"name"`
	ServiceIdentity string      `json:"service_identity"`
	ProtocolVersion string      `json:"protocol_version"`
	Tools           []ToolInput `json:"tools"`
	Version         int         `json:"version"` // PUT 乐观锁（≥1；POST 忽略）
}

// Catalog 目录行（读模型）。
type Catalog struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	ServiceIdentity string    `json:"service_identity"`
	ProtocolVersion string    `json:"protocol_version"`
	Source          string    `json:"source"`
	Status          string    `json:"status"`
	CatalogHash     string    `json:"catalog_hash"`
	Version         int       `json:"version"`
	CreatedBy       string    `json:"created_by"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// CatalogSummary 目录列表行（含审核统计）。
type CatalogSummary struct {
	Catalog
	ToolCount     int `json:"tool_count"`
	ApprovedCount int `json:"approved_count"`
	PendingCount  int `json:"pending_count"`
	RejectedCount int `json:"rejected_count"`
}

// Tool 工具行（读模型）。
type Tool struct {
	ID                 uuid.UUID       `json:"id"`
	CatalogID          uuid.UUID       `json:"catalog_id"`
	ToolName           string          `json:"tool_name"`
	ToolVersion        string          `json:"tool_version"`
	DescriptionDigest  string          `json:"description_digest"`
	DescriptionPreview string          `json:"description_preview"`
	InputSchema        map[string]any  `json:"input_schema"`
	OutputSchema       map[string]any  `json:"output_schema"`
	InputSchemaDigest  string          `json:"input_schema_digest"`
	OutputSchemaDigest string          `json:"output_schema_digest"`
	ToolHash           string          `json:"tool_hash"`
	CapabilityTags     []string        `json:"capability_tags"`
	RiskLevel          string          `json:"risk_level"`
	DataClassification string          `json:"data_classification"`
	AllowedPrincipals  []string        `json:"allowed_principals"`
	AllowedRoles       []string        `json:"allowed_roles"`
	AllowedTenants     []string        `json:"allowed_tenants"`
	ApprovalRequired   bool            `json:"approval_required"`
	MaxCallsPerMinute  int             `json:"max_calls_per_minute"`
	ArgConstraints     []ArgConstraint `json:"arg_constraints"`
	ReviewStatus       string          `json:"review_status"`
	ReviewedBy         string          `json:"reviewed_by"`
	ReviewedAt         *time.Time      `json:"reviewed_at"`
	CreatedAt          time.Time       `json:"created_at"`
	UpdatedAt          time.Time       `json:"updated_at"`
}

// ReviewInput 审核载荷（action + 定级更新（可选字段；未给出保持原值））。
type ReviewInput struct {
	Action             string   `json:"action"` // APPROVED|REJECTED
	RiskLevel          string   `json:"risk_level,omitempty"`
	DataClassification string   `json:"data_classification,omitempty"`
	AllowedPrincipals  []string `json:"allowed_principals,omitempty"`
	AllowedRoles       []string `json:"allowed_roles,omitempty"`
	AllowedTenants     []string `json:"allowed_tenants,omitempty"`
	ApprovalRequired   *bool    `json:"approval_required,omitempty"`
	MaxCallsPerMinute  *int     `json:"max_calls_per_minute,omitempty"`
}

// BindingInput 绑定写入载荷。
type BindingInput struct {
	ApplicationID string `json:"application_id"`
	EndpointPath  string `json:"endpoint_path"`
	CatalogID     string `json:"catalog_id"`
	Mode          string `json:"mode"`
	Version       int    `json:"version"`
}

// Binding 绑定行（读模型；catalog_name JOIN 带出）。
type Binding struct {
	ID            uuid.UUID `json:"id"`
	ApplicationID uuid.UUID `json:"application_id"`
	EndpointPath  string    `json:"endpoint_path"`
	CatalogID     uuid.UUID `json:"catalog_id"`
	CatalogName   string    `json:"catalog_name"`
	Mode          string    `json:"mode"`
	Version       int       `json:"version"`
	CreatedBy     string    `json:"created_by"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// ValidateToolInput 工具行校验（词表/长度——tool_hash 计算在 store 层）。
func ValidateToolInput(i int, in ToolInput) string {
	if strings.TrimSpace(in.ToolName) == "" || len(in.ToolName) > maxNameLen {
		return fmt.Sprintf("tools[%d].tool_name 必填且不超过 %d 字符", i, maxNameLen)
	}
	if len(in.ToolVersion) > maxToolVersionLen {
		return fmt.Sprintf("tools[%d].tool_version 不超过 %d 字符", i, maxToolVersionLen)
	}
	if len(in.Description) > maxDescriptionLen {
		return fmt.Sprintf("tools[%d].description 不超过 %d 字符", i, maxDescriptionLen)
	}
	if in.RiskLevel != "" {
		switch strings.ToUpper(strings.TrimSpace(in.RiskLevel)) {
		case RiskLow, RiskMedium, RiskHigh:
		default:
			return fmt.Sprintf("tools[%d].risk_level 词表外（LOW|MEDIUM|HIGH）", i)
		}
	}
	if in.DataClassification != "" {
		switch strings.ToUpper(strings.TrimSpace(in.DataClassification)) {
		case ClassPublic, ClassInternal, ClassConfidential, ClassUnknown:
		default:
			return fmt.Sprintf("tools[%d].data_classification 词表外（PUBLIC|INTERNAL|CONFIDENTIAL|UNKNOWN）", i)
		}
	}
	if in.MaxCallsPerMinute < 0 {
		return fmt.Sprintf("tools[%d].max_calls_per_minute 必须 ≥0", i)
	}
	for j, c := range in.ArgConstraints {
		if strings.TrimSpace(c.Field) == "" || len(c.Field) > maxNameLen {
			return fmt.Sprintf("tools[%d].arg_constraints[%d].field 必填且不超过 %d 字符", i, j, maxNameLen)
		}
		switch c.Kind {
		case ArgKindPathPrefix, ArgKindDomainSuffix:
		default:
			return fmt.Sprintf("tools[%d].arg_constraints[%d].kind 词表外（path_prefix|domain_suffix）", i, j)
		}
		if len(c.Allow) == 0 {
			return fmt.Sprintf("tools[%d].arg_constraints[%d].allow 非空必填", i, j)
		}
		for k, a := range c.Allow {
			if strings.TrimSpace(a) == "" || len(a) > 512 {
				return fmt.Sprintf("tools[%d].arg_constraints[%d].allow[%d] 非空且不超过 512 字符", i, j, k)
			}
		}
	}
	return ""
}

// ValidateCatalogInput 目录载荷校验（整体替换语义：tools 全量给出可空数组
// （空目录合法——发布段即空 tools；名称/身份/版本形态）。
func ValidateCatalogInput(in CatalogInput) string {
	if strings.TrimSpace(in.Name) == "" || len(in.Name) > maxNameLen {
		return "name 必填且不超过 128 字符"
	}
	if strings.TrimSpace(in.ServiceIdentity) == "" || len(in.ServiceIdentity) > maxServiceIdentLen {
		return "service_identity 必填且不超过 256 字符"
	}
	if v := strings.TrimSpace(in.ProtocolVersion); v != "" && len(v) > 32 {
		return "protocol_version 不超过 32 字符"
	}
	for i, t := range in.Tools {
		if msg := ValidateToolInput(i, t); msg != "" {
			return msg
		}
	}
	return ""
}

// ValidateBindingInput 绑定载荷校验。
func ValidateBindingInput(in BindingInput) string {
	if _, err := uuid.Parse(strings.TrimSpace(in.ApplicationID)); err != nil {
		return "application_id 非法（UUID）"
	}
	p := strings.TrimSpace(in.EndpointPath)
	if p == "" || len(p) > maxEndpointPathLen || !strings.HasPrefix(p, "/") {
		return "endpoint_path 须为 / 开头路径（≤1024 字符）"
	}
	if _, err := uuid.Parse(strings.TrimSpace(in.CatalogID)); err != nil {
		return "catalog_id 非法（UUID）"
	}
	switch strings.ToUpper(strings.TrimSpace(in.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		return "mode 非法（OBSERVE|PROTECT，缺省 OBSERVE）"
	}
	return ""
}
