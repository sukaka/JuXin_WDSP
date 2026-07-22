// Package accessrules 提供 IP 访问控制（黑白名单）规则：存储、校验、CSV 导入导出与 HTTP 处理。
// 表结构见 server/migrations/000008_stage5.up.sql 的 ip_access_rules。
package accessrules

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// 规则类型
const (
	RuleTypeAllow = "ALLOW" // 白名单
	RuleTypeDeny  = "DENY"  // 黑名单
)

// 生效范围
const (
	ScopeGlobal      = "GLOBAL"      // 全局
	ScopeApplication = "APPLICATION" // 指定应用
)

// 规则状态
const (
	StatusDraft    = "DRAFT"    // 草稿（保留给导入草稿，本阶段不强制使用）
	StatusActive   = "ACTIVE"   // 生效
	StatusDisabled = "DISABLED" // 停用
	StatusExpired  = "EXPIRED"  // 临时规则已过期
	StatusDeleted  = "DELETED"  // 已删除（软删除）
)

// 有效期类型
const (
	ValidityPermanent = "PERMANENT" // 永久
	ValidityTemporary = "TEMPORARY" // 临时（必须有 effective_until）
)

// 来源类型
const (
	SourceManual        = "MANUAL"         // 手工创建
	SourceSecurityEvent = "SECURITY_EVENT" // 安全事件联动
	SourceImport        = "IMPORT"         // 批量导入
	SourceAutoBlock     = "AUTO_BLOCK"     // 自动封禁
	SourceSystem        = "SYSTEM"         // 系统内置
)

// IP 版本
const (
	IPVersion4 = "IPV4"
	IPVersion6 = "IPV6"
)

// 错误
var (
	ErrNotFound         = errors.New("access rule not found")
	ErrConflict         = errors.New("access rule conflict")
	ErrInvalidInput     = errors.New("invalid access rule input")
	ErrInvalidAddress   = errors.New("invalid address")
	ErrInvalidTime      = errors.New("invalid effective time")
	ErrProtectedAddress = errors.New("address is protected")
	ErrVersionConflict  = errors.New("access rule version conflict")
	ErrInvalidState     = errors.New("invalid rule state")
	ErrAppNotFound      = errors.New("application not found")
)

// Rule 是一条 IP 访问控制规则。
type Rule struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	RuleType       string     `json:"rule_type"`
	ScopeType      string     `json:"scope_type"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	Address        string     `json:"address"` // 规范形式的单 IP 或 CIDR
	IPVersion      string     `json:"ip_version"`
	Priority       int        `json:"priority"` // 数值小者优先
	Status         string     `json:"status"`
	ValidityType   string     `json:"validity_type"`
	EffectiveFrom  *time.Time `json:"effective_from"`
	EffectiveUntil *time.Time `json:"effective_until"`
	Reason         string     `json:"reason"`
	SourceType     string     `json:"source_type"`
	SourceEventID  *uuid.UUID `json:"source_event_id"`
	HitCount       int64      `json:"hit_count"`
	LastHitAt      *time.Time `json:"last_hit_at"`
	CreatedBy      *uuid.UUID `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedBy      *uuid.UUID `json:"updated_by"`
	UpdatedAt      time.Time  `json:"updated_at"`
	Version        int        `json:"version"`
}

// CreateInput 是创建规则的输入。
type CreateInput struct {
	Name           string
	RuleType       string // ALLOW / DENY
	ScopeType      string // GLOBAL / APPLICATION
	ApplicationID  *uuid.UUID
	Address        string // 单IP或CIDR（入库前规范化为 netip 规范形式）
	Priority       int
	ValidityType   string // PERMANENT / TEMPORARY
	EffectiveFrom  *time.Time
	EffectiveUntil *time.Time
	Reason         string
	SourceType     string // MANUAL / SECURITY_EVENT / IMPORT / AUTO_BLOCK / SYSTEM
	SourceEventID  *uuid.UUID
}

// UpdateInput 是更新规则的输入（乐观锁）。
// rule_type / scope_type / application_id 不允许修改（避免变更唯一性维度）。
type UpdateInput struct {
	ID             uuid.UUID
	Version        int
	Name           string
	Address        string
	Priority       int
	ValidityType   string
	EffectiveFrom  *time.Time
	EffectiveUntil *time.Time
	Reason         string
}

// ListFilter 是规则列表筛选。
type ListFilter struct {
	RuleType      string
	ScopeType     string
	ApplicationID *uuid.UUID
	Status        string
	SourceType    string
	Keyword       string // 匹配名称或地址（模糊）
	Address       string // 地址精确匹配（会先规范化）
	Page          int
	PageSize      int
}
