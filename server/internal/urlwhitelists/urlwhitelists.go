// Package urlwhitelists 提供 URL 白名单规则管理：存储、校验、状态流转与 HTTP 处理。
// 表结构见 server/migrations/000223_url_whitelists.up.sql 的 url_whitelist_rules。
package urlwhitelists

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// 生效范围
const (
	ScopeGlobal      = "GLOBAL"      // 全局
	ScopeApplication = "APPLICATION" // 指定应用
)

// URL 匹配方式
const (
	MatchExact  = "EXACT"  // 精确匹配
	MatchPrefix = "PREFIX" // 前缀匹配（路径段边界）
	MatchRegex  = "REGEX"  // RE2 正则匹配
)

// 规则状态
const (
	StatusDraft    = "DRAFT"    // 草稿
	StatusActive   = "ACTIVE"   // 生效
	StatusDisabled = "DISABLED" // 停用
	StatusExpired  = "EXPIRED"  // 已过期
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
)

// 错误
var (
	ErrNotFound        = errors.New("url whitelist rule not found")
	ErrConflict        = errors.New("url whitelist rule conflict")
	ErrInvalidInput    = errors.New("invalid url whitelist rule input")
	ErrInvalidTime     = errors.New("invalid effective time")
	ErrVersionConflict = errors.New("url whitelist rule version conflict")
	ErrInvalidState    = errors.New("invalid url whitelist rule state")
	ErrAppNotFound     = errors.New("application not found")
)

// Rule 是一条 URL 白名单规则。
type Rule struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	ScopeType      string     `json:"scope_type"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	MatchType      string     `json:"match_type"`
	URIPattern     string     `json:"uri_pattern"`
	Methods        []string   `json:"methods"`
	Priority       int        `json:"priority"`
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

// CreateInput 是新建 URL 白名单规则的输入。
type CreateInput struct {
	Name           string
	ScopeType      string
	ApplicationID  *uuid.UUID
	MatchType      string
	URIPattern     string
	Methods        []string
	Priority       int
	ValidityType   string
	EffectiveFrom  *time.Time
	EffectiveUntil *time.Time
	Reason         string
	SourceType     string
	SourceEventID  *uuid.UUID
}

// UpdateInput 是更新 URL 白名单规则的输入（乐观锁）。
type UpdateInput struct {
	ID             uuid.UUID
	Version        int
	Name           string
	MatchType      string
	URIPattern     string
	Methods        []string
	Priority       int
	ValidityType   string
	EffectiveFrom  *time.Time
	EffectiveUntil *time.Time
	Reason         string
}

// ListFilter 是规则列表查询条件。
type ListFilter struct {
	ScopeType     string
	ApplicationID *uuid.UUID
	MatchType     string
	Status        string
	SourceType    string
	Keyword       string
	Page          int
	PageSize      int
}

// ValidateStatusTransition 校验规则状态流转（与 IP 黑白名单规则一致）。
func ValidateStatusTransition(from, to string) error {
	switch to {
	case StatusActive:
		switch from {
		case StatusDraft, StatusDisabled, StatusActive:
			return nil
		case StatusExpired:
			return fmt.Errorf("%w: 已过期规则请先延期再启用", ErrInvalidState)
		}
	case StatusDisabled:
		switch from {
		case StatusActive, StatusDisabled, StatusExpired:
			return nil
		case StatusDraft:
			return fmt.Errorf("%w: 草稿规则尚未生效，无需停用（可启用或删除）", ErrInvalidState)
		}
	}
	return fmt.Errorf("%w: 不允许的状态流转 %s → %s", ErrInvalidState, from, to)
}
