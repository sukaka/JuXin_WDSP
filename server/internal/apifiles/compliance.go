// compliance.go 文件合规规则（P2-03 管理面，迁移 000071）实体、枚举与
// match_value 规范化校验（handler 与 store 共用）。
//
// 消费方为网关联动分片（下发键 api_file_compliance_rules）：本包只负责
// 管理面 CRUD 与入库口径；匹配语义（EXT/MIME 与 api_file_assets 落库口径一致、
// FILENAME_REGEX 为 RE2）在入库前即规范化+校验，非法形态绝不落库。
package apifiles

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 动作（api_file_compliance_rules.action CHECK 对齐）：
// OBSERVE = 命中仅记录；BLOCK = 命中阻断。
const (
	ComplianceActionObserve = "OBSERVE"
	ComplianceActionBlock   = "BLOCK"
)

// 匹配类型（api_file_compliance_rules.match_type CHECK 对齐）。
const (
	MatchTypeExt           = "EXT"            // 扩展名（小写、无前导点，与资产 extension 同口径）
	MatchTypeMIME          = "MIME"           // 主类型小写（参数剥离，与资产 mime 同口径）
	MatchTypeFilenameRegex = "FILENAME_REGEX" // 文件名正则（RE2）
)

// match_value 长度上限（与表列宽一致）。
const (
	complianceValueMaxLen  = 256
	complianceReasonMaxLen = 256
	complianceExtMaxLen    = 16  // 与 api_file_assets.extension 列宽一致
	complianceMIMEMaxLen   = 128 // 与 api_file_assets.mime 列宽一致
)

// EXT 形态：小写字母数字开头，可含 _+-（不含点——前导点在规范化时剥离，
// 资产侧 extension 为单后缀口径，内部带点永不命中，直接判非法更诚实）。
var extValuePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_+-]{0,15}$`)

// MIME 形态：type/subtype（token 字符集按 RFC 2045 子集，小写已归一）。
var mimeValuePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9!#$&^_+.-]{0,126}/[a-z0-9][a-z0-9!#$&^_+.-]{0,126}$`)

// 合规规则仓储错误（handler 映射 404/409）。
var (
	ErrComplianceNotFound = errors.New("文件合规规则不存在")
	ErrComplianceConflict = errors.New("同方向同类型同匹配值的规则已存在")
)

// ComplianceRule 文件合规规则行（api_file_compliance_rules）。
type ComplianceRule struct {
	ID         uuid.UUID  `json:"id"`
	Direction  string     `json:"direction"`
	MatchType  string     `json:"match_type"`
	MatchValue string     `json:"match_value"`
	Action     string     `json:"action"`
	Reason     string     `json:"reason"`
	Enabled    bool       `json:"enabled"`
	CreatedBy  *uuid.UUID `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// ComplianceFilter 列表过滤（枚举值已在 handler 层归一校验）。
type ComplianceFilter struct {
	Direction string
	MatchType string
	Action    string
	Enabled   *bool // nil = 不过滤
	Page      int
	PageSize  int
}

// validMatchType 枚举校验。
func validMatchType(s string) bool {
	return s == MatchTypeExt || s == MatchTypeMIME || s == MatchTypeFilenameRegex
}

// validComplianceAction 枚举校验。
func validComplianceAction(s string) bool {
	return s == ComplianceActionObserve || s == ComplianceActionBlock
}

// normalize 归一（trim + 大写枚举 + match_value 按类型规范化）。
func (r *ComplianceRule) normalize() {
	r.Direction = strings.ToUpper(strings.TrimSpace(r.Direction))
	r.MatchType = strings.ToUpper(strings.TrimSpace(r.MatchType))
	r.Action = strings.ToUpper(strings.TrimSpace(r.Action))
	r.Reason = strings.TrimSpace(r.Reason)
	switch r.MatchType {
	case MatchTypeExt:
		// 小写 + 剥前导点（与资产 extension 落库口径一致）
		r.MatchValue = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(r.MatchValue), "."))
	case MatchTypeMIME:
		// 小写 + 剥参数（与资产 mime 落库口径一致）
		v := strings.ToLower(strings.TrimSpace(r.MatchValue))
		if i := strings.Index(v, ";"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		r.MatchValue = v
	default:
		r.MatchValue = strings.TrimSpace(r.MatchValue)
	}
}

// validate 入库前校验（枚举白名单 + match_value 按类型形态校验）。
// FILENAME_REGEX 用 Go regexp（RE2 语法）试编译——与网关判定引擎同族语法，
// 管理面编译不过的形态绝不落库。
func (r *ComplianceRule) validate() error {
	if !validDirection(r.Direction) {
		return fmt.Errorf("无效的 direction 取值（UPLOAD/DOWNLOAD）")
	}
	if !validMatchType(r.MatchType) {
		return fmt.Errorf("无效的 match_type 取值（EXT/MIME/FILENAME_REGEX）")
	}
	if !validComplianceAction(r.Action) {
		return fmt.Errorf("无效的 action 取值（OBSERVE/BLOCK）")
	}
	if len(r.MatchValue) == 0 {
		return fmt.Errorf("match_value 不能为空")
	}
	if len(r.MatchValue) > complianceValueMaxLen {
		return fmt.Errorf("match_value 长度不能超过 %d", complianceValueMaxLen)
	}
	switch r.MatchType {
	case MatchTypeExt:
		if !extValuePattern.MatchString(r.MatchValue) {
			return fmt.Errorf("EXT 形式非法（小写字母数字，可含 _+-，1-%d 字符，不含点）", complianceExtMaxLen)
		}
	case MatchTypeMIME:
		if len(r.MatchValue) > complianceMIMEMaxLen || !mimeValuePattern.MatchString(r.MatchValue) {
			return fmt.Errorf("MIME 形式非法（type/subtype，小写，不含参数）")
		}
	case MatchTypeFilenameRegex:
		if _, err := regexp.Compile(r.MatchValue); err != nil {
			return fmt.Errorf("FILENAME_REGEX 无法编译（RE2）：%v", err)
		}
	}
	if len(r.Reason) > complianceReasonMaxLen {
		return fmt.Errorf("reason 长度不能超过 %d", complianceReasonMaxLen)
	}
	return nil
}
