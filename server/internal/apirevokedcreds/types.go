// types.go 已吊销凭据实体与应用层校验（阶段8 §35「已吊销凭据使用」数据源）。
// 指纹级清单，不存凭据明文；凭据身份沿用项目统一口径（dynamic_security/detectors
// CredentialKey / apiruntime identity_fingerprint）：credential_type 与网关身份指纹
// 前缀（auth:/key:/sess:）一致，fingerprint 为加盐 HMAC-SHA256 截断 16 字节的
// 32 位 hex（不含前缀）。表与约束由迁移 000156 建立，入库前校验与 CHECK 同口径。
package apirevokedcreds

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// 权限点（种子见迁移 000156）。
const (
	PermCredentialRead   = "api_credential.read"
	PermCredentialManage = "api_credential.manage"
)

// 凭据来源上下文（与网关身份指纹前缀一致，发布时按 type + ":" + fingerprint 直接比对）。
const (
	TypeAuth    = "auth" // Authorization 头派生凭据
	TypeAPIKey  = "key"  // X-API-Key 头派生凭据
	TypeSession = "sess" // Cookie 会话派生凭据
)

// maxReasonLen 吊销原因长度护栏。
const maxReasonLen = 512

// fingerprintRe 指纹格式（加盐 HMAC-SHA256 截断 16 字节 hex，与迁移 000156 CHECK 同口径）。
var fingerprintRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// ErrNotFound 吊销记录不存在（404）。
var ErrNotFound = errors.New("revoked credential not found")

// ErrDuplicate 同一（credential_type, fingerprint）已登记（409；唯一索引兜底）。
var ErrDuplicate = errors.New("revoked credential already exists")

// ValidationError 载荷校验错误（400；与存储错误显式区分）。
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalidf(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Credential 吊销凭据读模型。
type Credential struct {
	ID             uuid.UUID  `json:"id"`
	CredentialType string     `json:"credential_type"`
	Fingerprint    string     `json:"fingerprint"`
	Reason         string     `json:"reason"`
	RevokedBy      string     `json:"revoked_by"`
	EffectiveFrom  time.Time  `json:"effective_from"`
	EffectiveUntil *time.Time `json:"effective_until"`
	CreatedBy      string     `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// CreateInput 登记吊销写入载荷（EffectiveFrom 为空时服务端取当前时间）。
type CreateInput struct {
	CredentialType string
	Fingerprint    string
	Reason         string
	EffectiveFrom  *time.Time
	EffectiveUntil *time.Time
}

// UpdateInput 调整吊销写入载荷（credential_type/fingerprint 为吊销对象身份，不可变更；
// 变更身份 = 删除后重新登记）。
type UpdateInput struct {
	Reason         string
	EffectiveFrom  time.Time
	EffectiveUntil *time.Time
}

// ListFilter 列表过滤（均为可选）。
type ListFilter struct {
	CredentialType string // 按来源上下文过滤（空 = 全部）
	Active         *bool  // 当前生效窗口内过滤（nil = 全部）
}

func validCredentialType(t string) bool {
	switch t {
	case TypeAuth, TypeAPIKey, TypeSession:
		return true
	}
	return false
}

// normalize 归一化公共字段并校验（Create/Update 共用）。
func normalize(credentialType, fingerprint, reason string) (string, string, string, error) {
	credentialType = strings.ToLower(strings.TrimSpace(credentialType))
	if !validCredentialType(credentialType) {
		return "", "", "", invalidf("credential_type 仅支持 auth/key/sess")
	}
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	if !fingerprintRe.MatchString(fingerprint) {
		return "", "", "", invalidf("fingerprint 须为 32 位小写 hex（加盐 HMAC-SHA256 指纹）")
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "", "", "", invalidf("reason 必填（吊销原因）")
	}
	if len([]rune(reason)) > maxReasonLen {
		return "", "", "", invalidf("reason 不超过 %d 字符", maxReasonLen)
	}
	return credentialType, fingerprint, reason, nil
}

// validateWindow 生效窗口合法性（到期须晚于生效，与迁移 CHECK 同口径）。
func validateWindow(from time.Time, until *time.Time) error {
	if until != nil && !until.After(from) {
		return invalidf("effective_until 须晚于 effective_from")
	}
	return nil
}

// validateCreate 登记吊销入库前校验。
func validateCreate(in *CreateInput) error {
	t, fp, reason, err := normalize(in.CredentialType, in.Fingerprint, in.Reason)
	if err != nil {
		return err
	}
	in.CredentialType, in.Fingerprint, in.Reason = t, fp, reason
	from := time.Now()
	if in.EffectiveFrom != nil {
		from = in.EffectiveFrom.UTC()
	}
	return validateWindow(from, in.EffectiveUntil)
}

// validateUpdate 调整吊销入库前校验。
func validateUpdate(in *UpdateInput) error {
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return invalidf("reason 必填（吊销原因）")
	}
	if len([]rune(reason)) > maxReasonLen {
		return invalidf("reason 不超过 %d 字符", maxReasonLen)
	}
	in.Reason = reason
	in.EffectiveFrom = in.EffectiveFrom.UTC()
	return validateWindow(in.EffectiveFrom, in.EffectiveUntil)
}
