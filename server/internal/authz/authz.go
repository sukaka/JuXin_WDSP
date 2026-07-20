// Package authz 提供认证主体（Principal）与权限上下文，无其他内部依赖。
package authz

import (
	"context"

	"github.com/google/uuid"
)

// Principal 是当前认证主体。
type Principal struct {
	UserID        uuid.UUID
	Username      string
	DisplayName   string
	Roles         []string
	Permissions   []string
	SessionID     string
	SourceIP      string
	UserAgent     string
	MustChangePwd bool
	PermsSet      map[string]bool
}

// HasPermission 判断主体是否拥有指定权限。
func (p *Principal) HasPermission(perm string) bool {
	if p == nil {
		return false
	}
	return p.PermsSet[perm]
}

// HasRole 判断主体是否拥有指定角色。
func (p *Principal) HasRole(role string) bool {
	if p == nil {
		return false
	}
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type ctxKey string

const principalKey ctxKey = "jiuzhang_principal"

// WithPrincipal 将认证主体注入上下文。
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}

// PrincipalFrom 从上下文获取认证主体，未认证返回 nil。
func PrincipalFrom(ctx context.Context) *Principal {
	if p, ok := ctx.Value(principalKey).(*Principal); ok {
		return p
	}
	return nil
}

// 内置角色编码
const (
	RoleSystemAdmin   = "SYSTEM_ADMIN"
	RoleSecurityAdmin = "SECURITY_ADMIN"
	RoleAuditAdmin    = "AUDIT_ADMIN"
)

// BuiltinRoles 返回三权内置角色清单。
func BuiltinRoles() []string {
	return []string{RoleSystemAdmin, RoleSecurityAdmin, RoleAuditAdmin}
}

// IsBuiltinRole 判断是否内置管理角色。
func IsBuiltinRole(role string) bool {
	switch role {
	case RoleSystemAdmin, RoleSecurityAdmin, RoleAuditAdmin:
		return true
	}
	return false
}
