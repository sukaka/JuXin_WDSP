// authz_rules.go 授权基线下发（W4-GW，P0-16/17 运行时消费前置）：
// api_role_baselines 表 confirmed=true 行 → api_role_baselines（BFLA）；
// api_field_permissions 表行 → api_field_permissions（Mass Assignment/字段越权）。
// 两表由迁移 000043/000044 建立；缺失/查询失败 Warn 跳过，与 MaskRuleStore 同一模式。
package guardconfig

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
)

// RoleBaselineLister 角色功能级基线读取接口（api_role_baselines 表；包内单测可 fake 错误路径）。
type RoleBaselineLister interface {
	ListConfirmedRoleBaselines(ctx context.Context) ([]gatewayconfig.GuardRoleBaseline, error)
}

// RoleBaselineStore api_role_baselines 读取（表由迁移 000043 建立；按冻结列名读取，
// 列：role/method/action/allowed；endpoint_key 经 api_endpoints 关联解析；仅取 confirmed=true 行）。
type RoleBaselineStore struct {
	db *pgxpool.Pool
}

// NewRoleBaselineStore 创建角色功能级基线读取仓储。
func NewRoleBaselineStore(db *pgxpool.Pool) *RoleBaselineStore {
	return &RoleBaselineStore{db: db}
}

var _ RoleBaselineLister = (*RoleBaselineStore)(nil)

// ListConfirmedRoleBaselines 读取 confirmed 角色基线（按端点/角色/方法/动作稳定排序）。
func (s *RoleBaselineStore) ListConfirmedRoleBaselines(ctx context.Context) ([]gatewayconfig.GuardRoleBaseline, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.endpoint_key, rb.role, rb.method, rb.action, rb.allowed
FROM api_role_baselines rb
JOIN api_endpoints ep ON ep.id = rb.endpoint_id
WHERE rb.confirmed AND rb.identity_assurance = 'VERIFIED'
ORDER BY ep.endpoint_key, rb.role, rb.method, rb.action`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardRoleBaseline{}
	for rows.Next() {
		var b gatewayconfig.GuardRoleBaseline
		if err := rows.Scan(&b.EndpointKey, &b.Role, &b.Method, &b.Action, &b.Allowed); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// FieldPermissionLister 字段权限读取接口（api_field_permissions 表；包内单测可 fake 错误路径）。
type FieldPermissionLister interface {
	ListFieldPermissions(ctx context.Context) ([]gatewayconfig.GuardFieldPermission, error)
}

// FieldPermissionStore api_field_permissions 读取（表由迁移 000044 建立；按冻结列名读取，
// 列：field_path/direction/attribute/role/tenant；endpoint_key 经 api_endpoints 关联解析；
// role/tenant NULL 归一为默认行空串，与下发契约一致）。
type FieldPermissionStore struct {
	db *pgxpool.Pool
}

// NewFieldPermissionStore 创建字段权限读取仓储。
func NewFieldPermissionStore(db *pgxpool.Pool) *FieldPermissionStore {
	return &FieldPermissionStore{db: db}
}

var _ FieldPermissionLister = (*FieldPermissionStore)(nil)

// ListFieldPermissions 读取全部字段权限行（按端点/字段路径/方向稳定排序）。
func (s *FieldPermissionStore) ListFieldPermissions(ctx context.Context) ([]gatewayconfig.GuardFieldPermission, error) {
	rows, err := s.db.Query(ctx, `
SELECT ep.endpoint_key, fp.field_path, fp.direction, fp.attribute,
       COALESCE(fp.role, ''), COALESCE(fp.tenant, '')
FROM api_field_permissions fp
JOIN api_endpoints ep ON ep.id = fp.endpoint_id
ORDER BY ep.endpoint_key, fp.field_path, fp.direction`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []gatewayconfig.GuardFieldPermission{}
	for rows.Next() {
		var p gatewayconfig.GuardFieldPermission
		if err := rows.Scan(&p.EndpointKey, &p.FieldPath, &p.Direction, &p.Attribute, &p.Role, &p.Tenant); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetRoleBaselineLister 注入角色功能级基线读取（nil 时不下发 api_role_baselines 段）。
func (p *Provider) SetRoleBaselineLister(l RoleBaselineLister) { p.roleBaselines = l }

// SetFieldPermissionLister 注入字段权限读取（nil 时不下发 api_field_permissions 段）。
func (p *Provider) SetFieldPermissionLister(l FieldPermissionLister) { p.fieldPermissions = l }

// loadAPIRoleBaselines 读取 confirmed 角色基线；未注入或查询失败（如迁移 000043 表尚未建立）
// Warn 并跳过，不阻断发布主流程（与脱敏规则同一纪律：增量能力，缺失时保持发布通道既有行为，
// 网关无基线下发时 BFLA 检测零行为，行为与历史版本一致）。
func (p *Provider) loadAPIRoleBaselines(ctx context.Context) []gatewayconfig.GuardRoleBaseline {
	if p.roleBaselines == nil {
		return nil
	}
	rules, err := p.roleBaselines.ListConfirmedRoleBaselines(ctx)
	if err != nil {
		slog.Warn("list api role baselines failed, skip api_role_baselines", "error", err)
		return nil
	}
	if len(rules) == 0 {
		return nil
	}
	return rules
}

// loadAPIFieldPermissions 读取字段权限；未注入或查询失败（如迁移 000044 表尚未建立）
// Warn 并跳过，不阻断发布主流程（纪律同 loadAPIRoleBaselines）。
func (p *Provider) loadAPIFieldPermissions(ctx context.Context) []gatewayconfig.GuardFieldPermission {
	if p.fieldPermissions == nil {
		return nil
	}
	perms, err := p.fieldPermissions.ListFieldPermissions(ctx)
	if err != nil {
		slog.Warn("list api field permissions failed, skip api_field_permissions", "error", err)
		return nil
	}
	if len(perms) == 0 {
		return nil
	}
	return perms
}
