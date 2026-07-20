// Package roles 提供角色与权限查询。
package roles

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Role 是角色实体。
type Role struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	IsBuiltin   bool      `json:"is_builtin"`
}

// Permission 是权限实体。
type Permission struct {
	ID          uuid.UUID `json:"id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Module      string    `json:"module"`
	Description string    `json:"description"`
}

// Handler 是角色权限处理器。
type Handler struct {
	db *pgxpool.Pool
}

// NewHandler 创建处理器。
func NewHandler(db *pgxpool.Pool) *Handler {
	return &Handler{db: db}
}

// ListRoles 返回全部角色。
func (h *Handler) ListRoles(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, code, name, description, is_builtin FROM roles ORDER BY is_builtin DESC, code`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var out []Role
	for rows.Next() {
		var role Role
		if err := rows.Scan(&role.ID, &role.Code, &role.Name, &role.Description, &role.IsBuiltin); err != nil {
			response.InternalError(w, r, err)
			return
		}
		out = append(out, role)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}

// GetRole 返回角色详情（含权限）。
func (h *Handler) GetRole(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色ID")
		return
	}
	var role Role
	err = h.db.QueryRow(r.Context(),
		`SELECT id, code, name, description, is_builtin FROM roles WHERE id = $1`, id).
		Scan(&role.ID, &role.Code, &role.Name, &role.Description, &role.IsBuiltin)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "角色不存在")
		return
	}
	perms, err := h.rolePermissions(r, id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 角色用户
	var userCount int
	_ = h.db.QueryRow(r.Context(),
		`SELECT count(*) FROM user_roles WHERE role_id = $1`, id).Scan(&userCount)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"role":        role,
		"permissions": perms,
		"user_count":  userCount,
	})
}

// RolePermissions 返回角色权限。
func (h *Handler) RolePermissions(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色ID")
		return
	}
	perms, err := h.rolePermissions(r, id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": perms})
}

func (h *Handler) rolePermissions(r *http.Request, roleID uuid.UUID) ([]Permission, error) {
	rows, err := h.db.Query(r.Context(), `
SELECT p.id, p.code, p.name, p.module, p.description
FROM permissions p
JOIN role_permissions rp ON rp.permission_id = p.id
WHERE rp.role_id = $1 ORDER BY p.module, p.code`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Module, &p.Description); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListPermissions 返回全部权限。
func (h *Handler) ListPermissions(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.Query(r.Context(),
		`SELECT id, code, name, module, description FROM permissions ORDER BY module, code`)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.Code, &p.Name, &p.Module, &p.Description); err != nil {
			response.InternalError(w, r, err)
			return
		}
		out = append(out, p)
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": out})
}
