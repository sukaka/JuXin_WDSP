package users

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/sessions"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// userStatusStore 抽象状态流转仓储操作（生产默认使用 *Store，单测可注入内存替身）。
type userStatusStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	Enable(ctx context.Context, id uuid.UUID) error
	Unlock(ctx context.Context, id uuid.UUID) error
}

// Handler 是用户管理处理器。
type Handler struct {
	store       *Store
	statusStore userStatusStore
	sessions    *sessions.Service
	settings    *settings.Service
	audits      *audits.Service
}

// NewHandler 创建用户管理处理器。
func NewHandler(store *Store, sess *sessions.Service, st *settings.Service, au *audits.Service) *Handler {
	return &Handler{store: store, statusStore: store, sessions: sess, settings: st, audits: au}
}

func (h *Handler) statusRepo() userStatusStore {
	if h.statusStore != nil {
		return h.statusStore
	}
	return h.store
}

type createUserRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	RoleCode    string `json:"role_code"`
}

// List 用户列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	f := ListFilter{
		Username: r.URL.Query().Get("username"),
		Status:   r.URL.Query().Get("status"),
		RoleCode: r.URL.Query().Get("role_code"),
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	list, total, err := h.store.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 附加角色信息
	items := make([]map[string]interface{}, 0, len(list))
	for _, u := range list {
		roles, _ := h.store.GetRoles(r.Context(), u.ID)
		items = append(items, userItem(&u, roles))
	}
	response.Page(w, r, items, total, f.Page, f.PageSize)
}

// Create 创建用户（系统管理员）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createUserRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// 用户名规则校验
	if err := validateUsername(req.Username); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	if len(req.DisplayName) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "显示名称过长")
		return
	}
	// 角色校验（仅允许内置三权角色）
	if !authz.IsBuiltinRole(req.RoleCode) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色")
		return
	}
	roleID, err := h.store.GetRoleIDByCode(r.Context(), req.RoleCode)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色")
		return
	}

	// 生成临时密码
	tempPassword, err := security.GenerateTemporaryPassword(16)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	hash, err := security.HashPassword(tempPassword)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	policy := h.settings.PasswordPolicy(r.Context())
	var expiresAt *time.Time
	if policy.ExpireDays > 0 {
		t := time.Now().Add(time.Duration(policy.ExpireDays) * 24 * time.Hour)
		expiresAt = &t
	}
	now := time.Now()
	user := &User{
		Username:           req.Username,
		DisplayName:        req.DisplayName,
		PasswordHash:       hash,
		Status:             StatusActive,
		MustChangePassword: true,
		PasswordChangedAt:  &now,
		PasswordExpiresAt:  expiresAt,
		CreatedBy:          &p.UserID,
	}
	if err := h.store.CreateWithRole(r.Context(), user, roleID, p.UserID); err != nil {
		if errors.Is(err, ErrUsernameExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "用户名已存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}

	h.recordAudit(r, p, "users", "create", "user", user.ID.String(), req.Username,
		"", userSummary(user, req.RoleCode), audits.ResultSuccess, "", audits.RiskMedium)

	// 临时密码仅在创建响应中返回一次，不记录日志/审计
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"user":               userItem(user, []RoleInfo{{Code: req.RoleCode}}),
		"temporary_password": tempPassword,
		"notice":             "请立即将临时密码告知用户，首次登录必须修改",
	})
}

// Get 用户详情。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	user, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	roles, _ := h.store.GetRoles(r.Context(), id)
	response.JSON(w, r, http.StatusOK, userItem(user, roles))
}

type updateUserRequest struct {
	DisplayName string `json:"display_name"`
	RoleCode    string `json:"role_code"`
	Version     int    `json:"version"`
}

// Update 修改用户（含角色变更，三权互斥校验）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	var req updateUserRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	if req.Version != target.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"该用户已被其他管理员修改，请刷新后重试")
		return
	}
	var roleID *uuid.UUID
	if req.RoleCode != "" {
		if !authz.IsBuiltinRole(req.RoleCode) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色")
			return
		}
		id, err := h.store.GetRoleIDByCode(r.Context(), req.RoleCode)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的角色")
			return
		}
		roleID = &id
	}

	before := userSummary(target, roleCodesOf(target, h.store, r))

	target.DisplayName = req.DisplayName
	if target.DisplayName == "" {
		target.DisplayName = target.Username
	}
	// 与 Create/个人资料同一限制，避免超长输入落到数据库约束报 500
	if len(target.DisplayName) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "显示名称过长")
		return
	}
	roleChanged, err := h.store.UpdateWithRole(r.Context(), target, roleID, p.UserID)
	if errors.Is(err, ErrVersionConflict) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"该用户已被其他管理员修改，请刷新后重试")
		return
	}
	if errors.Is(err, ErrLastSystemAdmin) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"不能移除最后一个系统管理员的角色")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}

	if roleChanged {
		// 角色变更后目标用户全部会话失效。
		if err := h.sessions.RevokeAllForUser(r.Context(), id, "role_changed"); err != nil {
			response.InternalError(w, r, err)
			return
		}
		risk := audits.RiskHigh
		if req.RoleCode == authz.RoleSystemAdmin {
			risk = audits.RiskCritical
		}
		h.recordAudit(r, p, "users", "assign_role", "user", id.String(), target.Username,
			before, userSummary(target, req.RoleCode), audits.ResultSuccess, "", risk)
	}

	roles, err := h.store.GetRoles(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "update", "user", id.String(), target.Username,
		before, userSummary(target, rolesStr(roles)), audits.ResultSuccess, "", audits.RiskLow)

	response.JSON(w, r, http.StatusOK, userItem(target, roles))
}

// Enable 启用已停用的用户（状态机约束：仅允许 DISABLED -> ACTIVE）。
func (h *Handler) Enable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	repo := h.statusRepo()
	target, err := repo.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if target.Status != StatusDisabled {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅已停用的用户可执行启用操作")
		return
	}
	if err := repo.Enable(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, ErrInvalidStatus):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅已停用的用户可执行启用操作")
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "users", "enable", "user", id.String(), target.Username,
		"status=DISABLED", "status=ACTIVE", audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "用户已启用"})
}

// Disable 停用用户。
func (h *Handler) Disable(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	if id == p.UserID {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "不能停用当前登录账号")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	roles, _ := h.store.GetRoles(r.Context(), id)
	if err := h.store.SetStatusGuarded(r.Context(), id, StatusDisabled); errors.Is(err, ErrLastSystemAdmin) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"不能停用最后一个系统管理员")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.sessions.RevokeAllForUser(r.Context(), id, "user_disabled"); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "disable", "user", id.String(), target.Username,
		userSummary(target, rolesStr(roles)), "status=DISABLED", audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "用户已停用"})
}

// Unlock 解锁已锁定的用户（状态机约束：仅允许 LOCKED -> ACTIVE，不得重启用已停用账号）。
func (h *Handler) Unlock(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	repo := h.statusRepo()
	target, err := repo.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if target.Status != StatusLocked {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅已锁定的用户可执行解锁操作")
		return
	}
	if err := repo.Unlock(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, ErrInvalidStatus):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "仅已锁定的用户可执行解锁操作")
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "users", "unlock", "user", id.String(), target.Username,
		"status=LOCKED", "status=ACTIVE", audits.ResultSuccess, "", audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "用户已解锁"})
}

// ResetPassword 重置密码（生成临时密码）。
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	tempPassword, err := security.GenerateTemporaryPassword(16)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	hash, err := security.HashPassword(tempPassword)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	policy := h.settings.PasswordPolicy(r.Context())
	var expiresAt *time.Time
	if policy.ExpireDays > 0 {
		t := time.Now().Add(time.Duration(policy.ExpireDays) * 24 * time.Hour)
		expiresAt = &t
	}
	// 重置后必须改密
	if err := h.store.UpdatePasswordForceChange(r.Context(), id, hash, expiresAt); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.sessions.RevokeAllForUser(r.Context(), id, "password_reset"); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "reset_password", "user", id.String(), target.Username,
		"", "password_reset=true", audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"temporary_password": tempPassword,
		"notice":             "临时密码仅本次显示，首次登录必须修改",
	})
}

// ResetTOTP 重置用户双因子认证（清空密钥与恢复码，高危操作）。
func (h *Handler) ResetTOTP(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	if !target.TOTPEnabled && target.TOTPPendingSecretEncrypted == nil {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "该用户未开启双因子认证")
		return
	}
	if err := h.store.ClearTOTP(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "totp_reset", "user", id.String(), target.Username,
		"totp_enabled=true", "totp_cleared=true", audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "该用户的双因子认证已重置"})
}

// ForceLogout 强制用户下线。
func (h *Handler) ForceLogout(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	if err := h.sessions.RevokeAllForUser(r.Context(), id, "force_logout_by_admin"); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "force_logout", "user", id.String(), target.Username,
		"", "all_sessions_revoked", audits.ResultSuccess, "", audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "该用户已全部下线"})
}

// Delete 删除用户（逻辑删除）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的用户ID")
		return
	}
	if id == p.UserID {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "不能删除当前登录账号")
		return
	}
	target, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "用户不存在")
		return
	}
	roles, _ := h.store.GetRoles(r.Context(), id)
	if err := h.store.SoftDeleteGuarded(r.Context(), id); errors.Is(err, ErrLastSystemAdmin) {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"不能删除最后一个系统管理员")
		return
	} else if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.sessions.RevokeAllForUser(r.Context(), id, "user_deleted"); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "users", "delete", "user", id.String(), target.Username,
		userSummary(target, rolesStr(roles)), "deleted=true", audits.ResultSuccess, "", audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "用户已删除"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, before, after, result, failReason, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        module,
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

func userItem(u *User, roles []RoleInfo) map[string]interface{} {
	roleList := make([]map[string]string, len(roles))
	for i, r := range roles {
		roleList[i] = map[string]string{"code": r.Code, "name": r.Name}
	}
	return map[string]interface{}{
		"id":                   u.ID,
		"username":             u.Username,
		"display_name":         u.DisplayName,
		"status":               u.Status,
		"must_change_password": u.MustChangePassword,
		"totp_enabled":         u.TOTPEnabled,
		"password_expires_at":  u.PasswordExpiresAt,
		"locked_until":         u.LockedUntil,
		"last_login_at":        u.LastLoginAt,
		"last_login_ip":        u.LastLoginIP,
		"roles":                roleList,
		"created_at":           u.CreatedAt,
		"updated_at":           u.UpdatedAt,
		"version":              u.Version,
	}
}

func userSummary(u *User, roleCode string) string {
	b, _ := json.Marshal(map[string]interface{}{
		"username":     u.Username,
		"display_name": u.DisplayName,
		"status":       u.Status,
		"role_code":    roleCode,
	})
	return string(b)
}

func roleCodesOf(u *User, s *Store, r *http.Request) string {
	roles, _ := s.GetRoles(r.Context(), u.ID)
	if len(roles) > 0 {
		return roles[0].Code
	}
	return ""
}

func rolesStr(roles []RoleInfo) string {
	if len(roles) > 0 {
		return roles[0].Code
	}
	return ""
}

func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	var n int
	if _, err := parseInt(v, &n); err != nil || n <= 0 {
		return def
	}
	return n
}

func parseInt(s string, n *int) (int, error) {
	var v int
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, http.ErrNotSupported
		}
		v = v*10 + int(c-'0')
	}
	*n = v
	return v, nil
}
