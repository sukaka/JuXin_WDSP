package users

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/loginlogs"
	"github.com/jiuzhang-waf/server/internal/response"
)

// ProfileHandler 是个人中心处理器。
type ProfileHandler struct {
	store *Store
	logs  *loginlogs.Service
}

// NewProfileHandler 创建个人中心处理器。
func NewProfileHandler(store *Store, logs *loginlogs.Service) *ProfileHandler {
	return &ProfileHandler{store: store, logs: logs}
}

// Get 返回个人资料。
func (h *ProfileHandler) Get(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	user, err := h.store.GetByID(r.Context(), p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	roles, _ := h.store.GetRoles(r.Context(), p.UserID)
	perms, _ := h.store.GetPermissions(r.Context(), p.UserID)
	item := userItem(user, roles)
	item["permissions"] = perms
	response.JSON(w, r, http.StatusOK, item)
}

type updateProfileRequest struct {
	DisplayName string `json:"display_name"`
	Version     int    `json:"version"`
}

// Update 修改个人资料（仅显示名称）。
func (h *ProfileHandler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateProfileRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.DisplayName == "" || len(req.DisplayName) > 128 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "显示名称不能为空且不超过128字符")
		return
	}
	user, err := h.store.GetByID(r.Context(), p.UserID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if req.Version != user.Version {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			"资料已被其他操作修改，请刷新后重试")
		return
	}
	user.DisplayName = req.DisplayName
	if err := h.store.Update(r.Context(), user); err != nil {
		response.InternalError(w, r, err)
		return
	}
	roles, _ := h.store.GetRoles(r.Context(), p.UserID)
	response.JSON(w, r, http.StatusOK, userItem(user, roles))
}

// LoginLogs 返回自己的登录记录。
func (h *ProfileHandler) LoginLogs(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	f := loginlogs.ListFilter{
		UserID:   &p.UserID,
		Page:     queryInt(r, "page", 1),
		PageSize: queryInt(r, "page_size", 20),
	}
	list, total, err := h.logs.List(r.Context(), f)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}
