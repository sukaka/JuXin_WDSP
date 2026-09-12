// memories_handler.go AI 记忆管理：查看/新增/修改/禁用/删除，严格属主隔离。
// 敏感内容（密码/密钥/私钥特征）一律拦截；AI 推测类记忆须用户确认后方可进入长期记忆。
package aihandlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/aimemory"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 记忆作用域与置信度白名单。
var memoryScopes = map[string]bool{
	aimemory.ScopeSession: true, aimemory.ScopeProject: true, aimemory.ScopeLongTerm: true,
}
var memoryConfidences = map[string]bool{
	aimemory.ConfidenceUserConfirmed: true, aimemory.ConfidenceSystemConfirmed: true, aimemory.ConfidenceAIInferred: true,
}

// MemoryList 本人记忆列表（scope 可选过滤，include_disabled 可选含禁用）。
func (d *Deps) MemoryList(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	scope := r.URL.Query().Get("scope")
	if scope != "" && !memoryScopes[scope] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的记忆作用域")
		return
	}
	list, err := d.Memories.List(r.Context(), p.UserID, scope, queryBool(r, "include_disabled"))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

// MemoryCreate 新增记忆（默认用户确认置信度；敏感内容拦截）。
func (d *Deps) MemoryCreate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req struct {
		MemoryScope    string `json:"memory_scope"`
		ScopeReference string `json:"scope_reference"`
		Content        string `json:"content"`
		ConfidenceType string `json:"confidence_type"`
	}
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !memoryScopes[req.MemoryScope] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的记忆作用域（SESSION/PROJECT/LONG_TERM）")
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" || len(req.Content) > 4000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "记忆内容必填且不超过 4000 字符")
		return
	}
	// 敏感内容拦截（任何作用域均不允许写入凭据类内容）
	if aimemory.ContainsSensitive(req.Content) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "记忆内容包含敏感信息（密码/密钥/私钥特征），禁止保存")
		return
	}
	confidence := req.ConfidenceType
	if confidence == "" {
		confidence = aimemory.ConfidenceUserConfirmed
	}
	if !memoryConfidences[confidence] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的置信度类型")
		return
	}
	m := &aimemory.Memory{
		UserID:         p.UserID,
		MemoryScope:    req.MemoryScope,
		ScopeReference: trunc(strings.TrimSpace(req.ScopeReference), 100),
		Content:        req.Content,
		ConfidenceType: confidence,
		SourceType:     "MANUAL",
	}
	if err := d.Memories.Create(r.Context(), m); err != nil {
		if errors.Is(err, aimemory.ErrSensitiveContent) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "敏感内容或 AI 推测未确认，禁止写入长期记忆")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"memory": m})
}

// MemoryUpdate 修改记忆内容（属主校验 + 敏感内容拦截）。
func (d *Deps) MemoryUpdate(w http.ResponseWriter, r *http.Request) {
	id, ok := d.loadOwnedMemory(w, r)
	if !ok {
		return
	}
	var req struct {
		Content string `json:"content"`
	}
	if err := decodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	req.Content = strings.TrimSpace(req.Content)
	if req.Content == "" || len(req.Content) > 4000 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "记忆内容必填且不超过 4000 字符")
		return
	}
	if aimemory.ContainsSensitive(req.Content) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "记忆内容包含敏感信息（密码/密钥/私钥特征），禁止保存")
		return
	}
	if err := d.Memories.Update(r.Context(), id, req.Content); err != nil {
		d.memoryError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "记忆已更新"})
}

// MemoryDelete 删除记忆（属主校验）。
func (d *Deps) MemoryDelete(w http.ResponseWriter, r *http.Request) {
	id, ok := d.loadOwnedMemory(w, r)
	if !ok {
		return
	}
	if err := d.Memories.Delete(r.Context(), id); err != nil {
		d.memoryError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "记忆已删除"})
}

// MemoryDisable 禁用记忆（属主校验；禁用后不再进入上下文）。
func (d *Deps) MemoryDisable(w http.ResponseWriter, r *http.Request) {
	id, ok := d.loadOwnedMemory(w, r)
	if !ok {
		return
	}
	if err := d.Memories.SetStatus(r.Context(), id, "DISABLED"); err != nil {
		d.memoryError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "记忆已禁用"})
}

// loadOwnedMemory 加载记忆并强制属主隔离（非属主一律 404）。
func (d *Deps) loadOwnedMemory(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的记忆ID")
		return uuid.Nil, false
	}
	owner, err := d.Memories.GetOwner(r.Context(), id)
	if err != nil {
		if errors.Is(err, aimemory.ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "记忆不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return uuid.Nil, false
	}
	p := authz.PrincipalFrom(r.Context())
	if p == nil || owner != p.UserID {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "记忆不存在")
		return uuid.Nil, false
	}
	return id, true
}

// memoryError 记忆错误映射。
func (d *Deps) memoryError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, aimemory.ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "记忆不存在")
	case errors.Is(err, aimemory.ErrSensitiveContent):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "记忆内容包含敏感信息，禁止保存")
	default:
		response.InternalError(w, r, err)
	}
}
