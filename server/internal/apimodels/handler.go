package apimodels

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 模型版本 API。
type Handler struct {
	store *Store
}

// NewHandler 创建。
func NewHandler(store *Store) *Handler { return &Handler{store: store} }

// List GET /api/v1/api-model-versions
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	ek := r.URL.Query().Get("endpoint_key")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	list, total, err := h.store.List(r.Context(), ek, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}
	response.Page(w, r, list, total, page, pageSize)
}

// CreateCandidate POST /api/v1/api-model-versions
func (h *Handler) CreateCandidate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		EndpointID  string            `json:"endpoint_id"`
		EndpointKey string            `json:"endpoint_key"`
		Schema      map[string]string `json:"schema"`
	}
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	eid, err := uuid.Parse(req.EndpointID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效 endpoint_id")
		return
	}
	v, err := h.store.CreateCandidate(r.Context(), eid, req.EndpointKey, req.Schema)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "候选模型已创建"})
}

// Confirm POST /api/v1/api-model-versions/{id}/confirm
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效ID")
		return
	}
	v, err := h.store.Confirm(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	if errors.Is(err, ErrNotCandidate) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"version": v, "message": "模型已冻结为正式版本"})
}
