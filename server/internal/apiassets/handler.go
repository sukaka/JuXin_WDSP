package apiassets

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/gateway/dynamic_security/normalizer"
)

// Handler API 端点管理。
type Handler struct {
	store *Store
}

// NewHandler 创建。
func NewHandler(store *Store) *Handler { return &Handler{store: store} }

// List GET /api/v1/api-endpoints
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	status := r.URL.Query().Get("status")
	list, total, err := h.store.List(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, pageOr(page, 1), pageOr(pageSize, 20))
}

// Discover POST /api/v1/api-endpoints/discover  {method, path, confidence?}
func (h *Handler) Discover(w http.ResponseWriter, r *http.Request) {
	_ = authz.PrincipalFrom(r.Context())
	var req struct {
		Method     string  `json:"method"`
		Path       string  `json:"path"`
		Confidence float64 `json:"confidence"`
	}
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	tpl := normalizer.NormalizePath(req.Path)
	if req.Confidence <= 0 {
		req.Confidence = 0.5
	}
	e, err := h.store.UpsertDiscovery(r.Context(), req.Method, tpl, req.Confidence, true)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e})
}

// Confirm POST /api/v1/api-endpoints/{id}/confirm
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效ID")
		return
	}
	e, err := h.store.Confirm(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e, "message": "端点已确认"})
}

// Get GET /api/v1/api-endpoints/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效ID")
		return
	}
	e, err := h.store.GetByID(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "端点不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"endpoint": e})
}

func pageOr(v, d int) int {
	if v <= 0 {
		return d
	}
	return v
}

// NormalizePath exported for tests via handler package tests using normalizer.
func NormalizeDemo(path string) string {
	return normalizer.NormalizePath(strings.TrimSpace(path))
}
