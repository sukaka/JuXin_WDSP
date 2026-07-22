package apiruntime

import (
	"net/http"
	"strconv"

	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 运行时事件。
type Handler struct {
	store *Store
}

// NewHandler 创建。
func NewHandler(store *Store) *Handler { return &Handler{store: store} }

// List GET /api/v1/api-runtime-events
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	list, total, err := h.store.List(r.Context(), page, pageSize)
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
