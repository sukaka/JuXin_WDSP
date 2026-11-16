package apiassets

import (
	"context"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

type applicationAssetValueReader interface {
	ApplicationAssetValue(context.Context, uuid.UUID) (*ApplicationAssetValue, error)
}

func (h *Handler) ApplicationAssetValue(w http.ResponseWriter, r *http.Request) {
	applicationID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的应用ID")
		return
	}
	reader, ok := h.store.(applicationAssetValueReader)
	if !ok {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "应用资产评分读取未启用")
		return
	}
	value, err := reader.ApplicationAssetValue(r.Context(), applicationID)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "应用不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, value)
}
