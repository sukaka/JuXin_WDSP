package requestpcap

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/security"
	"github.com/jiuzhang-waf/server/internal/users"
)

func (h *Handler) SetRotation(rotate func() error) *Handler {
	h.rotate = rotate
	return h
}

func (h *Handler) RotateKeys(w http.ResponseWriter, r *http.Request) {
	principal := h.principal(w, r)
	if principal == nil {
		return
	}
	if h.rotate == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "PCAP密钥管理未配置")
		return
	}
	var input evidenceActionRequest
	if err := response.DecodeJSON(w, r, &input, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !validReason(strings.TrimSpace(input.Reason)) || input.Password == "" || len(input.Password) > 256 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请填写1至500字符的轮换理由和密码")
		return
	}
	user, err := h.users.GetByID(r.Context(), principal.UserID)
	if err != nil || user.Status != users.StatusActive {
		response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "当前用户不可用")
		return
	}
	if err := security.VerifyPassword(input.Password, user.PasswordHash); err != nil {
		h.record(r, principal, "request_pcap.key_rotate", uuid.Nil, errors.New("password rejected"), "密码校验失败", audits.RiskCritical, input.Reason)
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "密码错误")
		return
	}
	err = h.rotate()
	h.record(r, principal, "request_pcap.key_rotate", uuid.Nil, err, "密钥轮换或公钥发布失败", audits.RiskCritical, input.Reason)
	if err != nil {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "密钥轮换未完成，请检查密钥存储和公钥分发目录")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]bool{"rotated": true})
}
