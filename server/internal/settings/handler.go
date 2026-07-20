package settings

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是系统设置处理器。
type Handler struct {
	svc    *Service
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(svc *Service, au *audits.Service) *Handler {
	return &Handler{svc: svc, audits: au}
}

// List 列出系统设置（可按分组过滤）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	list, err := h.svc.List(r.Context(), group)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"items": list})
}

type updateSettingRequest struct {
	Group   string          `json:"setting_group"`
	Key     string          `json:"setting_key"`
	Value   json.RawMessage `json:"setting_value"`
	Version int             `json:"version"`
}

// Update 更新系统设置。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateSettingRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// 白名单校验
	if !AllowedSettingKeys[req.Group+":"+req.Key] {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "不支持的设置项")
		return
	}
	if err := h.svc.Update(r.Context(), req.Group, req.Key, req.Value, req.Version, p.UserID); err != nil {
		if err == ErrNotFound {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "设置项不存在")
			return
		}
		if strings.Contains(err.Error(), "version conflict") {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"设置已被其他人修改，请刷新后重试")
			return
		}
		if strings.Contains(err.Error(), "value must be") {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}

	before, _ := json.Marshal(map[string]interface{}{
		"setting_group": req.Group, "setting_key": req.Key, "version": req.Version,
	})
	after, _ := json.Marshal(map[string]interface{}{
		"setting_group": req.Group, "setting_key": req.Key, "setting_value": req.Value,
	})
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "system_settings",
		Action:        "update",
		ObjectType:    "setting",
		ObjectID:      req.Group + ":" + req.Key,
		ObjectName:    req.Group + "." + req.Key,
		BeforeSummary: string(before),
		AfterSummary:  string(after),
		Result:        audits.ResultSuccess,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	})

	response.JSON(w, r, http.StatusOK, map[string]string{"message": "设置已更新"})
}
