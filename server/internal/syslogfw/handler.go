package syslogfw

import (
	"net/http"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是 syslog 外发相关接口处理器。
type Handler struct {
	fw     *Forwarder
	audits *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(fw *Forwarder, au *audits.Service) *Handler {
	return &Handler{fw: fw, audits: au}
}

// Test 立即用当前 settings 向 syslog 服务器发送一条测试消息，
// 返回成功/失败原因（未启用、地址为空、网络错误等）。
func (h *Handler) Test(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	err := h.fw.SendTestMessage(r.Context())

	result := audits.ResultSuccess
	detail := "syslog 测试消息发送成功"
	if err != nil {
		result = audits.ResultFailure
		detail = "syslog 测试消息发送失败: " + err.Error()
	}
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "system_settings",
		Action:       "syslog_test",
		ObjectType:   "setting",
		ObjectID:     "logging:syslog",
		ObjectName:   "syslog 外发",
		AfterSummary: detail,
		Result:       result,
		RiskLevel:    audits.RiskLow,
		RequestID:    response.RequestIDFrom(r),
	})

	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "测试消息已发送"})
}
