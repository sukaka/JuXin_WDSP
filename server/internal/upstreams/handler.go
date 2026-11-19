package upstreams

import (
	"net/http"
	"strconv"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// TestHandler 是源站测试处理器。
type TestHandler struct {
	audits       *audits.Service
	allowPrivate bool // 仅由服务端配置决定是否允许测试 RFC1918/ULA 私网源站，默认 false，绝不信任请求体
}

// NewTestHandler 创建源站测试处理器（默认禁止访问私网/回环/元数据地址）。
func NewTestHandler(au *audits.Service) *TestHandler {
	return &TestHandler{audits: au}
}

// SetAllowPrivate 服务端显式配置是否允许测试内网源站（不含回环/链路本地/云元数据）。
func (h *TestHandler) SetAllowPrivate(allow bool) *TestHandler {
	h.allowPrivate = allow
	return h
}

type testRequest struct {
	Scheme          string `json:"scheme"`
	Host            string `json:"host"`
	Port            int    `json:"port"`
	HealthCheckPath string `json:"health_check_path"`
	TLSServerName   string `json:"tls_server_name"`
	TLSVerify       bool   `json:"tls_verify"`
	// AllowPrivate 保留字段仅为兼容前端既有 JSON 载荷（DecodeJSON 启用了 DisallowUnknownFields），
	// 服务端完全忽略客户端传入值，私网策略仅以 h.allowPrivate 为准。
	AllowPrivate bool `json:"allow_private"`
}

// Test 执行源站连通性测试（SSRF防护）。
func (h *TestHandler) Test(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req testRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	result := TestConnectivity(r.Context(), TestInput{
		Scheme:          req.Scheme,
		Host:            req.Host,
		Port:            req.Port,
		HealthCheckPath: req.HealthCheckPath,
		TLSServerName:   req.TLSServerName,
		TLSVerify:       req.TLSVerify,
		AllowPrivate:    h.allowPrivate,
	})

	// 记录测试审计
	risk := audits.RiskLow
	if result.ErrorCode == "SSRF_BLOCKED" {
		risk = audits.RiskMedium
	}
	if h.audits != nil && p != nil {
		audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
			UserID:       &p.UserID,
			Username:     p.Username,
			SourceIP:     middleware.RemoteIP(r),
			ConnectionIP: middleware.ConnectionIP(r),
			UserAgent:    r.UserAgent(),
			Module:       "upstreams",
			Action:       "test",
			ObjectType:   "upstream",
			ObjectID:     "",
			ObjectName:   req.Host,
			AfterSummary: summarizeResult(result),
			Result:       resultToAuditStatus(result),
			RiskLevel:    risk,
			RequestID:    response.RequestIDFrom(r),
		})
	}

	// 返回结果（不含完整响应体）
	response.JSON(w, r, http.StatusOK, result)
}

func summarizeResult(res *TestResult) string {
	status := "ok"
	if res.ErrorCode != "" {
		status = "failed:" + res.ErrorCode
	}
	return `{"host_status":"` + status + `","http_status":` + itoa(res.HTTPStatus) + `}`
}

func resultToAuditStatus(res *TestResult) string {
	if res.ErrorCode != "" {
		return audits.ResultFailure
	}
	return audits.ResultSuccess
}

func itoa(v int) string {
	return strconv.Itoa(v)
}
