package upstreams

import (
	"context"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PrivatePolicy 描述源站手动连通性测试的私网放行策略（仅服务端来源可信，客户端请求体始终忽略）。
// 回环/链路本地/云元数据/未指定/组播地址仍由 TestConnectivity 无条件硬拦截。
type PrivatePolicy struct {
	AllowPrivate        bool
	AllowedPrivateCIDRs []netip.Prefix
}

// TestHandler 是源站测试处理器。
type TestHandler struct {
	audits       *audits.Service
	allowPrivate bool           // 服务端静态配置（如环境变量），默认 false，绝不信任请求体
	allowedCIDRs []netip.Prefix // 服务端静态私网 CIDR 白名单（如环境变量）
	policyLookup func(ctx context.Context) PrivatePolicy
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

// SetAllowedPrivateCIDRs 服务端显式配置允许测试的私网 CIDR 白名单（不含回环/链路本地/云元数据）。
func (h *TestHandler) SetAllowedPrivateCIDRs(prefixes []netip.Prefix) *TestHandler {
	if len(prefixes) == 0 {
		h.allowedCIDRs = nil
		return h
	}
	h.allowedCIDRs = append([]netip.Prefix(nil), prefixes...)
	return h
}

// SetPolicyLookup 注入动态策略查询（如读取 system_settings 的 network 组配置），每次测试实时生效。
func (h *TestHandler) SetPolicyLookup(fn func(ctx context.Context) PrivatePolicy) *TestHandler {
	h.policyLookup = fn
	return h
}

func (h *TestHandler) resolvePrivatePolicy(ctx context.Context) PrivatePolicy {
	out := PrivatePolicy{
		AllowPrivate: h.allowPrivate,
	}
	if len(h.allowedCIDRs) > 0 {
		out.AllowedPrivateCIDRs = append(out.AllowedPrivateCIDRs, h.allowedCIDRs...)
	}
	if h.policyLookup != nil {
		dyn := h.policyLookup(ctx)
		if dyn.AllowPrivate {
			out.AllowPrivate = true
		}
		if len(dyn.AllowedPrivateCIDRs) > 0 {
			out.AllowedPrivateCIDRs = append(out.AllowedPrivateCIDRs, dyn.AllowedPrivateCIDRs...)
		}
	}
	return out
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
	policy := h.resolvePrivatePolicy(r.Context())
	result := TestConnectivity(r.Context(), TestInput{
		Scheme:              req.Scheme,
		Host:                req.Host,
		Port:                req.Port,
		HealthCheckPath:     req.HealthCheckPath,
		TLSServerName:       req.TLSServerName,
		TLSVerify:           req.TLSVerify,
		AllowPrivate:        policy.AllowPrivate,
		AllowedPrivateCIDRs: policy.AllowedPrivateCIDRs,
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
