// handler.go 离线授权 HTTP 处理器：
//
//	GET  /api/v1/license/status   授权状态（任何登录用户；锁定状态下前端也要能查，不挂权限点）
//	POST /api/v1/license/import   导入 .lic（license.manage；multipart 文件或 JSON body {file_content}，
//	                              限 64KB；解析失败 400、验签失败 422、指纹不匹配/重复导入 409）
//	GET  /api/v1/license/history  导入历史分页（license.read）
//
// 写操作记操作审计（module "license"，RiskHigh；detail 只落
// license_id/product/customer/expires_at，绝不落签名与原文）。
package license

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 权限点（迁移 000078 种子：SYSTEM_ADMIN 全量、AUDIT_ADMIN 只读、SECURITY_ADMIN 不授权）。
const (
	PermRead   = "license.read"
	PermManage = "license.manage"
)

// codeLicenseInvalid 授权业务错误码（验签失败/指纹不匹配等授权自身无效分支）。
// 常量在 gate.go 统一定义并导出（门控/配额拒绝共用同一词表），此处保留包内短名。
const codeLicenseInvalid = CodeLicenseInvalid

// maxLicenseFileBytes .lic 上传体积上限（64KB；离线授权文件为小型 JSON）。
const maxLicenseFileBytes = 64 << 10

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// UsageProvider 配额用量提供者（装配层接 applications/apiassets 计数；
// nil 时 status/import 响应省略 usage 字段，保持原响应形态）。
type UsageProvider func(ctx context.Context) (applications int64, apiEndpoints int64, err error)

// Handler 离线授权处理器。
type Handler struct {
	svc    *Service
	audits auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	usage  UsageProvider // nil 时响应省略 usage 字段
}

// NewHandler 创建处理器。
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *Handler) SetAudits(a auditRecorder) *Handler { h.audits = a; return h }

// SetUsageProvider 注入配额用量提供者（生产由 app 装配 applications/apiassets 计数）。
func (h *Handler) SetUsageProvider(fn UsageProvider) *Handler { h.usage = fn; return h }

// RegisterRoutes 注册路由（统一 /api/v1/license 前缀）。
// status 不挂权限点：登录即可（授权锁定状态下前端仍需查询状态）；
// import/history 分别挂 license.manage / license.read。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/license/status",
		authzFn(http.HandlerFunc(h.Status)))
	mux.Handle("POST /api/v1/license/import",
		authzFn(middleware.RequirePermission(PermManage)(http.HandlerFunc(h.Import))))
	mux.Handle("GET /api/v1/license/history",
		authzFn(middleware.RequirePermission(PermRead)(http.HandlerFunc(h.History))))
}

// usageView 配额用量（status/import 响应 data.usage）。
type usageView struct {
	Applications int64 `json:"applications"`
	APIEndpoints int64 `json:"api_endpoints"`
}

// statusResponse 授权状态响应载荷（State 内嵌展开 + 可选 usage；向后兼容只增不删）。
type statusResponse struct {
	State
	Usage *usageView `json:"usage,omitempty"`
}

// snapshot 当前授权状态响应载荷：内存状态快照 + 可选配额用量。
// 用量读取失败仅记日志并省略 usage（用量为展示性数据，不阻断状态查询）。
func (h *Handler) snapshot(r *http.Request) statusResponse {
	out := statusResponse{State: h.svc.State()}
	if h.usage != nil {
		apps, eps, err := h.usage(r.Context())
		if err != nil {
			slog.Warn("license: 读取配额用量失败", "error", err)
		} else {
			out.Usage = &usageView{Applications: apps, APIEndpoints: eps}
		}
	}
	return out
}

// Status GET /api/v1/license/status：当前授权内存状态快照（含本机指纹与配额用量）。
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, r, http.StatusOK, h.snapshot(r))
}

// importRequest JSON body 导入入参（file_content 为 .lic 文件原文）。
type importRequest struct {
	FileContent string `json:"file_content"`
}

// Import POST /api/v1/license/import：multipart 文件（字段名 file）或
// JSON body {file_content} 两种方式上传 .lic；成功响应返回最新 status。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	fileBytes, ok := readUpload(w, r)
	if !ok {
		return
	}
	var operatorID *uuid.UUID
	if p != nil {
		id := p.UserID
		operatorID = &id
	}
	payload, err := h.svc.Import(r.Context(), fileBytes, operatorID)
	if err != nil {
		status, code, msg := mapImportError(err)
		h.recordAudit(r, p, payload, audits.ResultFailure, msg)
		response.Error(w, r, status, code, msg)
		return
	}
	h.recordAudit(r, p, payload, audits.ResultSuccess, "")
	// 响应返回导入后的最新授权状态（与 GET /status 同结构，含配额用量）
	response.JSON(w, r, http.StatusOK, h.snapshot(r))
}

// History GET /api/v1/license/history：导入历史分页（不含 payload/signature/raw_file）。
func (h *Handler) History(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	items, total, err := h.svc.History(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// readUpload 读取上传内容（multipart 优先，否则按 JSON body 解析；全程 64KB 上限）。
func readUpload(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		r.Body = http.MaxBytesReader(w, r.Body, maxLicenseFileBytes)
		if err := r.ParseMultipartForm(maxLicenseFileBytes); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"请求格式错误或文件超过 64KB 限制")
			return nil, false
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"缺少授权文件（multipart 字段名 file）")
			return nil, false
		}
		defer func() { _ = f.Close() }()
		data, err := io.ReadAll(io.LimitReader(f, maxLicenseFileBytes+1))
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取授权文件失败")
			return nil, false
		}
		if len(data) > maxLicenseFileBytes {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"授权文件超过 64KB 限制")
			return nil, false
		}
		if len(data) == 0 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "授权文件内容为空")
			return nil, false
		}
		return data, true
	}
	var req importRequest
	if err := response.DecodeJSON(w, r, &req, maxLicenseFileBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"请求格式错误（JSON body 须为 {file_content}）")
		return nil, false
	}
	if strings.TrimSpace(req.FileContent) == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "授权文件内容为空")
		return nil, false
	}
	return []byte(req.FileContent), true
}

// mapImportError 导入错误 → HTTP 状态码/业务码/中文信息（不泄露签名与原文内部细节）。
func mapImportError(err error) (status int, code, msg string) {
	switch {
	case errors.Is(err, ErrProductBound):
		return http.StatusConflict, CodeLicenseProductBound, err.Error()
	case errors.Is(err, ErrDuplicate):
		return http.StatusConflict, response.CodeResourceConflict, err.Error()
	case errors.Is(err, ErrFingerprintMismatch):
		return http.StatusConflict, codeLicenseInvalid, err.Error()
	case errors.Is(err, ErrSignature):
		return http.StatusUnprocessableEntity, codeLicenseInvalid, ErrSignature.Error()
	case errors.Is(err, ErrMalformed):
		return http.StatusBadRequest, response.CodeInvalidArgument, err.Error()
	default:
		return http.StatusInternalServerError, response.CodeInternalError, "服务器内部错误，请稍后重试"
	}
}

// recordAudit 记录导入审计（module license，RiskHigh；审计未接线时安全跳过——
// 仅测试场景；写入失败走兜底日志/计数，与 apinodes.recordAudit 同一纪律）。
// detail 只落 license_id/product/customer/expires_at，绝不落签名与原文。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, payload *Payload, result, failureReason string) {
	if h.audits == nil || p == nil {
		return
	}
	objectID, after := "", ""
	if payload != nil {
		objectID = payload.LicenseID
		after = importSummary(payload)
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "license",
		Action:        "import",
		ObjectType:    "license",
		ObjectID:      objectID,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failureReason,
		RiskLevel:     audits.RiskHigh,
		RequestID:     response.RequestIDFrom(r),
	})
}

// importSummary 审计 after 摘要（仅四要素；无敏感键，MaskSensitiveJSON 如实留存）。
func importSummary(p *Payload) string {
	var expires interface{}
	if p.ExpiresAt != nil {
		expires = p.ExpiresAt.Format("2006-01-02")
	}
	raw, _ := json.Marshal(map[string]interface{}{
		"license_id": p.LicenseID,
		"product":    p.Product,
		"customer":   p.Customer,
		"expires_at": expires,
	})
	return string(raw)
}

// queryInt 解析正整数查询参数（非法/缺省回退默认值；与 systemalerts 同口径）。
func queryInt(r *http.Request, key string, def int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
