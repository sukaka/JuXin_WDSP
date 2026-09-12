// Package response 提供统一 API 响应格式。
package response

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// 业务错误码
const (
	CodeSuccess                = "SUCCESS"
	CodeInvalidArgument        = "INVALID_ARGUMENT"
	CodeUnauthenticated        = "UNAUTHENTICATED"
	CodePermissionDenied       = "PERMISSION_DENIED"
	CodeAccountLocked          = "ACCOUNT_LOCKED"
	CodeAccountDisabled        = "ACCOUNT_DISABLED"
	CodePasswordExpired        = "PASSWORD_EXPIRED"
	CodePasswordChangeRequired = "PASSWORD_CHANGE_REQUIRED"
	CodeCaptchaRequired        = "CAPTCHA_REQUIRED"
	CodeCaptchaInvalid         = "CAPTCHA_INVALID"
	CodeResourceNotFound       = "RESOURCE_NOT_FOUND"
	CodeResourceConflict       = "RESOURCE_CONFLICT"
	CodeRateLimited            = "RATE_LIMITED"
	CodeCSRFInvalid            = "CSRF_INVALID"
	CodeInternalError          = "INTERNAL_ERROR"
	CodeServiceUnavailable     = "SERVICE_UNAVAILABLE"
	// TOTP_REQUIRED 是登录成功响应的业务分支码（HTTP 200，密码已通过、待第二步验证），非错误。
	CodeTOTPRequired = "TOTP_REQUIRED"
	CodeTOTPInvalid  = "TOTP_INVALID"
)

// Body 是统一响应结构。
type Body struct {
	Code      string      `json:"code"`
	Message   string      `json:"message"`
	Data      interface{} `json:"data,omitempty"`
	Details   interface{} `json:"details,omitempty"`
	RequestID string      `json:"request_id"`
}

// PageData 是分页响应数据。
type PageData struct {
	Items    interface{} `json:"items"`
	Page     int         `json:"page"`
	PageSize int         `json:"page_size"`
	Total    int64       `json:"total"`
}

// RequestIDKey 是请求上下文中 Request ID 的键。
type ctxKey string

const RequestIDKey ctxKey = "jiuzhang_request_id"

// RequestIDFrom 从请求上下文取 Request ID。
func RequestIDFrom(r *http.Request) string {
	if v, ok := r.Context().Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}

// JSON 输出成功响应。
func JSON(w http.ResponseWriter, r *http.Request, status int, data interface{}) {
	write(w, r, status, Body{
		Code:      CodeSuccess,
		Message:   "操作成功",
		Data:      data,
		RequestID: RequestIDFrom(r),
	})
}

// JSONWithCode 输出带自定义业务码的分支响应（HTTP 200 但 code 非 SUCCESS，
// 如登录时账号已开启双因子认证返回 TOTP_REQUIRED，客户端按 code 切换流程）。
func JSONWithCode(w http.ResponseWriter, r *http.Request, status int, code, message string, data interface{}) {
	write(w, r, status, Body{
		Code:      code,
		Message:   message,
		Data:      data,
		RequestID: RequestIDFrom(r),
	})
}

// Page 输出分页响应。
func Page(w http.ResponseWriter, r *http.Request, items interface{}, total int64, page, pageSize int) {
	JSON(w, r, http.StatusOK, PageData{
		Items:    items,
		Page:     page,
		PageSize: pageSize,
		Total:    total,
	})
}

// Error 输出错误响应。生产环境不返回内部错误细节。
func Error(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	write(w, r, status, Body{
		Code:      code,
		Message:   message,
		RequestID: RequestIDFrom(r),
	})
}

// ErrorWithDetails 输出带校验细节的错误响应（仅参数校验类使用）。
func ErrorWithDetails(w http.ResponseWriter, r *http.Request, status int, code, message string, details interface{}) {
	write(w, r, status, Body{
		Code:      code,
		Message:   message,
		Details:   details,
		RequestID: RequestIDFrom(r),
	})
}

// InternalError 输出内部错误（不泄露堆栈/SQL/路径）。
func InternalError(w http.ResponseWriter, r *http.Request, err error) {
	slog.Error("internal error",
		"request_id", RequestIDFrom(r),
		"method", r.Method,
		"path", r.URL.Path,
		"error", err,
	)
	Error(w, r, http.StatusInternalServerError, CodeInternalError, "服务器内部错误，请稍后重试")
}

func write(w http.ResponseWriter, r *http.Request, status int, body Body) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(body)
}

// DecodeJSON 解析请求 JSON，限制体积防止大包攻击。
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	// 拒绝多余 JSON 内容
	if dec.More() {
		return &json.SyntaxError{Offset: 0}
	}
	return nil
}
