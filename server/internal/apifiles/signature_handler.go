// signature_handler.go 文件签名（P2-02 验证面）HTTP 处理器：
//
//	POST /api/v1/api-security/file-signature/verify       复算校验签名 token（结论在响应体 valid）
//	GET  /api/v1/api-security/file-signature/key          返回当前 kid（不返回密钥材料）
//	POST /api/v1/api-security/file-signature/key/rotate   轮换密钥（生成新密钥加密落库 + kid 递增）
//
// 权限点 api_data.read（verify/key 查询）/ api_data.manage（rotate）；
// 验证与轮换均记操作审计（摘要不含密钥材料、token 与文件内容）。
package apifiles

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/apidata"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 验证请求体上限（filename/token 均为短串）。
const verifyBodyMaxBytes = 16 << 10

// 验证输入字段长度上限（filename 与身份指纹列宽对齐；token 见 signature.go）。
const (
	verifyFilenameMaxLen = 256
	verifyIdentityMaxLen = 128
)

// SignatureHandler 文件签名验证/密钥管理处理器。
type SignatureHandler struct {
	kv     SignatureSettingsKV
	enc    SignatureEncryptor
	audits *audits.Service
	// now 时钟注入（单测固定时间；缺省 time.Now）。
	now func() time.Time
}

// NewSignatureHandler 创建处理器（构造注入设置/加密/审计服务，语义同 apiscan 装配）。
func NewSignatureHandler(kv SignatureSettingsKV, enc SignatureEncryptor, audit *audits.Service) *SignatureHandler {
	return &SignatureHandler{kv: kv, enc: enc, audits: audit, now: time.Now}
}

// RegisterSignatureRoutes 注册路由（统一 /api/v1/api-security 前缀）。
func RegisterSignatureRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *SignatureHandler) {
	mux.Handle("POST /api/v1/api-security/file-signature/verify",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.Verify))))
	mux.Handle("GET /api/v1/api-security/file-signature/key",
		authz(middleware.RequirePermission(apidata.PermDataRead)(http.HandlerFunc(h.GetKey))))
	mux.Handle("POST /api/v1/api-security/file-signature/key/rotate",
		authz(middleware.RequirePermission(apidata.PermDataManage)(http.HandlerFunc(h.RotateKey))))
}

// verifySignatureRequest 验证请求。identity_fp 可选：缺省空串（匿名/未绑定口径）。
type verifySignatureRequest struct {
	Filename         string `json:"filename"`
	ContentSHA256Hex string `json:"content_sha256_hex"`
	Token            string `json:"token"`
	IdentityFP       string `json:"identity_fp"`
}

// Verify POST /api/v1/api-security/file-signature/verify
// 输入 {filename, content_sha256_hex, token, identity_fp?}；
// 输出 {valid, kid, signed_at, identity_fp_prefix?, reason}。
// 密钥未配置 503 如实说明；token 结论（含伪造/过期）一律 200 + valid 字段表达。
func (h *SignatureHandler) Verify(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req verifySignatureRequest
	if err := response.DecodeJSON(w, r, &req, verifyBodyMaxBytes); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	// filename 原样参与复算（不做 trim——签名绑定的是嵌入方观察到的精确字节），
	// 仅判空与长度；content_sha256_hex 归一小写（hex 输入大小写不敏感）。
	if strings.TrimSpace(req.Filename) == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "filename 不能为空")
		return
	}
	if len(req.Filename) > verifyFilenameMaxLen {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "filename 长度不能超过 256")
		return
	}
	shaHex := strings.ToLower(strings.TrimSpace(req.ContentSHA256Hex))
	if len(shaHex) != signatureHashHexLen || !isHex(shaHex) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "content_sha256_hex 须为 64 位 hex")
		return
	}
	token := strings.TrimSpace(req.Token)
	if token == "" || len(token) > signatureTokenMaxLen {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "token 不能为空且长度不能超过 512")
		return
	}
	if len(req.IdentityFP) > verifyIdentityMaxLen {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "identity_fp 长度不能超过 128")
		return
	}
	key, kid, err := LoadFileSignatureKey(r.Context(), h.kv, h.enc)
	if err != nil {
		if errors.Is(err, ErrSignatureKeyNotConfigured) {
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
				"文件签名密钥未配置（请先经 file-signature/key/rotate 生成）")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	maxAgeDays := DefaultSignatureMaxAgeDays
	if h.kv != nil {
		maxAgeDays = h.kv.GetInt(r.Context(), SettingsGroup, SettingsKeySignatureMaxAgeDays, DefaultSignatureMaxAgeDays)
	}
	res := VerifyFileToken(key, kid, req.Filename, shaHex, token, req.IdentityFP, maxAgeDays, h.now().UTC())
	// 验证操作记操作审计（摘要仅元数据：文件名/内容哈希/kid/结论；不含 token 与文件内容）
	after, _ := json.Marshal(map[string]any{
		"filename":           req.Filename,
		"content_sha256_hex": shaHex,
		"kid":                res.Kid,
		"valid":              res.Valid,
		"reason":             res.Reason,
	})
	result, risk := audits.ResultSuccess, audits.RiskLow
	if !res.Valid {
		// 验证不过的 token 可能是伪造/重放信号，风险档抬一级如实呈现
		result, risk = audits.ResultFailure, audits.RiskMedium
	}
	h.recordAudit(r, p, "verify", "api_file_signature", res.Kid, req.Filename,
		"", string(after), result, risk)
	response.JSON(w, r, http.StatusOK, res)
}

// GetKey GET /api/v1/api-security/file-signature/key
// 返回当前 kid（不返回密钥材料——密钥永不离开设置表密文形态）。
func (h *SignatureHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	kid := ""
	if h.kv != nil {
		kid = strings.TrimSpace(h.kv.GetString(r.Context(), signatureSettingsGroup, signatureKidSetting, ""))
	}
	if kid == "" {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound,
			"文件签名密钥尚未生成（POST file-signature/key/rotate 生成）")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]string{"kid": kid})
}

// RotateKey POST /api/v1/api-security/file-signature/key/rotate
// 生成新密钥加密落库 + kid 递增；旧 kid 的 token 自轮换起失效（v1 仅保留当前密钥）。
func (h *SignatureHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	operatorID := uuid.Nil
	if p != nil {
		operatorID = p.UserID
	}
	kid, err := RotateFileSignatureKey(r.Context(), h.kv, h.enc, operatorID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// 审计摘要只含 kid（密钥材料不进审计，与凭据纪律同则）
	after, _ := json.Marshal(map[string]string{"kid": kid})
	h.recordAudit(r, p, "rotate", "api_file_signature_key", kid, "file-signature-key",
		"", string(after), audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"kid": kid})
}

// recordAudit 写操作审计（含操作者、动作、对象、前后摘要、风险等级）。
// 审计服务未注入（旧接线/单测）或无操作者上下文时跳过，不影响主流程。
func (h *SignatureHandler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_files",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		ObjectName:    objName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	})
}

// isHex 判定字符串是否全为 hex 字符（输入已归一小写）。
func isHex(s string) bool {
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return len(s) > 0
}
