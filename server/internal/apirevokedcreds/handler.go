// handler.go 已吊销凭据 CRUD（阶段8 §35「已吊销凭据使用」数据源；
// 权限 api_credential.read/manage，种子见迁移 000156）。指纹级清单，不存凭据明文；
// 吊销人服务端取自登录主体（不接受客户端声明）。
package apirevokedcreds

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 请求体上限（单条吊销登记）。
const credentialBodyMaxBytes = 16 << 10

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 已吊销凭据管理面处理器。
type Handler struct {
	repo    Repository
	audits  auditRecorder
	publish PublishFunc
}

// PublishFunc 触发现有网关配置发布链（口径同 apiauthz.PublishFunc；nil = 发布通道暂不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// NewHandler 创建处理器（audit 为 nil 时跳过审计，不影响主流程；与 apiflows 同一纪律）。
func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// SetPublishFunc 注入现有配置发布链（吊销时效敏感：变更提交后异步触发整站发布热生效；
// 发布失败仅记日志，吊销记录已落库，后续发布可重试带上最新清单——与 apiauthz 同一口径）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// triggerPublish 吊销清单变更提交后触发发布链；发布通道不可用时 Warn 延迟同步。
func (h *Handler) triggerPublish(r *http.Request, p *authz.Principal) {
	if h.publish == nil {
		slog.Warn("revoked credential changed but publish channel unavailable, gateway sync deferred")
		return
	}
	uid := uuid.Nil
	if p != nil {
		uid = p.UserID
	}
	h.publish(context.Background(), uid, response.RequestIDFrom(r))
}

// credentialCreateRequest 登记吊销请求体。
type credentialCreateRequest struct {
	CredentialType string     `json:"credential_type"`
	Fingerprint    string     `json:"fingerprint"`
	Reason         string     `json:"reason"`
	EffectiveFrom  *time.Time `json:"effective_from"`  // 缺省当前时间
	EffectiveUntil *time.Time `json:"effective_until"` // 空 = 永久吊销
}

// credentialUpdateRequest 调整吊销请求体（吊销对象身份不可变更）。
type credentialUpdateRequest struct {
	Reason         string     `json:"reason"`
	EffectiveFrom  *time.Time `json:"effective_from"` // 必填
	EffectiveUntil *time.Time `json:"effective_until"`
}

// List GET /api/v1/api-security/revoked-credentials（credential_type/active 过滤可选）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var filter ListFilter
	if raw := strings.TrimSpace(r.URL.Query().Get("credential_type")); raw != "" {
		t := strings.ToLower(raw)
		if !validCredentialType(t) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 credential_type 取值（auth/key/sess）")
			return
		}
		filter.CredentialType = t
	}
	if raw := strings.TrimSpace(r.URL.Query().Get("active")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 active 取值（true/false）")
			return
		}
		filter.Active = &v
	}
	items, err := h.repo.List(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// Create POST /api/v1/api-security/revoked-credentials（登记即进入下次发布载荷
// （生效窗口内）；写操作审计；吊销人取自登录主体）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req credentialCreateRequest
	if err := decodeBody(w, r, &req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体非法: "+err.Error())
		return
	}
	operator := ""
	if p != nil {
		operator = p.Username
	}
	c, err := h.repo.Create(r.Context(), CreateInput{
		CredentialType: req.CredentialType, Fingerprint: req.Fingerprint, Reason: req.Reason,
		EffectiveFrom: req.EffectiveFrom, EffectiveUntil: req.EffectiveUntil,
	}, operator)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_revoked_credential", c.ID.String(),
		c.CredentialType+":"+c.Fingerprint, "",
		"reason="+c.Reason,
		audits.ResultSuccess, audits.RiskMedium)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusCreated, c)
}

// Get GET /api/v1/api-security/revoked-credentials/{id}。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := h.repo.Get(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, c)
}

// Update PUT /api/v1/api-security/revoked-credentials/{id}（调整原因/生效窗口；
// 吊销对象身份不可变更；写操作审计）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req credentialUpdateRequest
	if err := decodeBody(w, r, &req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体非法: "+err.Error())
		return
	}
	if req.EffectiveFrom == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "effective_from 必填")
		return
	}
	c, err := h.repo.Update(r.Context(), id, UpdateInput{
		Reason: req.Reason, EffectiveFrom: *req.EffectiveFrom, EffectiveUntil: req.EffectiveUntil,
	})
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_revoked_credential", c.ID.String(),
		c.CredentialType+":"+c.Fingerprint, "",
		"reason="+c.Reason,
		audits.ResultSuccess, audits.RiskMedium)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, c)
}

// Delete DELETE /api/v1/api-security/revoked-credentials/{id}
// （移除即退出下次发布载荷，等于解除吊销；写操作审计）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.repo.Delete(r.Context(), id); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_revoked_credential", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskMedium)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// writeStoreError 领域错误 → 状态码映射（校验错误 400 与存储错误 500 显式区分）。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, verr.Error())
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "吊销记录不存在")
	case errors.Is(err, ErrDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同类型同指纹的吊销记录已存在")
	default:
		response.InternalError(w, r, err)
	}
}

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "id 非法")
		return uuid.Nil, false
	}
	return id, true
}

func decodeBody(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, credentialBodyMaxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("请求体含多余内容")
	}
	return nil
}

// recordAudit 写操作审计（构造注入 audits.Service；含操作者、动作、对象、摘要、风险等级）。
// 审计服务未注入或无操作者上下文时跳过，不影响主流程（与 apiflows 同一纪律）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
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
