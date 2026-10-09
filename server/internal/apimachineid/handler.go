// handler.go 机器身份登记管理端点（NG-ID g1 批次 B1，设计 §1.12 十二端点表）：
//
//	POST   /api/v1/api-security/machine-identities
//	GET    /api/v1/api-security/machine-identities
//	GET    /api/v1/api-security/machine-identities/{id}
//	PUT    /api/v1/api-security/machine-identities/{id}
//	DELETE /api/v1/api-security/machine-identities/{id}
//	POST   /api/v1/api-security/machine-identities/{id}/keys
//	POST   /api/v1/api-security/machine-identities/{id}/keys/{keyId}/rotate
//	POST   /api/v1/api-security/machine-identities/{id}/keys/{keyId}/revoke
//	GET    /api/v1/api-security/machine-identity-bindings
//	POST   /api/v1/api-security/machine-identity-bindings
//	PUT    /api/v1/api-security/machine-identity-bindings/{id}
//	DELETE /api/v1/api-security/machine-identity-bindings/{id}
//
// 权限：read=jwt_trust.read / manage=jwt_trust.manage（可信密钥管理同域，零新增权限点）；
// 写操作 HIGH 审计（登记册与绑定变更影响认证准入面）；身份/键/绑定/水位变更触发既有
// 整站发布链热生效（设计 §1.12：SetPublishFunc 先例——apimcp 同口径）。
package apimachineid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// auditRecorder 操作审计记录接口（*audits.Service 实现；单测注入 spy——apimcp 同形态）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// PublishFunc 触发现有网关配置发布链（口径同 apimcp.PublishFunc；nil = 发布通道暂不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// Handler 机器身份管理面处理器。
type Handler struct {
	repo    Repository
	audits  auditRecorder
	publish PublishFunc
}

// NewHandler 创建（audit 为 nil 时跳过审计不影响主流程）。
func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// SetPublishFunc 注入现有配置发布链（设计 §1.12：身份/键/绑定/水位变更提交后异步触发
// 整站发布热生效；发布失败仅记日志，登记已落库，后续发布可重试带上最新状态——apimcp 同一口径）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// triggerPublish 登记变更提交后触发发布链；发布通道不可用时 Warn 延迟同步。
func (h *Handler) triggerPublish(r *http.Request, p *authz.Principal) {
	if h.publish == nil {
		slog.Warn("machine identity registry changed but publish channel unavailable, gateway sync deferred")
		return
	}
	uid := uuid.Nil
	if p != nil {
		uid = p.UserID
	}
	h.publish(context.Background(), uid, response.RequestIDFrom(r))
}

// ---------- 身份 ----------

// CreateIdentity POST /machine-identities（创建身份；同名 409）。
func (h *Handler) CreateIdentity(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req IdentityInput
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateIdentityInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	m, err := h.repo.CreateIdentity(r.Context(), req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "machine_identity", m.ID.String(), m.IdentityName,
		"", identitySummary(m), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]any{"identity": m})
}

// ListIdentities GET /machine-identities（含键状态摘要与撤销水位）。
func (h *Handler) ListIdentities(w http.ResponseWriter, r *http.Request) {
	list, watermark, err := h.repo.ListIdentities(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items": list, "total": len(list), "revocation_watermark": watermark,
	})
}

// GetIdentity GET /machine-identities/{id}（详情含键行——状态/窗口/revoked_seq 可见，§1.6）。
func (h *Handler) GetIdentity(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	m, keys, err := h.repo.GetIdentity(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"identity": m, "keys": keys})
}

// UpdateIdentity PUT /machine-identities/{id}（改范围/状态/exempt/绑定主体；乐观锁 409）。
func (h *Handler) UpdateIdentity(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req IdentityInput
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateIdentityInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	if req.Version < 1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必须 ≥1（乐观锁与身份 version 比对）")
		return
	}
	m, err := h.repo.UpdateIdentity(r.Context(), id, req)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "machine_identity", m.ID.String(), m.IdentityName,
		"", identitySummary(m), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]any{"identity": m})
}

// DeleteIdentity DELETE /machine-identities/{id}（键 FK 级联；存在绑定先决 409——见 store 注释）。
func (h *Handler) DeleteIdentity(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.repo.DeleteIdentity(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "machine_identity", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------- 公钥 ----------

// parseKeyID 解析 {keyId} 路径参数。
func parseKeyID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	keyID, err := uuid.Parse(r.PathValue("keyId"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 keyId")
		return uuid.Nil, false
	}
	return keyID, true
}

// decodeKeyInput 公钥载荷解码+校验（导入/轮换共用）。
func decodeKeyInput(w http.ResponseWriter, r *http.Request) (KeyInput, bool) {
	var req KeyInput
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return req, false
	}
	if msg := ValidateKeyInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return req, false
	}
	return req, true
}

// ImportKey POST /machine-identities/{id}/keys（公钥静态导入，§1.3 纪律；导入即 HIGH 审计）。
func (h *Handler) ImportKey(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	req, ok := decodeKeyInput(w, r)
	if !ok {
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	k, err := h.repo.ImportKey(r.Context(), id, req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "import_key", "machine_identity_key", k.ID.String(), k.Kid,
		"", keySummary(k, ""), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, k)
}

// RotateKey POST /machine-identities/{id}/keys/{keyId}/rotate（§1.6：原子=新 ACTIVE+
// 旧 RETIRED+重叠窗口缺省 24h 上限 168h）。
func (h *Handler) RotateKey(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	keyID, ok := parseKeyID(w, r)
	if !ok {
		return
	}
	req, ok := decodeKeyInput(w, r)
	if !ok {
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	newKey, oldKey, err := h.repo.RotateKey(r.Context(), id, keyID, req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "rotate_key", "machine_identity_key", keyID.String(), oldKey.Kid,
		"", keySummary(newKey, fmt.Sprintf("old_kid=%q retired_until=%v", oldKey.Kid, oldKey.RetireOverlapUntil)),
		audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]any{"key": newKey, "retired_key": oldKey})
}

// RevokeKey POST /machine-identities/{id}/keys/{keyId}/revoke（§1.6：即时生效；
// 撤销事实与水位 seq+1 同一事务；已 REVOKED 409）。
func (h *Handler) RevokeKey(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	keyID, ok := parseKeyID(w, r)
	if !ok {
		return
	}
	k, err := h.repo.RevokeKey(r.Context(), id, keyID)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "revoke_key", "machine_identity_key", k.ID.String(), k.Kid,
		"", keySummary(k, ""), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, k)
}

// ---------- 绑定 ----------

// ListBindings GET /machine-identity-bindings（application_id 可选过滤）。
func (h *Handler) ListBindings(w http.ResponseWriter, r *http.Request) {
	var applicationID uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
		applicationID = id
	}
	list, err := h.repo.ListBindings(r.Context(), applicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": list, "total": len(list)})
}

// CreateBinding POST /machine-identity-bindings（selector/mode/proof_required；同（应用,path）409）。
func (h *Handler) CreateBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if msg := ValidateBindingInput(req); msg != "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, msg)
		return
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	b, err := h.repo.CreateBinding(r.Context(), req, createdBy)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "machine_identity_binding", b.ID.String(), bindingPathOf(b),
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, b)
}

// UpdateBinding PUT /machine-identity-bindings/{id}（改 mode/proof_required；乐观锁 409）。
func (h *Handler) UpdateBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req BindingInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	switch strings.ToUpper(strings.TrimSpace(req.Mode)) {
	case "", ModeObserve, ModeProtect:
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "mode 非法（OBSERVE|PROTECT）")
		return
	}
	if req.Version < 1 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "version 必须 ≥1（乐观锁与绑定行 version 比对）")
		return
	}
	b, err := h.repo.UpdateBinding(r.Context(), id, req)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "machine_identity_binding", b.ID.String(), bindingPathOf(b),
		"", bindingSummary(b), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, b)
}

// DeleteBinding DELETE /machine-identity-bindings/{id}（解绑；不存在 404）。
func (h *Handler) DeleteBinding(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := h.repo.DeleteBinding(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "machine_identity_binding", id.String(), "", "", "",
		audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---------- 内部 ----------

func parseID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的资源ID")
		return uuid.Nil, false
	}
	return id, true
}

// writeStoreError 存储/校验错误→HTTP 精确映射（400 校验 / 404 不存在 / 409 冲突语义）。
func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ve.Msg)
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "机器身份不存在")
	case errors.Is(err, ErrKeyNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "公钥不存在")
	case errors.Is(err, ErrBindingNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "绑定不存在")
	case errors.Is(err, ErrDuplicateName):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同名身份已存在")
	case errors.Is(err, ErrIdentityInUse):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrIdentityInUse.Error())
	case errors.Is(err, ErrKeyDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrKeyDuplicate.Error())
	case errors.Is(err, ErrKeyStateConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrKeyStateConflict.Error())
	case errors.Is(err, ErrBindingDuplicate):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "同（应用,path）绑定已存在（恰一条）")
	case errors.Is(err, ErrAppNotFound):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "引用的应用不存在")
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrVersionConflict.Error())
	default:
		response.InternalError(w, r, err)
	}
}

// recordAudit 写操作审计（apimcp 同形态）。
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

// identitySummary 身份审计摘要（JSON 形态——键均非敏感键全值保留可读）。
func identitySummary(m *Identity) string {
	tenant, principal := "", ""
	if m.TenantID != nil {
		tenant = *m.TenantID
	}
	if m.PrincipalBinding != nil {
		principal = *m.PrincipalBinding
	}
	return fmt.Sprintf(`{"identity_name":%q,"tenant_id":%q,"principal_binding":%q,"status":%q,"bot_challenge_exempt":%t,"version":%d}`,
		m.IdentityName, tenant, principal, m.Status, m.BotChallengeExempt, m.Version)
}

// keySummary 公钥审计摘要（指纹引用——不落完整公钥（§1.3）；extra 追加轮换上下文）。
func keySummary(k *Key, extra string) string {
	var revokedSeq int64
	if k.RevokedSeq != nil {
		revokedSeq = *k.RevokedSeq
	}
	base := fmt.Sprintf(`{"kid":%q,"alg":%q,"key_fingerprint":%q,"status":%q,"revoked_seq":%d`,
		k.Kid, k.Alg, k.KeyFingerprint, k.Status, revokedSeq)
	if extra != "" {
		base += fmt.Sprintf(`,"note":%q`, extra)
	}
	return base + "}"
}

func bindingPathOf(b *Binding) string {
	if b.PathExact != "" {
		return b.PathExact
	}
	return b.PathPrefix
}

// bindingSummary 绑定审计摘要（JSON 形态）。
func bindingSummary(b *Binding) string {
	return fmt.Sprintf(`{"application_id":%q,"path_exact":%q,"path_prefix":%q,"mode":%q,"proof_required":%t,"version":%d}`,
		b.ApplicationID.String(), b.PathExact, b.PathPrefix, b.Mode, b.ProofRequired, b.Version)
}
