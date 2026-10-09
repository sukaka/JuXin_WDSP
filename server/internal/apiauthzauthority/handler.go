// handler.go 权威关系接入管理 API（NG-AZ-01；docs/nextgen/NG-AZ-01-authority-ingest.md §6）：
//
//	GET    /api/v1/api-security/authz/authorities           来源列表（api_authorization.read）
//	POST   /api/v1/api-security/authz/authorities           来源登记（api_authorization.authority_manage）
//	GET    /api/v1/api-security/authz/authorities/{id}      来源详情含公钥（api_authorization.read）
//	PATCH  /api/v1/api-security/authz/authorities/{id}      启停/范围/钥匙轮换（authority_manage）
//	POST   /api/v1/api-security/authz/authorities/{id}/imports  离线签名批次导入（authority_import）
//	GET    /api/v1/api-security/authz/authorities/{id}/status   水位/缺口/冲突/批次历史（read）
//
// 纪律：写操作 CSRF + 审计；导入成功触发整站发布（关系快照经既有发布链下发——
// 与 apiauthz 手工确认同一生效通道）；拒绝批次同样留痕（REJECTED + 逐条原因）。
package apiauthzauthority

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 权限点（种子见迁移 000172；读沿用 api_authorization.read）。
const (
	PermAuthzRead       = "api_authorization.read"
	PermAuthorityManage = "api_authorization.authority_manage"
	PermAuthorityImport = "api_authorization.authority_import"
)

// ServiceAPI 服务接口（*Service 实现；测试注入 fake）。
type ServiceAPI interface {
	CreateSource(ctx context.Context, name string, scopes SourceScopes, maxAge *int64, keys []SourceKey) (*AuthoritySource, error)
	PatchSource(ctx context.Context, id uuid.UUID, in SourcePatch) (*AuthoritySource, []SourceKey, error)
	Import(ctx context.Context, sourceID uuid.UUID, body []byte, actorID uuid.UUID) (*ImportBatch, error)
	GetSource(ctx context.Context, id uuid.UUID) (*AuthoritySource, error)
	ListSources(ctx context.Context) ([]AuthoritySource, error)
	ListSourceKeys(ctx context.Context, sourceID uuid.UUID) ([]SourceKey, error)
	ListBatches(ctx context.Context, sourceID uuid.UUID, limit int) ([]ImportBatch, error)
	GetWatermark(ctx context.Context, sourceID uuid.UUID) (SourceWatermark, error)
	ListConflicts(ctx context.Context, status string, limit int) ([]ConflictRecord, error)
}

// publishFunc 整站发布触发（与 apiauthz 同一适配形态）。
type publishFunc func(ctx context.Context, uid uuid.UUID, rid string)

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 权威关系接入处理器。
type Handler struct {
	svc     ServiceAPI
	audits  auditRecorder
	publish publishFunc
}

// NewHandler 创建处理器。
func NewHandler(svc ServiceAPI, auditsSvc auditRecorder) *Handler {
	return &Handler{svc: svc, audits: auditsSvc}
}

// SetPublishFunc 注入整站发布触发（nil = 不触发，装配不可用时降级仅落库）。
func (h *Handler) SetPublishFunc(fn publishFunc) { h.publish = fn }

// RegisterRoutes 注册路由（/api/v1/api-security/authz 命名空间）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/authz/authorities",
		authzFn(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/authz/authorities",
		authzFn(middleware.RequirePermission(PermAuthorityManage)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/authz/authorities/{id}",
		authzFn(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PATCH /api/v1/api-security/authz/authorities/{id}",
		authzFn(middleware.RequirePermission(PermAuthorityManage)(http.HandlerFunc(h.Patch))))
	mux.Handle("POST /api/v1/api-security/authz/authorities/{id}/imports",
		authzFn(middleware.RequirePermission(PermAuthorityImport)(http.HandlerFunc(h.Import))))
	mux.Handle("GET /api/v1/api-security/authz/authorities/{id}/status",
		authzFn(middleware.RequirePermission(PermAuthzRead)(http.HandlerFunc(h.Status))))
}

// ---------- 请求/响应 ----------

type createSourceRequest struct {
	Name               string       `json:"name"`
	Scopes             SourceScopes `json:"scopes"`
	MaxEventAgeSeconds *int64       `json:"max_event_age_seconds"`
	Keys               []SourceKey  `json:"keys,omitempty"`
}

type sourceDetail struct {
	*AuthoritySource
	Keys []SourceKey `json:"keys"`
}

// List GET /api/v1/api-security/authz/authorities
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.svc.ListSources(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []AuthoritySource{}
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items})
}

// Create POST /api/v1/api-security/authz/authorities
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	var req createSourceRequest
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	src, err := h.svc.CreateSource(r.Context(), req.Name, req.Scopes, req.MaxEventAgeSeconds, req.Keys)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, "create", "api_authority_source", src.ID.String(),
		"", "登记权威来源 "+src.Name, audits.ResultSuccess)
	response.JSON(w, r, http.StatusOK, src)
}

// Get GET /api/v1/api-security/authz/authorities/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSourceID(w, r)
	if !ok {
		return
	}
	src, err := h.svc.GetSource(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "来源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	keys, err := h.svc.ListSourceKeys(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if keys == nil {
		keys = []SourceKey{}
	}
	response.JSON(w, r, http.StatusOK, sourceDetail{AuthoritySource: src, Keys: keys})
}

// Patch PATCH /api/v1/api-security/authz/authorities/{id}
func (h *Handler) Patch(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSourceID(w, r)
	if !ok {
		return
	}
	var req SourcePatch
	if err := response.DecodeJSON(w, r, &req, 1<<20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	src, keys, err := h.svc.PatchSource(r.Context(), id, req)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "来源不存在")
		case errors.Is(err, ErrVersionConflict):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "来源已被其他人修改，请刷新后重试")
		default:
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		}
		return
	}
	h.recordAudit(r, "update", "api_authority_source", id.String(), "", "变更权威来源配置", audits.ResultSuccess)
	response.JSON(w, r, http.StatusOK, sourceDetail{AuthoritySource: src, Keys: keys})
}

// Import POST /api/v1/api-security/authz/authorities/{id}/imports
// 离线签名批次导入（原始 JSON 体直传 service——五步校验链含严格未知字段拒收）。
// 响应：批次记录（APPLIED 带 counts / REJECTED 带逐条原因——HTTP 均 200，
// 业务结果看 status；输入完全不可解析也留痕 REJECTED）。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSourceID(w, r)
	if !ok {
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBatchBodyBytes+1))
	if err != nil || int64(len(body)) > maxBatchBodyBytes {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "批次体读取失败或超长")
		return
	}
	var actorID uuid.UUID
	if p := authz.PrincipalFrom(r.Context()); p != nil {
		actorID = p.UserID
	}
	batch, err := h.svc.Import(r.Context(), id, body, actorID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if batch.Status == BatchApplied {
		h.recordAudit(r, "import", "api_authority_source", id.String(), "",
			"权威批次导入成功 mode="+batch.Mode, audits.ResultSuccess)
		if h.publish != nil {
			rid := response.RequestIDFrom(r)
			if p := authz.PrincipalFrom(r.Context()); p != nil {
				h.publish(r.Context(), p.UserID, rid)
			}
		}
	} else {
		h.recordAudit(r, "import", "api_authority_source", id.String(), "",
			"权威批次导入被拒: "+truncate(batch.Error, 200), audits.ResultFailure)
	}
	response.JSON(w, r, http.StatusOK, batch)
}

// Status GET /api/v1/api-security/authz/authorities/{id}/status
// 水位/缺口（gap_from 非空即 AUTHZ_SOURCE_GAP）/冲突/最近批次历史。
func (h *Handler) Status(w http.ResponseWriter, r *http.Request) {
	id, ok := parseSourceID(w, r)
	if !ok {
		return
	}
	src, err := h.svc.GetSource(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "来源不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	wm, err := h.svc.GetWatermark(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	gapStatus := "OK"
	if wm.LastSequence == 0 {
		gapStatus = "NO_DATA"
	} else if wm.GapFrom != nil {
		gapStatus = "AUTHZ_SOURCE_GAP"
	}
	conflicts, err := h.svc.ListConflicts(r.Context(), ConflictOpen, 50)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	batches, err := h.svc.ListBatches(r.Context(), id, 20)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if conflicts == nil {
		conflicts = []ConflictRecord{}
	}
	if batches == nil {
		batches = []ImportBatch{}
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"source":     src,
		"watermark":  wm,
		"gap_status": gapStatus,
		"conflicts":  conflicts,
		"batches":    batches,
	})
}

// parseSourceID 路径来源 ID（非法 400）。
func parseSourceID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的来源 id（需 UUID）")
		return uuid.Nil, false
	}
	return id, true
}

// recordAudit 写操作审计（与 apirevokedcreds 同一纪律：审计未注入/无主体跳过）。
func (h *Handler) recordAudit(r *http.Request, action, objType, objID, before, after, result string) {
	if h.audits == nil {
		return
	}
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_authorization",
		Action:        action,
		ObjectType:    objType,
		ObjectID:      objID,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		RiskLevel:     "HIGH", // 权威关系输入直接改变授权事实
		RequestID:     response.RequestIDFrom(r),
	})
}

// truncate 审计摘要截断。
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
