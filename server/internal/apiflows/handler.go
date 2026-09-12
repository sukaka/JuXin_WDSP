// handler.go 流程基线 CRUD（阶段8 §44 发布下发面；权限 api_flow.read/manage）。
package apiflows

import (
	"context"
	"encoding/json"
	"errors"
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

// 请求体上限（单流程含全部步骤）。
const flowBodyMaxBytes = 64 << 10

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 流程基线管理面处理器。
type Handler struct {
	repo    Repository
	audits  auditRecorder
	publish PublishFunc
}

// PublishFunc 触发现有网关配置发布链（口径同 apiauthz.PublishFunc；nil = 发布通道暂不可用）。
type PublishFunc func(ctx context.Context, uid uuid.UUID, requestID string)

// NewHandler 创建处理器（audit 为 nil 时跳过审计，不影响主流程；与 apigrpcdesc 同一纪律）。
func NewHandler(repo Repository, audit *audits.Service) *Handler {
	h := &Handler{repo: repo}
	if audit != nil {
		h.audits = audit
	}
	return h
}

// SetPublishFunc 注入现有配置发布链（基线变更提交后异步触发整站发布热生效；
// 发布失败仅记日志，基线已落库，后续发布可重试带上最新状态——与 apiauthz 同一口径）。
func (h *Handler) SetPublishFunc(fn PublishFunc) { h.publish = fn }

// triggerPublish 基线变更提交后触发发布链；发布通道不可用时 Warn 延迟同步。
func (h *Handler) triggerPublish(r *http.Request, p *authz.Principal) {
	if h.publish == nil {
		slog.Warn("api flow baseline changed but publish channel unavailable, gateway sync deferred")
		return
	}
	uid := uuid.Nil
	if p != nil {
		uid = p.UserID
	}
	h.publish(context.Background(), uid, response.RequestIDFrom(r))
}

// flowUpsertRequest 创建/整体替换请求体。
type flowUpsertRequest struct {
	FlowID            string      `json:"flow_id"`
	Name              string      `json:"name"`
	Description       string      `json:"description"`
	Enabled           *bool       `json:"enabled"`             // 创建缺省 true
	MaxPerWindow      int         `json:"max_per_window"`      // 流程级短窗调用上限（0 = 不判定）
	RateWindowSeconds int         `json:"rate_window_seconds"` // 流程级短窗秒数（0 = 缺省 60s）
	Steps             []StepInput `json:"steps"`
	ExpectedVersion   *int        `json:"expected_version"` // 仅 PUT 必填
}

// List GET /api/v1/api-security/flow-baselines（enabled 过滤可选；不含步骤明细）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var enabled *bool
	if raw := strings.TrimSpace(r.URL.Query().Get("enabled")); raw != "" {
		v, err := strconv.ParseBool(raw)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的 enabled 取值（true/false）")
			return
		}
		enabled = &v
	}
	items, err := h.repo.List(r.Context(), enabled)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

// Create POST /api/v1/api-security/flow-baselines（创建即按 enabled 参与发布；写操作审计）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req flowUpsertRequest
	if err := decodeBody(w, r, &req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体非法: "+err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	createdBy := ""
	if p != nil {
		createdBy = p.Username
	}
	f, err := h.repo.Create(r.Context(), FlowInput{
		FlowID: req.FlowID, Name: req.Name, Description: req.Description,
		Enabled: enabled, MaxPerWindow: req.MaxPerWindow, RateWindowSeconds: req.RateWindowSeconds,
		Steps: req.Steps,
	}, createdBy)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_flow_baseline", f.ID.String(), f.FlowID, "",
		"enabled="+strconv.FormatBool(f.Enabled)+" steps="+strconv.Itoa(len(f.Steps)),
		audits.ResultSuccess, audits.RiskMedium)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusCreated, f)
}

// Get GET /api/v1/api-security/flow-baselines/{id}（含步骤明细）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	f, err := h.repo.Get(r.Context(), id)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, f)
}

// Update PUT /api/v1/api-security/flow-baselines/{id}（整体替换；
// expected_version 乐观锁，冲突 409；写操作审计）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req flowUpsertRequest
	if err := decodeBody(w, r, &req); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求体非法: "+err.Error())
		return
	}
	if req.ExpectedVersion == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "expected_version 必填（乐观锁）")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	f, err := h.repo.Update(r.Context(), id, FlowInput{
		FlowID: req.FlowID, Name: req.Name, Description: req.Description,
		Enabled: enabled, MaxPerWindow: req.MaxPerWindow, RateWindowSeconds: req.RateWindowSeconds,
		Steps: req.Steps,
	}, *req.ExpectedVersion)
	if err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_flow_baseline", f.ID.String(), f.FlowID, "",
		"enabled="+strconv.FormatBool(f.Enabled)+" steps="+strconv.Itoa(len(f.Steps))+" version="+strconv.Itoa(f.Version),
		audits.ResultSuccess, audits.RiskMedium)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, f)
}

// Delete DELETE /api/v1/api-security/flow-baselines/{id}（删除即退出下次发布载荷；写操作审计）。
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
	h.recordAudit(r, p, "delete", "api_flow_baseline", id.String(), "", "", "",
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
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "流程基线不存在")
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "版本冲突：基线已被他人修改，请刷新后重试")
	case errors.Is(err, ErrDuplicateFlowID):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "flow_id 已被占用")
	case errors.Is(err, ErrUnknownEndpoint):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "步骤引用的 endpoint_id 不存在")
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
	r.Body = http.MaxBytesReader(w, r.Body, flowBodyMaxBytes)
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
// 审计服务未注入或无操作者上下文时跳过，不影响主流程（与 apigrpcdesc 同一纪律）。
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
