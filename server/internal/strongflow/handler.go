// handler.go 强流程定义管理端点（NG-FLOW-01 §1.9/D10）：
//
//	GET/POST /api/v1/api-security/strong-flows/definitions
//	GET/PUT  .../definitions/{id}
//	POST     .../definitions/{id}/activate
//	POST     .../definitions/{id}/retire
//
// 权限：read=查询 / manage=写与激活停用（零新增权限点）；写操作 HIGH 审计
// （定义即阻断资格配置——与对象模型 PATCH 同纪律）。
package strongflow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Repository 定义仓储接口（*Store 实现；包内单测注入内存 fake——
// 版本冻结的并发/事务语义由 PG 集成测试覆盖，fake 只承载 HTTP 映射与权限路径）。
type Repository interface {
	Create(ctx context.Context, in DefinitionInput, operatorID uuid.UUID, operatorName string) (*DefinitionDetail, error)
	List(ctx context.Context, applicationID uuid.UUID, status string, page, pageSize int) ([]Definition, int64, error)
	Get(ctx context.Context, id uuid.UUID) (*DefinitionDetail, error)
	Update(ctx context.Context, id uuid.UUID, in DefinitionInput) (*DefinitionDetail, error)
	Activate(ctx context.Context, id uuid.UUID) (*Definition, error)
	Retire(ctx context.Context, id uuid.UUID) error
	ListInstances(ctx context.Context, applicationID uuid.UUID, status string, createdSince *time.Time, page, pageSize int) ([]Instance, int64, error)
	GetInstance(ctx context.Context, id uuid.UUID, withEvidence bool) (*InstanceDetail, error)
	ResolveInstance(ctx context.Context, id uuid.UUID, in ResolveInput, requestID string) (*ResolveResult, error)
}

// Handler 强流程定义处理器。
type Handler struct {
	store  Repository
	audits *audits.Service
	// publishFunc 整站发布触发（NG-FLOW-02 闭环 FLOW-01 偏差 2：activate/retire 改变
	// ACTIVE 集合即改变 api_strong_flows 下发面——挂既有发布链热生效；apiflows
	// SetPublishFunc 同一先例；未注入（旧接线/单测）时跳过，定义已落库可随后续发布生效）
	publishFunc func(ctx context.Context, operatorID uuid.UUID, requestID string)
}

// NewHandler 创建。
func NewHandler(store Repository, audit *audits.Service) *Handler {
	return &Handler{store: store, audits: audit}
}

// SetPublishFunc 注入发布触发（应用装配时）。
func (h *Handler) SetPublishFunc(fn func(ctx context.Context, operatorID uuid.UUID, requestID string)) {
	h.publishFunc = fn
}

// triggerPublish 激活/停用后触发整站发布（异步失败仅记日志——定义已落库，
// 发布可重试；同 apiflows 口径）。
func (h *Handler) triggerPublish(r *http.Request, p *authz.Principal) {
	if h.publishFunc == nil || p == nil {
		return
	}
	h.publishFunc(r.Context(), p.UserID, response.RequestIDFrom(r))
}

// RegisterRoutes 注册路由（/api/v1/api-security/strong-flows 命名空间）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/strong-flows/definitions",
		authzFn(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/api-security/strong-flows/definitions",
		authzFn(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/api-security/strong-flows/definitions/{id}",
		authzFn(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/api-security/strong-flows/definitions/{id}",
		authzFn(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Update))))
	mux.Handle("POST /api/v1/api-security/strong-flows/definitions/{id}/activate",
		authzFn(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Activate))))
	mux.Handle("POST /api/v1/api-security/strong-flows/definitions/{id}/retire",
		authzFn(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.Retire))))
	mux.Handle("GET /api/v1/api-security/strong-flows/instances",
		authzFn(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.ListInstances))))
	mux.Handle("GET /api/v1/api-security/strong-flows/instances/{id}",
		authzFn(middleware.RequirePermission(PermFlowRead)(http.HandlerFunc(h.GetInstance))))
	mux.Handle("POST /api/v1/api-security/strong-flows/instances/{id}/resolve",
		authzFn(middleware.RequirePermission(PermFlowManage)(http.HandlerFunc(h.ResolveInstance))))
}

// List GET /api/v1/api-security/strong-flows/definitions
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	var applicationID uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
		applicationID = id
	}
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	if status != "" && status != StatusDraft && status != StatusActive && status != StatusRetired {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 非法（DRAFT|ACTIVE|RETIRED）")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	list, total, err := h.store.List(r.Context(), applicationID, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Create POST /api/v1/api-security/strong-flows/definitions
// 新建（version=1）或同名新草稿（version=max+1——D1「编辑产新草稿」承载）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req DefinitionInput
	if err := decodeDefinition(w, r, &req); err != nil {
		return
	}
	var operatorID uuid.UUID
	operatorName := ""
	if p != nil {
		operatorID = p.UserID
		operatorName = p.Username
	}
	d, err := h.store.Create(r.Context(), req, operatorID, operatorName)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_strong_flow_definition", d.ID.String(), d.Name,
		"", definitionSummary(&d.Definition, len(d.Steps)), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, d)
}

// Get GET /api/v1/api-security/strong-flows/definitions/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	d, err := h.store.Get(r.Context(), id)
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "强流程定义不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, d)
}

// Update PUT /api/v1/api-security/strong-flows/definitions/{id}
// 仅 DRAFT 原地编辑（激活即冻结——ACTIVE/RETIRED 409）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req DefinitionInput
	if err := decodeDefinition(w, r, &req); err != nil {
		return
	}
	before, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	d, err := h.store.Update(r.Context(), id, req)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_strong_flow_definition", id.String(), d.Name,
		definitionSummary(&before.Definition, len(before.Steps)), definitionSummary(&d.Definition, len(d.Steps)),
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, d)
}

// Activate POST .../definitions/{id}/activate
// 激活即冻结（activate 前全量校验 + 端点归属核对；同事务 RETIRED 同名义旧 ACTIVE）。
func (h *Handler) Activate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	d, err := h.store.Activate(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "activate", "api_strong_flow_definition", id.String(), d.Name,
		"", definitionSummary(d, -1), audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, d)
}

// Retire POST .../definitions/{id}/retire（ACTIVE/DRAFT→RETIRED；RETIRED 单向终态）。
func (h *Handler) Retire(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	before, err := h.store.Get(r.Context(), id)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	if err := h.store.Retire(r.Context(), id); err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "retire", "api_strong_flow_definition", id.String(), before.Name,
		definitionSummary(&before.Definition, len(before.Steps)), "status=RETIRED",
		audits.ResultSuccess, audits.RiskHigh)
	h.triggerPublish(r, p)
	response.JSON(w, r, http.StatusOK, map[string]any{"id": id, "status": StatusRetired})
}

// ListInstances GET /api/v1/api-security/strong-flows/instances
// 实例分页列表（application_id/status/created_since 过滤；read 权限；FLOW-02 最小面）。
func (h *Handler) ListInstances(w http.ResponseWriter, r *http.Request) {
	var applicationID uuid.UUID
	if v := strings.TrimSpace(r.URL.Query().Get("application_id")); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的站点ID")
			return
		}
		applicationID = id
	}
	status := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("status")))
	switch status {
	case "", "ACTIVE", "CONFIRMED", "INDETERMINATE", "CANCELLED", "FAILED":
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 非法（ACTIVE|CONFIRMED|INDETERMINATE|CANCELLED|FAILED）")
		return
	}
	var createdSince *time.Time
	if v := strings.TrimSpace(r.URL.Query().Get("created_since")); v != "" {
		tm, err := time.Parse(time.RFC3339, v)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "created_since 非法（RFC3339）")
			return
		}
		createdSince = &tm
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	if pageSize > 100 {
		pageSize = 100
	}
	items, total, err := h.store.ListInstances(r.Context(), applicationID, status, createdSince, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// GetInstance GET .../instances/{id}（NG-FLOW-03 §1.9）：实例行 + 步骤轨迹全链 +
// 状态语义字段（INDETERMINATE=「未知，不显示安全通过」逐字不美化，§9.4 红线）。
// 证据明细档（fencing_token/reason_code/request_id）仅 evidence_read 带出；
// read 权限只见摘要档四字段（无权限键缺席，不空串占位）。
func (h *Handler) GetInstance(w http.ResponseWriter, r *http.Request) {
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	withEvidence := false
	if p := authz.PrincipalFrom(r.Context()); p != nil {
		withEvidence = p.HasPermission(PermEvidenceRead)
	}
	d, err := h.store.GetInstance(r.Context(), id, withEvidence)
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, d)
}

// ResolveInstance POST .../instances/{id}/resolve（NG-FLOW-03 §1.5/D5 管理恢复）：
// action 三词 + reason 必填 + expected_version 乐观锁（409）+ 终态拒重复（409 幂等
// 不误伤）+ KEEP_UNKNOWN 不推进；manage 权限 + HIGH 审计（after 含 action/reason/
// 前后状态全值回读）。响应为恢复后的实例详情（证据裁剪同详情端点纪律）。
func (h *Handler) ResolveInstance(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, ok := parsePathID(w, r)
	if !ok {
		return
	}
	var req ResolveInput
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if err := ValidateResolveInput(req); err != nil {
		writeStoreError(w, r, err)
		return
	}
	res, err := h.store.ResolveInstance(r.Context(), id, req, response.RequestIDFrom(r))
	if err != nil {
		writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "resolve", "api_strong_flow_instance", id.String(), "",
		fmt.Sprintf(`{"status":%q}`, res.BeforeStatus), resolveSummary(res, strings.TrimSpace(req.Reason)),
		audits.ResultSuccess, audits.RiskHigh)
	withEvidence := false
	if p != nil {
		withEvidence = p.HasPermission(PermEvidenceRead)
	}
	d, err := h.store.GetInstance(r.Context(), id, withEvidence)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, d)
}

// ---------- 内部 ----------

// writeStoreError 存储/校验错误→HTTP 精确映射（400 校验 / 404 不存在 / 409 状态语义）。
func writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, ve.Msg)
	case errors.Is(err, ErrInstanceNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "强流程实例不存在")
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "强流程定义不存在")
	case errors.Is(err, ErrNoSteps):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrNotDraft):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrNotDraft.Error())
	case errors.Is(err, ErrInstanceTerminal):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrInstanceTerminal.Error())
	case errors.Is(err, ErrInvalidTransition):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrInvalidTransition.Error())
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, ErrVersionConflict.Error())
	default:
		response.InternalError(w, r, err)
	}
}

// decodeDefinition 解码定义载荷（success_rule 白名单键——未知键拒收不忽略）。
func decodeDefinition(w http.ResponseWriter, r *http.Request, req *DefinitionInput) error {
	if err := response.DecodeJSON(w, r, req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return err
	}
	return nil
}

// definitionSummary 审计摘要（定义状态+版本+绑定+步数；四要素式全值回读）。
func definitionSummary(d *Definition, stepCount int) string {
	if d == nil {
		return ""
	}
	n := stepCount
	if n < 0 {
		n = -1 // activate 场景步数在库内，摘要不重复读
	}
	return "name=" + d.Name + " version=" + itoa(d.Version) + " status=" + d.Status +
		" mode=" + d.Mode + " binding=" + d.BindingPathPrefix + " instance_key_param=" + d.InstanceKeyParam +
		" steps=" + itoa(n)
}

func itoa(n int) string {
	if n < 0 {
		return "-"
	}
	digits := []byte{}
	for v := n; ; v /= 10 {
		digits = append([]byte{byte('0' + v%10)}, digits...)
		if v < 10 {
			break
		}
	}
	return string(digits)
}

func parsePathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的资源ID")
		return uuid.Nil, false
	}
	return id, true
}

func queryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return def
	}
	return n
}

// recordAudit 写操作审计（构造注入 audits.Service；未注入或无操作者时跳过不影响主流程）。
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
