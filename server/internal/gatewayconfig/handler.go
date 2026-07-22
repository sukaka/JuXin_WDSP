package gatewayconfig

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/applications"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 是网关配置发布/版本/状态处理器。
type Handler struct {
	publisher *Publisher
	apps      *applications.Store
	audits    *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(pub *Publisher, apps *applications.Store, au *audits.Service) *Handler {
	return &Handler{publisher: pub, apps: apps, audits: au}
}

// Preview 配置预览。
func (h *Handler) Preview(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	// 构建快照（全部活动应用）
	pub := h.publisher
	appsData, snapshot, err := pub.buildSnapshot(r.Context(), nil)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	gen, err := Generate(GenerateInput{Apps: appsData, AdminSocket: pub.caddy.SocketPath()})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "gateway_configs", "preview", "gateway_config", "", "gateway", "", "", audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"configuration_hash": gen.Hash,
		"server_count":       gen.ServerCount,
		"route_count":        gen.RouteCount,
		"business_snapshot":  snapshot,
		"config_preview":     gen.JSON,
	})
}

// Validate 配置校验。
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	pub := h.publisher
	appsData, snapshot, err := pub.buildSnapshot(r.Context(), nil)
	if err != nil {
		response.Error(w, r, http.StatusOK, response.CodeInvalidArgument, err.Error())
		return
	}
	gen, err := Generate(GenerateInput{Apps: appsData, AdminSocket: pub.caddy.SocketPath()})
	if err != nil {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"valid": false, "error": err.Error(),
		})
		return
	}
	if err := pub.caddy.ValidateConfig(r.Context(), gen.JSON); err != nil {
		h.recordAudit(r, p, "gateway_configs", "validate", "gateway_config", "", "gateway", "", "failed: "+err.Error(), audits.ResultFailure, audits.RiskLow)
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"valid": false, "error": err.Error(), "configuration_hash": gen.Hash,
		})
		return
	}
	h.recordAudit(r, p, "gateway_configs", "validate", "gateway_config", "", "gateway", "", "valid", audits.ResultSuccess, audits.RiskLow)
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"valid": true, "configuration_hash": gen.Hash, "server_count": gen.ServerCount,
		"route_count": gen.RouteCount, "business_snapshot": snapshot,
	})
}

type publishRequest struct {
	IdempotencyKey string      `json:"idempotency_key"`
	AppIDs         []uuid.UUID `json:"app_ids"`
}

// Publish 发布配置。
func (h *Handler) Publish(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req publishRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	task, err := h.publisher.PublishSync(r.Context(), PublishInput{
		RequestedBy:    p.UserID,
		RequestID:      response.RequestIDFrom(r),
		IdempotencyKey: req.IdempotencyKey,
		AppIDs:         req.AppIDs,
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	risk := audits.RiskHigh
	h.recordAudit(r, p, "gateway_configs", "publish", "publish_task", task.ID.String(), "gateway",
		"", taskResultSummary(task), taskToAuditResult(task), risk)
	response.JSON(w, r, http.StatusOK, taskItem(task))
}

// CurrentConfig 当前生效配置。
func (h *Handler) CurrentConfig(w http.ResponseWriter, r *http.Request) {
	version, err := h.publisher.GetCurrentVersion(r.Context())
	if err != nil || version == nil {
		response.JSON(w, r, http.StatusOK, map[string]interface{}{"has_current": false})
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"has_current": true,
		"version":     versionItem(version),
	})
}

// ListTasks 发布任务列表。
func (h *Handler) ListTasks(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	tasks, total, err := h.publisher.ListTasks(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(tasks))
	for _, t := range tasks {
		items = append(items, taskItem(&t))
	}
	response.Page(w, r, items, total, page, pageSize)
}

// GetTask 发布任务详情。
func (h *Handler) GetTask(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	task, err := h.publisher.GetTask(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "任务不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, taskItem(task))
}

// ListVersions 配置版本列表。
func (h *Handler) ListVersions(w http.ResponseWriter, r *http.Request) {
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	versions, total, err := h.publisher.ListVersions(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	items := make([]map[string]interface{}, 0, len(versions))
	for _, v := range versions {
		items = append(items, versionItem(&v))
	}
	response.Page(w, r, items, total, page, pageSize)
}

// GetVersion 配置版本详情。
func (h *Handler) GetVersion(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	v, err := h.publisher.GetVersion(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, versionItem(v))
}

// GetVersionDiff 版本差异。
func (h *Handler) GetVersionDiff(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	v, err := h.publisher.GetVersion(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "版本不存在")
		return
	}
	current, _ := h.publisher.GetCurrentVersion(r.Context())
	var currentHash, currentNum string
	if current != nil {
		currentHash = current.ConfigurationHash
		currentNum = current.VersionNumber
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"target_version":         versionItem(v),
		"current_version_number": currentNum,
		"current_hash":           currentHash,
		"target_hash":            v.ConfigurationHash,
		"same":                   currentHash == v.ConfigurationHash,
		"business_snapshot":      v.BusinessSnapshot,
	})
}

type rollbackRequest struct {
	VersionID uuid.UUID `json:"version_id"`
}

// Rollback 回滚到历史版本。
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的版本ID")
		return
	}
	task, err := h.publisher.Rollback(r.Context(), RollbackInput{
		VersionID:   id,
		RequestedBy: p.UserID,
		RequestID:   response.RequestIDFrom(r),
	})
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "gateway_configs", "rollback", "publish_task", task.ID.String(), "gateway",
		"", taskResultSummary(task), taskToAuditResult(task), audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, taskItem(task))
}

// GatewayStatus 网关状态。
func (h *Handler) GatewayStatus(w http.ResponseWriter, r *http.Request) {
	// 网关管理接口可用性
	pingErr := h.publisher.caddy.Ping(r.Context())
	gatewayUp := pingErr == nil

	// 统计信息
	appCount, _ := h.countApps(r)
	domainCount := h.countDomains(r)
	upstreamCount := h.countUpstreams(r)

	current, _ := h.publisher.GetCurrentVersion(r.Context())
	var currentVersion, currentHash, lastPublishAt string
	var publishResult string
	if current != nil {
		currentVersion = current.VersionNumber
		currentHash = current.ConfigurationHash
		publishResult = current.PublishResult
		if current.PublishedAt != nil {
			lastPublishAt = current.PublishedAt.Format("2006-01-02 15:04:05")
		}
	}

	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"gateway_up":          gatewayUp,
		"gateway_error":       errString(pingErr),
		"current_version":     currentVersion,
		"current_hash":        currentHash,
		"last_publish_result": publishResult,
		"last_publish_at":     lastPublishAt,
		"application_count":   appCount,
		"domain_count":        domainCount,
		"upstream_count":      upstreamCount,
	})
}

func (h *Handler) countApps(r *http.Request) (int64, error) {
	var n int64
	err := h.apps.DB().QueryRow(r.Context(), `SELECT count(*) FROM applications WHERE deleted_at IS NULL AND status='ACTIVE'`).Scan(&n)
	return n, err
}

func (h *Handler) countDomains(r *http.Request) int64 {
	var n int64
	_ = h.apps.DB().QueryRow(r.Context(), `SELECT count(*) FROM application_domains ad JOIN applications a ON a.id=ad.application_id WHERE a.deleted_at IS NULL AND a.status='ACTIVE' AND ad.status='ACTIVE'`).Scan(&n)
	return n
}

func (h *Handler) countUpstreams(r *http.Request) int64 {
	var n int64
	_ = h.apps.DB().QueryRow(r.Context(), `SELECT count(*) FROM upstreams u JOIN applications a ON a.id=u.application_id WHERE a.deleted_at IS NULL AND a.status='ACTIVE' AND u.status='ACTIVE' AND u.deleted_at IS NULL`).Scan(&n)
	return n
}

func taskItem(t *PublishTask) map[string]interface{} {
	return map[string]interface{}{
		"id": t.ID, "task_type": t.TaskType, "status": t.Status,
		"requested_by": t.RequestedBy, "requested_at": t.RequestedAt,
		"started_at": t.StartedAt, "finished_at": t.FinishedAt,
		"target_version_id": t.TargetVersionID, "current_step": t.CurrentStep,
		"progress": t.Progress, "result_summary": t.ResultSummary,
		"failure_code": t.FailureCode, "failure_message": t.FailureMessage,
		"request_id": t.RequestID,
	}
}

func versionItem(v *ConfigVersion) map[string]interface{} {
	return map[string]interface{}{
		"id": v.ID, "version_number": v.VersionNumber, "configuration_hash": v.ConfigurationHash,
		"business_snapshot": v.BusinessSnapshot, "change_summary": v.ChangeSummary,
		"previous_version_id": v.PreviousVersionID, "publish_task_id": v.PublishTaskID,
		"publish_result": v.PublishResult, "is_current": v.IsCurrent,
		"created_by": v.CreatedBy, "created_at": v.CreatedAt, "published_at": v.PublishedAt,
	}
}

func taskResultSummary(t *PublishTask) string {
	return `{"status":"` + t.Status + `","step":"` + t.CurrentStep + `"}`
}

func taskToAuditResult(t *PublishTask) string {
	if t.Status == TaskSuccess {
		return audits.ResultSuccess
	}
	return audits.ResultFailure
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, module, action, objType, objID, objName, before, after, result, risk string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        module,
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

var _ = errors.New
