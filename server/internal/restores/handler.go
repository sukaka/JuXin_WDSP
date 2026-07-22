// handler.go 恢复接口：List/Validate/Create/Get/Confirm/Cancel。
package restores

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/backups"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 恢复处理器。
type Handler struct {
	store   *Store
	service *Service
	audits  *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, service *Service, au *audits.Service) *Handler {
	return &Handler{store: store, service: service, audits: au}
}

// List 恢复任务列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// Get 恢复任务详情（含预览与失败原因）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的恢复ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "恢复任务不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

type validateRequest struct {
	BackupJobID string `json:"backup_job_id"`
}

// Validate 校验备份并输出恢复预览（不创建任务）。
func (h *Handler) Validate(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req validateRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	backupID, err := uuid.Parse(req.BackupJobID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	preview, err := h.service.ValidateBackup(r.Context(), backupID)
	if err != nil {
		h.writeServiceError(w, r, err)
		h.recordAudit(r, p, "validate", backupID.String(), "", audits.ResultFailure, audits.RiskLow, err.Error())
		return
	}
	h.recordAudit(r, p, "validate", backupID.String(), "", audits.ResultSuccess, audits.RiskLow, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"preview": preview})
}

type createRestoreRequest struct {
	BackupJobID string `json:"backup_job_id"`
	Scope       string `json:"scope"`
}

// Create 创建恢复任务（异步隔离恢复，绝不触碰正式表）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createRestoreRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	backupID, err := uuid.Parse(req.BackupJobID)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	if !ValidScope(req.Scope) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的恢复范围（支持 FULL / CONFIG / DATABASE / CERTIFICATE）")
		return
	}
	job, err := h.service.Create(r.Context(), backupID, req.Scope, &p.UserID, response.RequestIDFrom(r))
	if err != nil {
		h.writeServiceError(w, r, err)
		h.recordAudit(r, p, "create", backupID.String(), req.Scope, audits.ResultFailure, audits.RiskHigh, err.Error())
		return
	}
	h.recordAudit(r, p, "create", job.ID.String(), req.Scope, audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

type confirmRequest struct {
	Reason string `json:"reason"`
}

// Confirm 管理员二次确认 → 正式恢复（高风险，全程审计）。
func (h *Handler) Confirm(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的恢复ID")
		return
	}
	var req confirmRequest
	if r.ContentLength > 0 {
		if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
	}
	job, summary, err := h.service.Confirm(r.Context(), id, p.UserID)
	if err != nil {
		h.writeServiceError(w, r, err)
		h.recordAudit(r, p, "confirm", id.String(), req.Reason, audits.ResultFailure, audits.RiskCritical, err.Error())
		return
	}
	summaryJSON, _ := json.Marshal(summary)
	h.recordAuditWithDetail(r, p, "confirm", id.String(), req.Reason, audits.ResultSuccess, audits.RiskCritical,
		"", string(summaryJSON))
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job, "post_verify": summary})
}

// Import 导入外部备份文件（multipart 上传，全新环境恢复入口）。
// 文件先落临时目录（流式，内存有界），再经 Service.ImportBackup 全量验证后登记。
func (h *Handler) Import(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	// 限制上传大小（与备份文件上限一致）
	r.Body = http.MaxBytesReader(w, r.Body, 2<<30)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的上传请求")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少备份文件")
		return
	}
	defer file.Close()
	// 文件名安全：仅接受 .jzbk 后缀，原名仅记录不使用其路径语义
	if !strings.HasSuffix(strings.ToLower(header.Filename), ".jzbk") {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅支持 .jzbk 备份文件")
		return
	}
	tmpPath, err := h.service.StagingImportPath("jz-import-" + uuid.NewString() + ".jzbk")
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	out, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		out.Close()
		os.Remove(tmpPath)
		response.InternalError(w, r, err)
		return
	}
	out.Close()
	defer os.Remove(tmpPath)

	job, err := h.service.ImportBackup(r.Context(), tmpPath, &p.UserID)
	if err != nil {
		h.recordAudit(r, p, "import", "", header.Filename, audits.ResultFailure, audits.RiskHigh, err.Error())
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	h.recordAudit(r, p, "import", job.ID.String(), header.Filename, audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, job)
}

// Cancel 取消等待确认的恢复任务（删除隔离环境）。
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的恢复ID")
		return
	}
	if err := h.service.Cancel(r.Context(), id); err != nil {
		if errors.Is(err, ErrInvalidStatus) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅等待确认的任务可取消")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "cancel", id.String(), "", audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "恢复任务已取消"})
}

// writeServiceError 统一错误映射。
func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, backups.ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份任务不存在")
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "恢复任务不存在")
	case errors.Is(err, ErrBackupNotReady):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "备份未成功或未通过验证，不可用于恢复")
	case errors.Is(err, backups.ErrFileMissing):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份文件不存在")
	case errors.Is(err, backups.ErrIncompatible):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "备份由更新版本创建，与当前系统不兼容")
	case errors.Is(err, ErrActiveRestore):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "存在进行中的恢复任务，请先完成或取消")
	case errors.Is(err, ErrEmptyScope):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "该备份在所选范围内无可恢复表")
	case errors.Is(err, ErrInvalidStatus):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "任务状态不允许该操作")
	case errors.Is(err, ErrMaintenanceUnavail):
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "维护模式存储不可用，拒绝正式恢复")
	case errors.Is(err, backups.ErrNoEncryption):
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "加密服务未配置")
	default:
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "恢复操作失败："+failMsg(err))
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason string) {
	h.recordAuditWithDetail(r, p, action, objID, objName, result, risk, failReason, "")
}

func (h *Handler) recordAuditWithDetail(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason, afterSummary string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.RemoteIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "restores",
		Action:        action,
		ObjectType:    "restore_job",
		ObjectID:      objID,
		ObjectName:    objName,
		AfterSummary:  afterSummary,
		Result:        result,
		FailureReason: failReason,
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
