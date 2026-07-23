// handler.go 备份接口：List/Create/Get/Verify/Download/Delete。
package backups

import (
	"errors"
	"net/http"
	"os"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Handler 备份处理器。
type Handler struct {
	store   *Store
	worker  *Worker
	dataDir string
	audits  *audits.Service
}

// NewHandler 创建处理器。
func NewHandler(store *Store, worker *Worker, dataDir string, au *audits.Service) *Handler {
	return &Handler{store: store, worker: worker, dataDir: dataDir, audits: au}
}

// List 备份任务列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	backupType := r.URL.Query().Get("backup_type")
	status := r.URL.Query().Get("status")
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.List(r.Context(), backupType, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

type createBackupRequest struct {
	BackupType string `json:"backup_type"`
}

// Create 创建备份任务（异步执行；二次校验类型）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createBackupRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if !ValidType(req.BackupType) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"无效的备份类型（支持 FULL / CONFIG_ONLY）")
		return
	}
	if h.worker.exporter.enc == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable,
			"加密服务未配置，无法创建加密备份")
		return
	}
	job, err := h.store.Create(r.Context(), req.BackupType, &p.UserID, response.RequestIDFrom(r))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", job.ID.String(), req.BackupType, audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

// Get 备份任务详情（含失败原因）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份任务不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

// Verify 手动验证备份完整性（重新解密校验，结果落库）。
func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	res, err := h.worker.VerifyBackup(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份任务不存在")
			return
		}
		if errors.Is(err, ErrInvalidStatus) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "任务执行中，无法验证")
			return
		}
		if errors.Is(err, ErrNoEncryption) {
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "加密服务未配置")
			return
		}
		h.recordAudit(r, p, "verify", id.String(), "", audits.ResultFailure, audits.RiskMedium, err.Error())
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "备份验证未通过："+failMsg(err))
		return
	}
	h.recordAudit(r, p, "verify", id.String(), "", audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"verified": true, "result": res})
}

// Download 下载备份文件（文件名固定模式 backup-{id}.jzbk，防路径穿越）。
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份任务不存在")
		return
	}
	if job.Status != StatusSuccess {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅成功的备份可下载")
		return
	}
	// 文件名仅由任务 ID 派生，不接受用户输入的任何路径片段
	path, err := BackupPath(h.dataDir, id)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的文件路径")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份文件不存在")
		return
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "download", id.String(), BackupFileName(id), audits.ResultSuccess, audits.RiskLow, "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+BackupFileName(id)+`"`)
	http.ServeContent(w, r, BackupFileName(id), st.ModTime(), f)
}

// Delete 删除备份（文件 + 记录；被恢复任务引用或执行中的不可删）。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的备份ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "备份任务不存在")
		return
	}
	if job.Status == StatusRunning || job.Status == StatusVerifying {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "任务执行中，不可删除")
		return
	}
	ref, err := h.store.IsReferencedByRestore(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if ref {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "存在关联恢复任务，不可删除")
		return
	}
	// 先删文件再删记录；文件删除失败不继续（不静默）
	if path, perr := BackupPath(h.dataDir, id); perr == nil {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			response.InternalError(w, r, rmErr)
			return
		}
	}
	if err := h.store.Delete(r.Context(), id); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", id.String(), job.BackupType, audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "备份已删除"})
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason string) {
	_ = h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "backups",
		Action:        action,
		ObjectType:    "backup_job",
		ObjectID:      objID,
		ObjectName:    objName,
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
