package rulepacks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

const (
	maxRulePackConcurrentUploads = 2
	rulePackUploadTimeout        = 2 * time.Minute
	defaultConnDeadline          = 30 * time.Second
	uploadMultipartOverhead      = 1 << 20
	minUploadDiskFreeBytes       = 32 << 20
)

// Handler 提供纯离线 WAF 规则包 HTTP 接口。
type Handler struct {
	svc           *Service
	audits        *audits.Service
	uploadSemOnce sync.Once
	uploadSem     chan struct{}
}

// NewHandler 创建规则包 HTTP 处理器。
func NewHandler(svc *Service, au *audits.Service) *Handler {
	return &Handler{svc: svc, audits: au}
}

func (h *Handler) acquireUploadSlot() (func(), bool) {
	h.uploadSemOnce.Do(func() {
		h.uploadSem = make(chan struct{}, maxRulePackConcurrentUploads)
	})
	select {
	case h.uploadSem <- struct{}{}:
		return func() { <-h.uploadSem }, true
	default:
		return nil, false
	}
}

// Current GET /api/v1/rule-packs/current — 当前激活规则包版本与节点对齐状态。
func (h *Handler) Current(w http.ResponseWriter, r *http.Request) {
	status, err := h.svc.GetCurrentStatus(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, status)
}

// List GET /api/v1/rule-packs — 分页查询规则包档案列表。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	page := parseQueryInt(r, "page", 1)
	pageSize := parseQueryInt(r, "page_size", 20)
	items, total, err := h.svc.ListPacks(r.Context(), page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if items == nil {
		items = []RulePack{}
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Get GET /api/v1/rule-packs/{id} — 查询单个规则包详情与预检报告。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则包 ID")
		return
	}
	pack, err := h.svc.GetPack(r.Context(), id)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, pack)
}

// Upload POST /api/v1/rule-packs/upload — 上传纯离线规则包并立即执行验签、静态门禁与差异预检（零现网副作用）。
func (h *Handler) Upload(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if !h.svc.Storage().Writable() {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, ErrStorageUnavailable.Error())
		return
	}
	releaseSlot, ok := h.acquireUploadSlot()
	if !ok {
		w.Header().Set("Retry-After", "5")
		response.Error(w, r, http.StatusTooManyRequests, response.CodeRateLimited, ErrConcurrentUpload.Error())
		return
	}
	defer releaseSlot()

	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(rulePackUploadTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(rulePackUploadTimeout))
	defer func() {
		_ = rc.SetReadDeadline(time.Now().Add(defaultConnDeadline))
		_ = rc.SetWriteDeadline(time.Now().Add(defaultConnDeadline))
	}()

	if free := h.svc.diskFree(h.svc.Storage().StoreDir()); free >= 0 && free < minUploadDiskFreeBytes {
		response.Error(w, r, http.StatusInsufficientStorage, "INSUFFICIENT_STORAGE", "规则存储分区磁盘空间不足")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxArchiveBytes+uploadMultipartOverhead)
	mr, err := r.MultipartReader()
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请使用 multipart/form-data 上传规则包文件（字段名 file）")
		return
	}

	if err := os.MkdirAll(h.svc.Storage().StagingDir(), 0o750); err != nil {
		response.InternalError(w, r, err)
		return
	}

	var tmpPath string
	var origName string
	defer func() {
		if tmpPath != "" {
			_ = os.Remove(tmpPath)
		}
	}()

	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				response.Error(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE",
					fmt.Sprintf("规则包大小超过上限 (%d MiB)", MaxArchiveBytes>>20))
				return
			}
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "读取上传表单失败: "+err.Error())
			return
		}
		if part.FormName() != "file" {
			_ = part.Close()
			continue
		}
		origName = strings.TrimSpace(part.FileName())
		if err := validateUploadFileName(origName); err != nil {
			_ = part.Close()
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		tmpFile, err := os.CreateTemp(h.svc.Storage().StagingDir(), "upload-*.tar.gz")
		if err != nil {
			_ = part.Close()
			response.InternalError(w, r, err)
			return
		}
		tmpPath = tmpFile.Name()
		n, copyErr := io.Copy(tmpFile, io.LimitReader(part, MaxArchiveBytes+1))
		_ = part.Close()
		syncErr := tmpFile.Sync()
		closeErr := tmpFile.Close()
		if copyErr != nil {
			var maxErr *http.MaxBytesError
			if errors.As(copyErr, &maxErr) {
				response.Error(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE",
					fmt.Sprintf("规则包大小超过上限 (%d MiB)", MaxArchiveBytes>>20))
				return
			}
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "接收规则包失败: "+copyErr.Error())
			return
		}
		if n > MaxArchiveBytes {
			response.Error(w, r, http.StatusRequestEntityTooLarge, "PAYLOAD_TOO_LARGE",
				fmt.Sprintf("规则包大小超过上限 (%d MiB)", MaxArchiveBytes>>20))
			return
		}
		if syncErr != nil || closeErr != nil {
			response.InternalError(w, r, fmt.Errorf("写入临时规则包失败: sync=%v close=%v", syncErr, closeErr))
			return
		}
		break
	}

	if tmpPath == "" {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "缺少上传文件字段 file")
		return
	}

	var uploadedBy *uuid.UUID
	if p != nil && p.UserID != uuid.Nil {
		uid := p.UserID
		uploadedBy = &uid
	}

	pack, err := h.svc.UploadAndVerify(r.Context(), tmpPath, origName, uploadedBy)
	if err != nil {
		h.recordAudit(r, p, "upload", origName, origName, "error="+err.Error(), audits.ResultFailure, audits.RiskMedium)
		h.writeServiceError(w, r, err)
		return
	}
	tmpPath = "" // 已被 PersistArchive 移走
	h.recordAudit(r, p, "upload", pack.ID.String(), pack.RulePackVersion,
		fmt.Sprintf("crs=%s,size=%d,sha256=%.12s", pack.CRSVersion, pack.FileSize, pack.FileSHA256),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, pack)
}

// Apply POST /api/v1/rule-packs/{id}/apply — 管理员确认后一键生效（自动发布 + 自动同步元数据）。
func (h *Handler) Apply(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则包 ID")
		return
	}
	req, err := decodeOptionalApplyRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	var uid uuid.UUID
	if p != nil {
		uid = p.UserID
	}
	job, err := h.svc.StartApply(r.Context(), id, req, uid, response.RequestIDFrom(r))
	if err != nil {
		h.recordAudit(r, p, "apply", id.String(), id.String(), "error="+err.Error(), audits.ResultFailure, audits.RiskHigh)
		h.writeServiceError(w, r, err)
		return
	}
	summary := fmt.Sprintf("job_id=%s,version=%s", job.ID, job.TargetVersion)
	if req.AllowDegradedHA {
		summary += ",degraded_ha=true,reason=" + req.DegradedReason
	}
	h.recordAudit(r, p, "apply", id.String(), job.TargetVersion, summary, audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusAccepted, job)
}

// Rollback POST /api/v1/rule-packs/{id}/rollback — 一键回滚到保留的历史规则包快照。
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的规则包 ID")
		return
	}
	req, err := decodeOptionalApplyRequest(r)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	var uid uuid.UUID
	if p != nil {
		uid = p.UserID
	}
	job, err := h.svc.StartRollback(r.Context(), id, req, uid, response.RequestIDFrom(r))
	if err != nil {
		h.recordAudit(r, p, "rollback", id.String(), id.String(), "error="+err.Error(), audits.ResultFailure, audits.RiskHigh)
		h.writeServiceError(w, r, err)
		return
	}
	h.recordAudit(r, p, "rollback", id.String(), job.TargetVersion,
		fmt.Sprintf("job_id=%s,target=%s,prev=%s", job.ID, job.TargetVersion, job.PreviousVersion),
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusAccepted, job)
}

// GetJob GET /api/v1/rule-packs/jobs/{job_id} — 查询规则包应用/回滚任务进度与节点明细。
func (h *Handler) GetJob(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("job_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务 ID")
		return
	}
	job, err := h.svc.GetJob(r.Context(), id)
	if err != nil {
		h.writeServiceError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, job)
}

// RetryNodeSync POST /api/v1/rule-packs/nodes/{node_id}/retry-sync — 备机恢复后补发规则包并重同步配置。
func (h *Handler) RetryNodeSync(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	nodeID, err := uuid.Parse(r.PathValue("node_id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的节点 ID")
		return
	}
	if err := h.svc.RetryNodeSync(r.Context(), nodeID); err != nil {
		h.recordAudit(r, p, "retry_node_sync", nodeID.String(), nodeID.String(), "error="+err.Error(), audits.ResultFailure, audits.RiskMedium)
		h.writeServiceError(w, r, err)
		return
	}
	h.recordAudit(r, p, "retry_node_sync", nodeID.String(), nodeID.String(), "resynced", audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "节点规则包与配置已补齐同步"})
}

func (h *Handler) writeServiceError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, err.Error())
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrInvalidArchive),
		errors.Is(err, ErrInvalidSignature), errors.Is(err, ErrStaticGateFailed),
		errors.Is(err, ErrIncompatibleSystem):
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
	case errors.Is(err, ErrVersionDowngrade), errors.Is(err, ErrVersionConflict),
		errors.Is(err, ErrInvalidState), errors.Is(err, ErrActiveJob),
		errors.Is(err, ErrUpgradeActive), errors.Is(err, ErrSplitBrain),
		errors.Is(err, ErrRollbackUnavailable):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
	case errors.Is(err, ErrStorageUnavailable), errors.Is(err, ErrClusterUnsupported):
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, err.Error())
	default:
		response.InternalError(w, r, err)
	}
}

func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, summary, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:       &p.UserID,
		Username:     p.Username,
		SourceIP:     middleware.RemoteIP(r),
		ConnectionIP: middleware.ConnectionIP(r),
		UserAgent:    r.UserAgent(),
		Module:       "waf_rules",
		Action:       "rulepack_" + action,
		ObjectType:   "waf_rule_pack",
		ObjectID:     objID,
		ObjectName:   objName,
		AfterSummary: summary,
		Result:       result,
		RiskLevel:    risk,
		RequestID:    response.RequestIDFrom(r),
	})
}

func decodeOptionalApplyRequest(r *http.Request) (ApplyRequest, error) {
	var req ApplyRequest
	if r.Body == nil || r.ContentLength == 0 {
		return req, nil
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	if err := dec.Decode(&req); err != nil {
		if errors.Is(err, io.EOF) {
			return req, nil
		}
		return req, errors.New("请求体 JSON 格式错误")
	}
	req.DegradedReason = strings.TrimSpace(req.DegradedReason)
	if len([]rune(req.DegradedReason)) > 500 {
		return req, errors.New("降级说明长度不能超过 500 字")
	}
	return req, nil
}

func validateUploadFileName(name string) error {
	if name == "" || len(name) > 255 {
		return errors.New("文件名不能为空且不超过 255 字符")
	}
	if filepath.Base(name) != name || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return errors.New("文件名不能包含路径分隔符")
	}
	if strings.HasPrefix(name, ".") || !strings.HasSuffix(strings.ToLower(name), ".tar.gz") {
		return errors.New("规则包必须为 .tar.gz 归档文件")
	}
	return nil
}

func parseQueryInt(r *http.Request, key string, def int) int {
	v := strings.TrimSpace(r.URL.Query().Get(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
