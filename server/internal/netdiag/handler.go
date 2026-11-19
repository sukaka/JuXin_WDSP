// handler.go 网络诊断工具接口：任务创建/查询/停止/产物下载。
package netdiag

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// jobStore 任务仓储接口（由 *Store 实现；单测注入 stub）。
type jobStore interface {
	Create(ctx context.Context, node, action, target string, params Params, requestedBy *uuid.UUID, requestID string) (*Job, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Job, error)
	List(ctx context.Context, action, status string, page, pageSize int) ([]Job, int64, error)
	StopPending(ctx context.Context, id uuid.UUID) (bool, error)
}

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 网络诊断处理器。
type Handler struct {
	store       jobStore
	audits      auditRecorder
	sidecarDir  string // 边车共享卷目录（api 容器内路径）
	dataDir     string // 服务端诊断产物数据目录（pcap 落盘处）
	defaultNode string
}

// NewHandler 创建处理器。
func NewHandler(store jobStore, au auditRecorder, sidecarDir, dataDir, defaultNode string) *Handler {
	return &Handler{store: store, audits: au, sidecarDir: sidecarDir, dataDir: dataDir, defaultNode: defaultNode}
}

// RegisterRoutes 注册网络诊断路由。authChain 为认证链（会话解析+CSRF+认证+授权门控），
// 权限控制在路由层按权限点强制校验。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	exec := middleware.RequirePermission("network_tools.execute")
	mux.Handle("POST /api/v1/network-tools/jobs", authChain(exec(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/network-tools/jobs", authChain(exec(http.HandlerFunc(h.List))))
	mux.Handle("GET /api/v1/network-tools/jobs/{id}", authChain(exec(http.HandlerFunc(h.Get))))
	mux.Handle("POST /api/v1/network-tools/jobs/{id}/stop", authChain(exec(http.HandlerFunc(h.Stop))))
	mux.Handle("GET /api/v1/network-tools/jobs/{id}/download",
		authChain(middleware.RequirePermission("network_tools.download")(http.HandlerFunc(h.Download))))
}

type createRequest struct {
	Action      string `json:"action"`
	Target      string `json:"target"`
	Port        int    `json:"port,omitempty"`
	Count       int    `json:"count,omitempty"`
	MaxHops     int    `json:"max_hops,omitempty"`
	DurationSec int    `json:"duration_sec,omitempty"`
	Iface       string `json:"iface,omitempty"`
	FilterProto string `json:"filter_proto,omitempty"`
	FilterPort  int    `json:"filter_port,omitempty"`
	FilterHost  string `json:"filter_host,omitempty"`
	Node        string `json:"node,omitempty"`
}

// Create 创建诊断任务（PENDING，Worker 下发共享卷请求文件后执行）。
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	var req createRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	params := Params{
		Count:       req.Count,
		Port:        req.Port,
		MaxHops:     req.MaxHops,
		DurationSec: req.DurationSec,
		Iface:       req.Iface,
		FilterProto: req.FilterProto,
		FilterPort:  req.FilterPort,
		FilterHost:  req.FilterHost,
	}
	if err := Validate(req.Action, req.Target, &params); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	node := req.Node
	if node == "" {
		node = h.defaultNode
	}
	if !validNodeName(node) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "node 节点名不合法")
		return
	}
	job, err := h.store.Create(r.Context(), node, req.Action, req.Target, params, &p.UserID, response.RequestIDFrom(r))
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "execute", job.ID.String(), req.Action+" "+req.Target, audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusCreated, map[string]interface{}{"job": job})
}

// List 分页查询诊断任务。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	action := r.URL.Query().Get("action")
	if action != "" && !ValidAction(action) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "action 过滤值不合法")
		return
	}
	status := r.URL.Query().Get("status")
	if status != "" && !validStatus(status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "status 过滤值不合法")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	jobs, total, err := h.store.List(r.Context(), action, status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, jobs, total, page, pageSize)
}

// Get 查询任务详情（含 result_text；无 network_tools.download 权限时脱敏抓包 payload preview）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "诊断任务不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if len(job.CapturePackets) > 0 && (p == nil || !p.HasPermission("network_tools.download")) {
		jobCopy := *job
		jobCopy.CapturePackets = redactCapturePacketPreviews(job.CapturePackets)
		job = &jobCopy
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

func redactCapturePacketPreviews(raw json.RawMessage) json.RawMessage {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return raw
	}
	var packets []CapturePacket
	if err := json.Unmarshal(trimmed, &packets); err != nil {
		return nil
	}
	for i := range packets {
		packets[i].Preview = ""
	}
	out, err := json.Marshal(packets)
	if err != nil {
		return nil
	}
	return out
}

// Stop 停止诊断任务：PENDING 直接置 STOPPED；RUNNING 写停止标记文件由 netmgrd 终止执行。
func (h *Handler) Stop(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "诊断任务不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	switch job.Status {
	case StatusPending:
		stopped, err := h.store.StopPending(r.Context(), id)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		if !stopped {
			// 竞态：Worker 已下发，按 RUNNING 流程写停止标记
			if err := h.writeStopFlag(id); err != nil {
				response.InternalError(w, r, err)
				return
			}
		}
	case StatusRunning:
		if err := h.writeStopFlag(id); err != nil {
			response.InternalError(w, r, err)
			return
		}
	default:
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "任务已结束，无法停止")
		return
	}
	h.recordAudit(r, p, "stop", id.String(), "", audits.ResultSuccess, audits.RiskLow, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"message": "停止请求已受理"})
}

// writeStopFlag 原子写停止标记文件（空文件 stop-<jobUUID>）。
func (h *Handler) writeStopFlag(id uuid.UUID) error {
	dir := diagDir(h.sidecarDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".stop-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, stopFlagPath(h.sidecarDir, id))
}

// Download 下载抓包产物（文件名固定模式 capture-<id>.pcap，防路径穿越；
// 仅 capture 且 SUCCESS 且有产物；sha256 与入库值一致才发送）。
func (h *Handler) Download(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	if p == nil {
		response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	job, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "诊断任务不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if job.Action != ActionCapture {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "仅抓包任务有产物可下载")
		return
	}
	if job.Status != StatusSuccess {
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "仅成功的抓包任务可下载")
		return
	}
	if job.CaptureFile == "" || job.CaptureHash == "" {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "抓包产物不存在")
		return
	}
	// 路径仅由任务 ID 派生，不接受用户输入的任何路径片段
	path, err := CapturePath(h.dataDir, id)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的文件路径")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "抓包产物不存在")
		return
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	// sha256 一致性校验（与 Worker 入库值比对，防篡改后外发）
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if hex.EncodeToString(sum.Sum(nil)) != job.CaptureHash {
		h.recordAudit(r, p, "download", id.String(), job.CaptureFile, audits.ResultFailure, audits.RiskMedium, "产物完整性校验失败")
		response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "产物完整性校验失败，请重新执行诊断")
		return
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "download", id.String(), job.CaptureFile, audits.ResultSuccess, audits.RiskMedium, "")
	w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	w.Header().Set("Content-Disposition", `attachment; filename="capture-`+id.String()+`.pcap"`)
	http.ServeContent(w, r, job.CaptureFile, st.ModTime(), f)
}

// recordAudit 写入操作审计。持久化失败仅记日志，不影响主流程结果。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objectID, objectName, result, risk, failReason string) {
	if h.audits == nil {
		return
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "network_tools",
		Action:        action,
		ObjectType:    "netdiag_job",
		ObjectID:      objectID,
		ObjectName:    objectName,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record netdiag audit failed", "action", action, "error", err)
	}
}

func validStatus(s string) bool {
	switch s {
	case StatusPending, StatusRunning, StatusSuccess, StatusFailed, StatusStopped, StatusTimeout:
		return true
	}
	return false
}

// validNodeName 校验节点名（字母数字及 ._-，1-64 字符）。
func validNodeName(s string) bool {
	if len(s) == 0 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			continue
		}
		return false
	}
	return true
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
