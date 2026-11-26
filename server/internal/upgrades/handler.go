// handler.go 升级接口：List/RegisterPackage/Precheck/Execute/Get/Rollback。
package upgrades

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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

// packageRegistrar 上传登记所需的持久化能力（*Store 实现；测试可注入内存实现）。
type packageRegistrar interface {
	FindPackageByHash(ctx context.Context, hash string) (*Package, error)
	CreatePackage(ctx context.Context, pkg *Package) error
}

// upgradeExecutor 上传后自动创建升级执行的入口（*Service 实现；测试可注入）。
// Execute 立即执行；Schedule 创建定时任务（SCHEDULED，到点自动开始）。
type upgradeExecutor interface {
	Execute(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string) (*Job, error)
	Schedule(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string, scheduledAt time.Time) (*Job, error)
}

// upgradeModeExecutor 支持按 cluster_mode（LOCAL / HA_ROLLING）创建升级任务的可选扩展接口（*Service 实现）。
type upgradeModeExecutor interface {
	ExecuteWithMode(ctx context.Context, packageID, requestedBy uuid.UUID, requestID, clusterMode string) (*Job, error)
	ScheduleWithMode(ctx context.Context, packageID, requestedBy uuid.UUID, requestID string, scheduledAt time.Time, clusterMode string) (*Job, error)
}

// upgradeCanceller 取消定时升级任务的入口（*Service 实现；测试可注入）。
type upgradeCanceller interface {
	Cancel(ctx context.Context, jobID, requestedBy uuid.UUID) (*Job, error)
}

// jobNodeExecStore 为任务查询附加逐节点执行明细的最小只读接口（*Store 实现）。
type jobNodeExecStore interface {
	GetJob(ctx context.Context, id uuid.UUID) (*Job, error)
	ListJobs(ctx context.Context, status string, page, pageSize int) ([]Job, int64, error)
	ListNodeExecutions(ctx context.Context, jobID uuid.UUID) ([]NodeExecution, error)
	ListNodeExecutionsByJobIDs(ctx context.Context, jobIDs []uuid.UUID) (map[uuid.UUID][]NodeExecution, error)
}

// Handler 升级处理器。
type Handler struct {
	store   *Store
	service *Service
	audits  *audits.Service
	// 上传配置（SetUploadDir 注入；packagesDir 为空时上传接口不可用）
	packagesDir    string
	maxUploadBytes int64
	// uploadLocks 按目标文件名划分上传互斥锁（同名并发上传串行化，防 check-then-rename
	// TOCTOU 竞态互相覆盖导致登记哈希与落盘文件不符）
	uploadLocks       sync.Map
	uploadSemOnce     sync.Once
	uploadSem         chan struct{}
	diskFreeFn        func(string) int64
	diskCheckInterval int64
	// artifactVerifier 负责固定信任根、签名和归档内容绑定校验。
	// 仅测试可替换；生产默认使用 verifyPackageArtifact。
	artifactVerifier PackageArtifactVerifier
	// registrar/executor 上传链路的登记与自动执行入口；canceller 定时任务取消入口。
	// 仅测试可替换（同 artifactVerifier 模式）；生产由 NewHandler 绑定 store/service。
	registrar packageRegistrar
	executor  upgradeExecutor
	canceller upgradeCanceller
	jobReader jobNodeExecStore
	// auditRecorder 仅测试可替换：非 nil 时 recordAudit 委托给它（生产为 nil，走 audits.Service）。
	auditRecorder func(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason string)
}

// NewHandler 创建处理器。
func NewHandler(store *Store, svc *Service, au *audits.Service) *Handler {
	h := &Handler{
		store:            store,
		service:          svc,
		audits:           au,
		artifactVerifier: verifyPackageArtifact,
	}
	if store != nil {
		h.registrar = store
		h.jobReader = store
	}
	if svc != nil {
		h.executor = svc
		h.canceller = svc
	}
	return h
}

// SetArtifactVerifier 为隔离测试注入临时验签器；正式路径不得通过环境变量替换信任根。
func (h *Handler) SetArtifactVerifier(verifier PackageArtifactVerifier) *Handler {
	h.artifactVerifier = verifier
	return h
}

// SetUploadDeps 为隔离测试注入内存版登记/执行实现；生产装配使用 store/service。
func (h *Handler) SetUploadDeps(registrar packageRegistrar, executor upgradeExecutor) *Handler {
	h.registrar = registrar
	h.executor = executor
	return h
}

// SetCanceller 为隔离测试注入内存版取消实现；生产装配使用 service。
func (h *Handler) SetCanceller(canceller upgradeCanceller) *Handler {
	h.canceller = canceller
	return h
}

// SetAuditRecorder 为隔离测试捕获审计写入；生产为 nil，走 audits.Service。
func (h *Handler) SetAuditRecorder(fn func(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason string)) *Handler {
	h.auditRecorder = fn
	return h
}

// uploadLock 返回按目标文件名划分的上传互斥锁（进程内同名上传串行化）。
func (h *Handler) uploadLock(target string) *sync.Mutex {
	v, _ := h.uploadLocks.LoadOrStore(target, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// RegisterRoutes 注册升级路由。authChain 为认证链（会话解析+认证+CSRF），
// 权限控制在路由层按权限点强制校验。
// 路径契约：docs/tasks/STAGE_6_SECURITY_OPERATIONS_DELIVERY.md §19.5。
func (h *Handler) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	read := requireAnyPermission("upgrades.read", "upgrade_records.read")
	// 升级包
	mux.Handle("GET /api/v1/upgrade-packages", authChain(read(http.HandlerFunc(h.ListPackages))))
	mux.Handle("POST /api/v1/upgrades/packages", authChain(middleware.RequirePermission("upgrades.execute")(http.HandlerFunc(h.RegisterPackage))))
	mux.Handle("POST /api/v1/upgrades/packages/upload", authChain(middleware.RequirePermission("upgrades.execute")(http.HandlerFunc(h.UploadPackage))))
	mux.Handle("GET /api/v1/upgrade-packages/{id}", authChain(read(http.HandlerFunc(h.GetPackage))))
	// 升级前检查（body 携带 package_id，可选 cluster_mode）
	mux.Handle("POST /api/v1/upgrades/precheck", authChain(middleware.RequirePermission("upgrades.precheck")(http.HandlerFunc(h.Precheck))))
	// 集群节点版本与就绪态（固定路径优先于 /upgrades/{id}）
	mux.Handle("GET /api/v1/upgrades/nodes", authChain(read(http.HandlerFunc(h.ListNodes))))
	// 升级任务
	mux.Handle("GET /api/v1/upgrades", authChain(read(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/upgrades", authChain(middleware.RequirePermission("upgrades.execute")(http.HandlerFunc(h.Execute))))
	mux.Handle("GET /api/v1/upgrades/{id}", authChain(read(http.HandlerFunc(h.Get))))
	mux.Handle("POST /api/v1/upgrades/{id}/rollback", authChain(middleware.RequirePermission("upgrades.rollback")(http.HandlerFunc(h.Rollback))))
	mux.Handle("POST /api/v1/upgrades/{id}/cancel", authChain(middleware.RequirePermission("upgrades.execute")(http.HandlerFunc(h.Cancel))))
	mux.Handle("POST /api/v1/upgrades/{id}/retry-node", authChain(middleware.RequirePermission("upgrades.execute")(http.HandlerFunc(h.RetryNode))))
}

// requireAnyPermission 要求拥有任一权限点（路由层权限控制）。
func requireAnyPermission(perms ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := authz.PrincipalFrom(r.Context())
			if p == nil {
				response.Error(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "未登录或会话已过期")
				return
			}
			for _, perm := range perms {
				if p.HasPermission(perm) {
					next.ServeHTTP(w, r)
					return
				}
			}
			response.Error(w, r, http.StatusForbidden, response.CodePermissionDenied, "无权执行该操作")
		})
	}
}

// ---------- 升级包 ----------

// ListPackages 升级包列表。
func (h *Handler) ListPackages(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && !ValidPackageStatus(status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的升级包状态")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	list, total, err := h.store.ListPackages(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, page, pageSize)
}

// GetPackage 升级包详情。
func (h *Handler) GetPackage(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的升级包ID")
		return
	}
	pkg, err := h.store.GetPackage(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级包不存在")
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"package": pkg})
}

type registerPackageRequest struct {
	FileName    string          `json:"file_name"`
	VersionFrom string          `json:"version_from"`
	VersionTo   string          `json:"version_to"`
	FileHash    string          `json:"file_hash"`
	FileSize    int64           `json:"file_size"`
	Manifest    json.RawMessage `json:"manifest"`
}

// RegisterPackage 登记升级包：校验版本号与哈希格式，
// 全部通过则状态 REGISTERED；只有实际上传包通过签名与 manifest 校验后才进入 VERIFIED。
func (h *Handler) RegisterPackage(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req registerPackageRequest
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	pkg, validationErr := buildPackage(&req, p.UserID)
	if err := h.store.CreatePackage(r.Context(), pkg); err != nil {
		response.InternalError(w, r, err)
		return
	}
	if validationErr != nil {
		h.recordAudit(r, p, "register_package", pkg.ID.String(), pkg.FileName, audits.ResultFailure, audits.RiskMedium, validationErr.Error())
		response.JSON(w, r, http.StatusOK, map[string]interface{}{
			"package": pkg,
			"message": "升级包校验未通过，已登记为 REJECTED：" + validationErr.Error(),
		})
		return
	}
	h.recordAudit(r, p, "register_package", pkg.ID.String(), pkg.FileName, audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"package": pkg})
}

// buildPackage 校验登记请求并构造升级包。仅凭登记信息不能宣称内容已验证，
// 因此合法请求初始状态为 REGISTERED。
// 返回的 error 为校验失败原因（包仍以 REJECTED 状态登记，保留证据）。
func buildPackage(req *registerPackageRequest, uploadedBy uuid.UUID) (*Package, error) {
	pkg := &Package{
		FileName:    strings.TrimSpace(req.FileName),
		VersionFrom: strings.TrimSpace(req.VersionFrom),
		VersionTo:   strings.TrimSpace(req.VersionTo),
		FileHash:    strings.ToLower(strings.TrimSpace(req.FileHash)),
		FileSize:    req.FileSize,
		Manifest:    req.Manifest,
		Status:      PackageRegistered,
		UploadedBy:  &uploadedBy,
	}
	validate := func() error {
		if err := validatePackageFileName(pkg.FileName); err != nil {
			return err
		}
		if _, err := ParseVersion(pkg.VersionFrom); err != nil {
			return err
		}
		to, err := ParseVersion(pkg.VersionTo)
		if err != nil {
			return err
		}
		from, _ := ParseVersion(pkg.VersionFrom)
		if to.Compare(from) <= 0 {
			return errors.New("目标版本必须高于起始版本")
		}
		if !ValidHash(pkg.FileHash) {
			return errors.New("文件哈希必须为64位小写十六进制（sha256）")
		}
		if pkg.FileSize <= 0 {
			return errors.New("文件大小必须大于0")
		}
		if len(pkg.Manifest) > 0 && !json.Valid(pkg.Manifest) {
			return errors.New("manifest 不是合法 JSON")
		}
		return nil
	}
	if err := validate(); err != nil {
		pkg.Status = PackageRejected
		return pkg, err
	}
	return pkg, nil
}

// Precheck 对升级包执行升级前检查（异步任务外的独立预检，可选 cluster_mode）。
func (h *Handler) Precheck(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	// 兼容两种输入：POST /upgrades/precheck 的 body.package_id 或路径 {id}
	var id uuid.UUID
	var err error
	clusterMode := ClusterModeLocal
	if pv := r.PathValue("id"); pv != "" {
		id, err = uuid.Parse(pv)
	} else {
		var body struct {
			PackageID   string `json:"package_id"`
			ClusterMode string `json:"cluster_mode"`
		}
		if derr := response.DecodeJSON(w, r, &body, 4096); derr != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
		id, err = uuid.Parse(body.PackageID)
		if err == nil {
			mode, merr := NormalizeClusterMode(body.ClusterMode)
			if merr != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, merr.Error())
				return
			}
			clusterMode = mode
		}
	}
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的升级包ID")
		return
	}
	items, err := h.service.RunPrecheckWithMode(r.Context(), id, clusterMode)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级包不存在")
			return
		}
		if errors.Is(err, ErrInvalidInput) {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "precheck", id.String(), "", audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"precheck":     items,
		"passed":       !HasFail(items),
		"cluster_mode": clusterMode,
	})
}

// ---------- 集群节点版本与就绪态 ----------

// ListNodes 查询主备集群各节点当前版本与协同通道就绪态（GET /api/v1/upgrades/nodes）。
func (h *Handler) ListNodes(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		response.JSON(w, r, http.StatusOK, ClusterNodesResponse{
			Items:          []ClusterNodeStatusItem{},
			CurrentVersion: CurrentVersion,
			SplitBrain:     false,
			ClusterReady:   false,
		})
		return
	}
	res, err := h.service.ListClusterNodeStatuses(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, res)
}

// ---------- 升级任务 ----------

// List 升级任务列表（附带 cluster_mode 与 node_executions）。
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status != "" && !ValidStatus(status) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务状态")
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	reader := h.jobReader
	if reader == nil {
		reader = h.store
	}
	list, total, err := reader.ListJobs(r.Context(), status, page, pageSize)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if len(list) > 0 {
		ids := make([]uuid.UUID, len(list))
		for i := range list {
			if h.service != nil && (list[i].Status == StatusApplying || list[i].Status == StatusMigrating || list[i].Status == StatusVerifying) {
				if rerr := h.service.ReconcileJobResult(r.Context(), list[i].ID); rerr == nil {
					if updated, gerr := reader.GetJob(r.Context(), list[i].ID); gerr == nil {
						list[i] = *updated
					}
				} else {
					slog.Warn("reconcile upgrade job result on list failed", "job_id", list[i].ID, "error", rerr)
				}
			}
			if list[i].ClusterMode == "" {
				list[i].ClusterMode = ClusterModeLocal
			}
			ids[i] = list[i].ID
		}
		if byJob, nerr := reader.ListNodeExecutionsByJobIDs(r.Context(), ids); nerr == nil {
			for i := range list {
				if execs, ok := byJob[list[i].ID]; ok {
					list[i].NodeExecutions = execs
				} else if list[i].ClusterMode == ClusterModeHARolling {
					list[i].NodeExecutions = []NodeExecution{}
				}
			}
		} else {
			slog.Warn("list upgrade node executions failed", "error", nerr)
		}
	}
	response.Page(w, r, list, total, page, pageSize)
}

type executeRequest struct {
	PackageID   uuid.UUID `json:"package_id"`
	ClusterMode string    `json:"cluster_mode"`
}

// Execute 执行升级（异步：PRECHECK→BACKUP→[HA_ROLLING 备节点]→APPLYING→MIGRATING→VERIFYING）。
func (h *Handler) Execute(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req executeRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	mode, err := NormalizeClusterMode(req.ClusterMode)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	job, err := h.service.ExecuteWithMode(r.Context(), req.PackageID, p.UserID, response.RequestIDFrom(r), mode)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级包不存在")
		case errors.Is(err, ErrInvalidInput):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		case errors.Is(err, ErrPackageNotVerified):
			response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "升级包未通过校验（REJECTED），不可执行")
		case errors.Is(err, ErrActiveUpgrade):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "已有进行中的升级任务")
		case errors.Is(err, ErrClusterSplitBrain):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "execute", job.ID.String(), "", audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

// Get 升级任务详情（含预检结果、失败原因、cluster_mode 与 node_executions）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	reader := h.jobReader
	if reader == nil {
		reader = h.store
	}
	job, err := reader.GetJob(r.Context(), id)
	if err != nil {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级任务不存在")
		return
	}
	if h.service != nil && !TerminalStatus(job.Status) && job.Status != StatusRollingBack && job.Status != StatusScheduled {
		if rerr := h.service.ReconcileJobResult(r.Context(), job.ID); rerr != nil {
			slog.Warn("reconcile upgrade job result on get failed", "job_id", job.ID, "error", rerr)
		} else if updated, gerr := reader.GetJob(r.Context(), id); gerr == nil {
			job = updated
		}
	}
	if job.ClusterMode == "" {
		job.ClusterMode = ClusterModeLocal
	}
	if execs, nerr := reader.ListNodeExecutions(r.Context(), job.ID); nerr == nil {
		if len(execs) > 0 {
			job.NodeExecutions = execs
		} else if job.ClusterMode == ClusterModeHARolling {
			job.NodeExecutions = []NodeExecution{}
		}
	} else {
		slog.Warn("list upgrade node executions for job failed", "job_id", job.ID, "error", nerr)
	}
	resp := map[string]interface{}{"job": job}
	if h.service != nil {
		resp["server_status"] = h.service.EvaluateJobReadiness(r.Context(), job)
	}
	response.JSON(w, r, http.StatusOK, resp)
}

type retryNodeRequest struct {
	NodeID uuid.UUID `json:"node_id"`
}

// RetryNode 单节点补升重试（POST /api/v1/upgrades/{id}/retry-node）。
func (h *Handler) RetryNode(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	jobID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	var req retryNodeRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil || req.NodeID == uuid.Nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请提供有效的 node_id")
		return
	}
	if h.service == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "升级执行服务未配置")
		return
	}
	execRow, err := h.service.RetryNodeUpgrade(r.Context(), jobID, req.NodeID, p.UserID, response.RequestIDFrom(r))
	if err != nil {
		h.recordAudit(r, p, "retry_node", jobID.String(), req.NodeID.String(), audits.ResultFailure, audits.RiskHigh, err.Error())
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级任务或节点执行记录不存在")
		case errors.Is(err, ErrInvalidInput):
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		case errors.Is(err, ErrActiveUpgrade):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "存在进行中的升级任务，请稍后重试")
		case errors.Is(err, ErrInvalidStatus), errors.Is(err, ErrClusterSplitBrain):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		case errors.Is(err, ErrClusterSyncNotConfigured):
			response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "集群节点协同服务未配置")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "retry_node", jobID.String(), execRow.NodeName, audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"node_execution": execRow})
}

// Rollback 显式回滚已完成/失败的升级任务（恢复其升级前备份）。
func (h *Handler) Rollback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	job, err := h.service.Rollback(r.Context(), id, p.UserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级任务不存在")
		case errors.Is(err, ErrNoBackup):
			response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, "该任务无升级前备份，无法回滚")
		case errors.Is(err, ErrInvalidStatus):
			response.Error(w, r, http.StatusConflict, response.CodeInvalidArgument, err.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "rollback", id.String(), "", audits.ResultSuccess, audits.RiskHigh, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

// Cancel 取消定时升级任务：仅 SCHEDULED 状态可取消（转为 CANCELLED）；
// 已进入 PENDING 及以后的任务返回 409「任务已开始，无法取消」。
func (h *Handler) Cancel(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的任务ID")
		return
	}
	if h.canceller == nil {
		response.Error(w, r, http.StatusServiceUnavailable, response.CodeServiceUnavailable, "升级执行服务未配置")
		return
	}
	job, err := h.canceller.Cancel(r.Context(), id, p.UserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "升级任务不存在")
		case errors.Is(err, ErrInvalidStatus):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, err.Error())
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	h.recordAudit(r, p, "cancel", id.String(), "", audits.ResultSuccess, audits.RiskMedium, "")
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"job": job})
}

// recordAudit 写入操作审计。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objID, objName, result, risk, failReason string) {
	if h.auditRecorder != nil {
		h.auditRecorder(r, p, action, objID, objName, result, risk, failReason)
		return
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "upgrades",
		Action:        action,
		ObjectType:    "upgrade",
		ObjectID:      objID,
		ObjectName:    objName,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     risk,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record upgrade audit failed", "action", action, "object_id", objID, "error", err)
	}
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
