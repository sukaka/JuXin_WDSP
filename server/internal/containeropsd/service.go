// service.go containeropsd HTTP 服务：路由、项目/白名单双重校验（fail-closed）、
// 动作任务受理与执行、sidecar 审计行（stdout，不含环境变量/凭据）。
package containeropsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// apiSelfService 管理 API 容器服务名：按 docs/CONTAINER_OPS_DESIGN.md 第 7 节，
// 通道对该服务只允许 restart（Docker restart 策略自动拉起），禁止 stop/update
// 切断操作会话；API 自身版本更新走宿主机升级执行器通道。
const apiSelfService = "api"

// 请求体上限（字节）
const maxRequestBody = 64 * 1024

type queuedActionJob struct {
	jobID    string
	delaySec int
}

// Service 是 containeropsd 核心服务。
type Service struct {
	cfg         Config
	docker      *DockerClient
	jobs        *jobStore
	logger      *slog.Logger
	jobQueue    chan queuedActionJob
	workersOnce sync.Once

	stopTimeoutSec int           // stop/restart 的 SIGKILL 前等待秒数（默认 10）
	maxDelaySec    int           // delay_seconds 上限（默认 300）
	jobTimeout     time.Duration // 单个任务执行超时
	healthTimeout  time.Duration // 更新后健康等待超时
	healthInterval time.Duration // 健康等待轮询间隔
	settleWait     time.Duration // 无健康检查容器的稳定运行窗口
}

// NewService 创建服务。results 目录固定在 socket 同级 results/（与管理面共享卷约定一致）。
func NewService(cfg Config, dc *DockerClient, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	jobs, err := newJobStore(filepath.Join(filepath.Dir(cfg.SocketPath), "results"))
	if err != nil {
		return nil, err
	}
	return &Service{
		cfg:            cfg,
		docker:         dc,
		jobs:           jobs,
		logger:         logger,
		jobQueue:       make(chan queuedActionJob, defaultMaxActiveJobs),
		stopTimeoutSec: 10,
		maxDelaySec:    300,
		jobTimeout:     10 * time.Minute,
		healthTimeout:  60 * time.Second,
		healthInterval: time.Second,
		settleWait:     2 * time.Second,
	}, nil
}

// apiError 结构化错误响应。
type apiError struct {
	Status  int
	Code    string
	Message string
}

func (e *apiError) Error() string { return e.Message }

func errf(status int, code, format string, args ...interface{}) *apiError {
	return &apiError{Status: status, Code: code, Message: fmt.Sprintf(format, args...)}
}

// writeError 输出结构化错误并返回（供 handler 直接 return）。
func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		// Engine 错误归类映射
		var unreachable *EngineUnreachable
		switch {
		case errors.As(err, &unreachable):
			ae = errf(http.StatusServiceUnavailable, "UNAVAILABLE", "Docker Engine 不可用")
		case IsNotFound(err):
			ae = errf(http.StatusNotFound, "CONTAINER_NOT_FOUND", "目标容器不存在")
		default:
			var ee *EngineError
			if errors.As(err, &ee) {
				ae = errf(http.StatusBadGateway, "DOCKER_ERROR", "Docker 操作失败: %s", ee.Message)
			} else {
				ae = errf(http.StatusInternalServerError, "INTERNAL_ERROR", "内部错误")
			}
		}
	}
	writeJSON(w, ae.Status, map[string]interface{}{
		"error": map[string]string{"code": ae.Code, "message": ae.Message},
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// statusRecorder 捕获响应状态码用于审计行。
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Handler 返回 HTTP 路由（含审计行与 panic 兜底）。
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/containers", s.op("list", s.handleListContainers))
	mux.HandleFunc("GET /v1/containers/{service}/logs", s.op("logs", s.handleLogs))
	mux.HandleFunc("POST /v1/containers/{service}/actions", s.op("action", s.handleSubmitAction))
	mux.HandleFunc("GET /v1/actions/{job_id}", s.op("action_status", s.handleGetAction))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("containeropsd handler panic", "path", r.URL.Path, "panic", rec)
				writeError(w, errf(http.StatusInternalServerError, "INTERNAL_ERROR", "内部错误"))
			}
		}()
		mux.ServeHTTP(w, r)
	})
}

// op 包装一个业务 handler：记录 sidecar 审计行（时间、动作、目标服务、结果、耗时）。
// 审计行落 stdout 由 Docker 日志驱动采集，绝不含环境变量值与凭据。
func (s *Service) op(name string, h func(w http.ResponseWriter, r *http.Request)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		h(rec, r)
		s.logger.Info("containerops",
			"op", name,
			"service", r.PathValue("service"),
			"job_id", r.PathValue("job_id"),
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}
}

// requireConfigured 项目未显式配置时 fail-closed。
func (s *Service) requireConfigured() error {
	if s.cfg.Project == "" {
		return errf(http.StatusServiceUnavailable, "PROJECT_NOT_CONFIGURED",
			"未配置 "+EnvProject+"，容器运维通道不可用")
	}
	return nil
}

// requireWhitelisted 校验服务在白名单内（白名单为空时拒绝一切目标并给出明确错误）。
func (s *Service) requireWhitelisted(service string) error {
	if !ValidServiceName(service) {
		return errf(http.StatusBadRequest, "INVALID_ARGUMENT", "服务名格式不合法")
	}
	if !s.cfg.AllowedServices[service] {
		return errf(http.StatusForbidden, "SERVICE_NOT_ALLOWED",
			"服务 %q 未纳入 "+EnvAllowedServices+" 白名单", service)
	}
	return nil
}

// resolveContainer 双重校验后解析服务到容器：项目标签过滤 + 服务白名单。
// 同一服务多实例时优先取运行中的容器（其次按名称字典序取第一个，保证确定性）。
func (s *Service) resolveContainer(ctx context.Context, service string) (*ContainerSummary, error) {
	if err := s.requireWhitelisted(service); err != nil {
		return nil, err
	}
	list, err := s.docker.ListContainers(ctx, s.cfg.Project)
	if err != nil {
		return nil, err
	}
	var matched []ContainerSummary
	for _, c := range list {
		if c.Labels[LabelService] == service {
			matched = append(matched, c)
		}
	}
	if len(matched) == 0 {
		return nil, errf(http.StatusNotFound, "CONTAINER_NOT_FOUND",
			"项目 %q 中不存在服务 %q 的容器", s.cfg.Project, service)
	}
	sort.Slice(matched, func(i, j int) bool {
		if (matched[i].State == "running") != (matched[j].State == "running") {
			return matched[i].State == "running"
		}
		return matched[i].Name() < matched[j].Name()
	})
	return &matched[0], nil
}

// resolveInspect 解析服务并读取容器完整信息。
func (s *Service) resolveInspect(ctx context.Context, service string) (*ContainerInspect, error) {
	summary, err := s.resolveContainer(ctx, service)
	if err != nil {
		return nil, err
	}
	return s.docker.InspectContainer(ctx, summary.ID)
}

// containerView 是列表项响应（白名单字段，绝不包含环境变量值）。
type containerView struct {
	Service      string `json:"service"`
	Project      string `json:"project"`
	ID           string `json:"id"`
	Name         string `json:"name"`
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	State        string `json:"state"`
	Status       string `json:"status"`
	Health       string `json:"health"`
	Running      bool   `json:"running"`
	RestartCount int    `json:"restart_count"`
	StartedAt    string `json:"started_at"`
}

// handleListContainers GET /v1/containers
func (s *Service) handleListContainers(w http.ResponseWriter, r *http.Request) {
	if err := s.requireConfigured(); err != nil {
		writeError(w, err)
		return
	}
	list, err := s.docker.ListContainers(r.Context(), s.cfg.Project)
	if err != nil {
		writeError(w, err)
		return
	}
	views := make([]containerView, 0, len(list))
	for _, c := range list {
		service := c.Labels[LabelService]
		if !s.cfg.AllowedServices[service] {
			continue
		}
		view := containerView{
			Service: service,
			Project: c.Labels[LabelProject],
			ID:      c.ID,
			Name:    c.Name(),
			Image:   c.Image,
			ImageID: c.ImageID,
			State:   c.State,
			Status:  c.Status,
			Running: c.State == "running",
		}
		// inspect 补充健康/重启计数/启动时间；容器在两次调用间消失时降级为列表字段
		if inspect, err := s.docker.InspectContainer(r.Context(), c.ID); err == nil {
			if inspect.State.Health != nil {
				view.Health = inspect.State.Health.Status
			}
			view.RestartCount = inspect.RestartCount
			if !strings.HasPrefix(inspect.State.StartedAt, "0001-01-01") {
				view.StartedAt = inspect.State.StartedAt
			}
		} else {
			s.logger.Warn("inspect 容器失败，列表降级为基础字段", "container", c.ID[:minInt(12, len(c.ID))], "error", err)
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool { return views[i].Service < views[j].Service })
	writeJSON(w, http.StatusOK, map[string]interface{}{"containers": views})
}

// handleLogs GET /v1/containers/{service}/logs?tail=N&since=UNIX_SECONDS
func (s *Service) handleLogs(w http.ResponseWriter, r *http.Request) {
	if err := s.requireConfigured(); err != nil {
		writeError(w, err)
		return
	}
	service := r.PathValue("service")
	tail := DefaultTail
	if raw := r.URL.Query().Get("tail"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT", "tail 必须为非负整数"))
			return
		}
		tail = clampTail(n)
	}
	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT", "since 必须为非负 Unix 秒"))
			return
		}
		since = n
	}
	inspect, err := s.resolveInspect(r.Context(), service)
	if err != nil {
		writeError(w, err)
		return
	}
	stream, err := s.docker.ContainerLogs(r.Context(), inspect.ID, tail, since)
	if err != nil {
		writeError(w, err)
		return
	}
	defer func() { _ = stream.Close() }()
	lines, truncated, nextSince, err := ParseLogStream(stream, inspect.TTY(), MaxLogBytes)
	if err != nil {
		writeError(w, errf(http.StatusBadGateway, "DOCKER_ERROR", "读取日志失败: %v", err))
		return
	}
	if nextSince == 0 {
		nextSince = since
	}
	writeJSON(w, http.StatusOK, LogsResult{
		Service:   service,
		Lines:     lines,
		Truncated: truncated,
		NextSince: nextSince,
	})
}

// actionRequest 是动作受理请求体。
type actionRequest struct {
	Action       string `json:"action"`
	DelaySeconds int    `json:"delay_seconds"`
}

// handleSubmitAction POST /v1/containers/{service}/actions
func (s *Service) handleSubmitAction(w http.ResponseWriter, r *http.Request) {
	if err := s.requireConfigured(); err != nil {
		writeError(w, err)
		return
	}
	service := r.PathValue("service")
	var req actionRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT", "请求体必须为合法 JSON"))
		return
	}
	switch req.Action {
	case ActionStart, ActionStop, ActionRestart, ActionUpdate:
	default:
		writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT",
			"不支持的动作 %q（允许 start|stop|restart|update）", req.Action))
		return
	}
	// API 自停保护：api 服务只允许 restart（设计文档第 7 节）
	if service == apiSelfService && req.Action != ActionRestart {
		writeError(w, errf(http.StatusForbidden, "ACTION_NOT_ALLOWED",
			"服务 %q 仅允许 restart（API 自停保护），版本更新请走升级执行器通道", service))
		return
	}
	if req.DelaySeconds < 0 {
		writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT", "delay_seconds 不能为负"))
		return
	}
	if req.DelaySeconds > s.maxDelaySec {
		req.DelaySeconds = s.maxDelaySec
	}
	// 受理前先行解析（fail-fast 404/403）；执行时仍会重新解析
	if _, err := s.resolveContainer(r.Context(), service); err != nil {
		writeError(w, err)
		return
	}
	job, err := s.jobs.create(service, req.Action)
	if err != nil {
		if errors.Is(err, errJobQueueFull) || errors.Is(err, errJobStoreFull) {
			w.Header().Set("Retry-After", "1")
			writeError(w, errf(http.StatusTooManyRequests, "JOB_QUEUE_FULL", "活动任务数已达上限，请稍后重试"))
			return
		}
		s.logger.Error("创建运维任务失败", "service", service, "action", req.Action, "error", err)
		writeError(w, errf(http.StatusInternalServerError, "INTERNAL_ERROR", "创建任务失败"))
		return
	}
	s.workersOnce.Do(s.startJobWorkers)
	// create 已预留活动名额，队列容量等于活动任务上限，因此此处无需新建 goroutine 或无限等待。
	s.jobQueue <- queuedActionJob{jobID: job.JobID, delaySec: req.DelaySeconds}
	writeJSON(w, http.StatusAccepted, job)
}

// handleGetAction GET /v1/actions/{job_id}
func (s *Service) handleGetAction(w http.ResponseWriter, r *http.Request) {
	if err := s.requireConfigured(); err != nil {
		writeError(w, err)
		return
	}
	jobID := r.PathValue("job_id")
	if !ValidJobID(jobID) {
		writeError(w, errf(http.StatusBadRequest, "INVALID_ARGUMENT", "任务 ID 格式不合法"))
		return
	}
	job, ok := s.jobs.get(jobID)
	if !ok {
		writeError(w, errf(http.StatusNotFound, "JOB_NOT_FOUND", "任务不存在"))
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (s *Service) startJobWorkers() {
	for i := 0; i < jobWorkerCount; i++ {
		go func() {
			for queued := range s.jobQueue {
				s.runJob(queued.jobID, queued.delaySec)
			}
		}()
	}
}

// runJob 异步执行动作任务：延迟 → RUNNING → 按服务串行执行 → SUCCESS/FAILED 落盘。
func (s *Service) runJob(jobID string, delaySec int) {
	defer s.jobs.done(jobID)
	job, ok := s.jobs.get(jobID)
	if !ok {
		s.logger.Error("运维任务在执行前丢失", "job_id", jobID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.jobTimeout)
	defer cancel()
	if delaySec > 0 {
		timer := time.NewTimer(time.Duration(delaySec) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			if err := s.jobs.transition(jobID, JobFailed, "任务等待执行超时"); err != nil {
				s.logger.Error("持久化超时任务结果失败", "job_id", jobID, "error", err)
			}
			return
		case <-timer.C:
		}
	}
	if err := s.jobs.transition(jobID, JobRunning, ""); err != nil {
		s.logger.Error("持久化运维任务运行状态失败，动作未执行",
			"job_id", job.JobID, "service", job.Service, "action", job.Action, "error", err)
		if failErr := s.jobs.transition(jobID, JobFailed, "任务状态持久化失败，动作未执行"); failErr != nil {
			s.logger.Error("持久化运维任务失败状态失败", "job_id", job.JobID, "error", failErr)
		}
		return
	}
	mu := s.jobs.lockFor(job.Service)
	mu.Lock()
	defer mu.Unlock()

	err := s.executeAction(ctx, job)
	status, message := JobSuccess, "执行成功"
	switch {
	case err == nil:
	case errors.Is(err, errUpdateNoop):
		message = "目标镜像与当前运行一致，无需更新"
	default:
		status = JobFailed
		message = err.Error()
		if len(message) > 300 {
			message = message[:300] + "…"
		}
		s.logger.Warn("运维动作执行失败", "job_id", job.JobID, "service", job.Service, "action", job.Action, "error", message)
	}
	if err := s.jobs.transition(jobID, status, message); err != nil {
		s.logger.Error("持久化运维任务结果失败",
			"job_id", job.JobID, "service", job.Service, "action", job.Action, "result", status, "error", err)
	}
}

// executeAction 按动作类型分派执行（执行时重新解析容器，目标可能已在受理后变化）。
func (s *Service) executeAction(ctx context.Context, job *ActionJob) error {
	if job.Action == ActionUpdate {
		return s.executeUpdate(ctx, job)
	}
	inspect, err := s.resolveInspect(ctx, job.Service)
	if err != nil {
		return err
	}
	switch job.Action {
	case ActionStart:
		if err := s.docker.StartContainer(ctx, inspect.ID); err != nil {
			return fmt.Errorf("启动容器失败: %w", err)
		}
	case ActionStop:
		if err := s.docker.StopContainer(ctx, inspect.ID, s.stopTimeoutSec); err != nil {
			return fmt.Errorf("停止容器失败: %w", err)
		}
	case ActionRestart:
		if err := s.docker.RestartContainer(ctx, inspect.ID, s.stopTimeoutSec); err != nil {
			return fmt.Errorf("重启容器失败: %w", err)
		}
	default:
		return fmt.Errorf("不支持的动作 %q", job.Action)
	}
	return nil
}

// Run 监听 Unix Socket 并服务直到 ctx 取消（优雅关停，退出前移除 socket 文件）。
func (s *Service) Run(ctx context.Context) error {
	sockPath := s.cfg.SocketPath
	if err := os.MkdirAll(filepath.Dir(sockPath), 0o750); err != nil {
		return fmt.Errorf("创建 socket 目录失败: %w", err)
	}
	// 清理陈旧 socket：仅删除 socket 类型文件，其他类型拒绝覆盖（防误删）
	if fi, err := os.Stat(sockPath); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("socket 路径已被非 socket 文件占用: %s", sockPath)
		}
		if err := os.Remove(sockPath); err != nil {
			return fmt.Errorf("清理陈旧 socket 失败: %w", err)
		}
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return fmt.Errorf("监听 socket 失败: %w", err)
	}
	// 0660：共享卷内由同组 API 容器访问（设计文档第 2 节）
	if err := os.Chmod(sockPath, 0o660); err != nil {
		_ = ln.Close()
		return fmt.Errorf("设置 socket 权限失败: %w", err)
	}

	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       35 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	s.logger.Info("containeropsd 已监听", "socket", sockPath, "project", s.cfg.Project,
		"allowed_services", len(s.cfg.AllowedServices))
	err = srv.Serve(ln)
	_ = os.Remove(sockPath)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
