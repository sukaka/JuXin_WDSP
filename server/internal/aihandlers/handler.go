// Package aihandlers 阶段7 AI 安全运营中心 HTTP 接口层：
// 会话与流式对话、一次性分析、草稿、模型/Agent/Tool/Prompt/记忆/审计/用量/评估管理。
// 所有接口强制认证 + 权限点校验；会话与记忆严格属主隔离；模型密钥加密存储且任何响应不得回传。
package aihandlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jiuzhang-waf/server/internal/aiaudit"
	"github.com/jiuzhang-waf/server/internal/aicost"
	"github.com/jiuzhang-waf/server/internal/aimemory"
	"github.com/jiuzhang-waf/server/internal/aimodel"
	"github.com/jiuzhang-waf/server/internal/ainoise"
	"github.com/jiuzhang-waf/server/internal/aiorchestrator"
	"github.com/jiuzhang-waf/server/internal/aiprompts"
	"github.com/jiuzhang-waf/server/internal/aitools"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
	"github.com/jiuzhang-waf/server/internal/settings"
)

// defaultModelCode 路由档位缺省模型（本地 Ollama 小模型，配置缺失不致命）。
const defaultModelCode = "qwen2.5:3b"

// Deps 阶段7接口层集中依赖。
type Deps struct {
	DB       *pgxpool.Pool
	Orch     *aiorchestrator.Orchestrator
	Sessions *aiorchestrator.SessionStore
	Gateway  *aimodel.Gateway
	Models   *aimodel.Store
	Tools    *aitools.Registry
	Drafts   *aitools.DraftStore
	Audit    *aiaudit.Service
	Cost     *aicost.Recorder
	Memories *aimemory.Store
	Prompts  *aiprompts.Store
	Settings *settings.Service
	// 阶段7 增量：AI 自动降噪（簇仓储 + 后台扫描工人；未装配时端点降级 503）
	Noise       ainoise.Store
	NoiseWorker *ainoise.Worker
	// AgentCodes 代码 registry 中实际注册的 Agent code（列表 in_registry 标记用）
	AgentCodes map[string]bool
	// chat 运行态（停止信号用）
	chat *chatRuntime
}

// NewDeps 创建接口层依赖（初始化内部运行态）。
func NewDeps(d Deps) *Deps {
	d.chat = newChatRuntime()
	return &d
}

// RegisterRoutes 注册阶段7全部 AI 路由（权限在路由层按权限点强制校验）。
func (d *Deps) RegisterRoutes(mux *http.ServeMux, authChain func(http.Handler) http.Handler) {
	rp := middleware.RequirePermission

	// ---- 会话与消息（属主隔离在 handler 内强制）----
	mux.Handle("GET /api/v1/ai/sessions", authChain(rp("ai.sessions.read_own")(http.HandlerFunc(d.SessionList))))
	mux.Handle("POST /api/v1/ai/sessions", authChain(rp("ai.chat.use")(http.HandlerFunc(d.SessionCreate))))
	mux.Handle("GET /api/v1/ai/sessions/{id}", authChain(rp("ai.sessions.read_own")(http.HandlerFunc(d.SessionGet))))
	mux.Handle("PATCH /api/v1/ai/sessions/{id}", authChain(rp("ai.chat.use")(http.HandlerFunc(d.SessionPatch))))
	mux.Handle("DELETE /api/v1/ai/sessions/{id}", authChain(rp("ai.sessions.delete_own")(http.HandlerFunc(d.SessionDelete))))
	mux.Handle("POST /api/v1/ai/sessions/{id}/archive", authChain(rp("ai.chat.use")(http.HandlerFunc(d.SessionArchive))))
	mux.Handle("GET /api/v1/ai/sessions/{id}/messages", authChain(rp("ai.sessions.read_own")(http.HandlerFunc(d.MessageList))))
	mux.Handle("POST /api/v1/ai/sessions/{id}/messages", authChain(rp("ai.chat.use")(http.HandlerFunc(d.MessageSend))))
	mux.Handle("POST /api/v1/ai/sessions/{id}/stop", authChain(rp("ai.chat.use")(http.HandlerFunc(d.MessageStop))))
	mux.Handle("POST /api/v1/ai/sessions/{id}/retry", authChain(rp("ai.chat.use")(http.HandlerFunc(d.MessageRetry))))
	mux.Handle("POST /api/v1/ai/sessions/{id}/continue", authChain(rp("ai.chat.use")(http.HandlerFunc(d.MessageContinue))))
	mux.Handle("POST /api/v1/ai/messages/{id}/feedback", authChain(rp("ai.chat.use")(http.HandlerFunc(d.MessageFeedback))))

	// ---- 任务记录（仅本人）----
	mux.Handle("GET /api/v1/ai/tasks", authChain(rp("ai.sessions.read_own")(http.HandlerFunc(d.TaskList))))
	mux.Handle("GET /api/v1/ai/tasks/{id}", authChain(rp("ai.sessions.read_own")(http.HandlerFunc(d.TaskGet))))

	// ---- 一次性 AI 分析 ----
	mux.Handle("POST /api/v1/ai/analyze/event", authChain(rp("ai.event_analysis.use")(http.HandlerFunc(d.AnalyzeEvent))))
	mux.Handle("POST /api/v1/ai/analyze/false-positive", authChain(rp("ai.false_positive_analysis.use")(http.HandlerFunc(d.AnalyzeFalsePositive))))
	mux.Handle("POST /api/v1/ai/analyze/attack-profile", authChain(rp("ai.attack_profile.use")(http.HandlerFunc(d.AnalyzeAttackProfile))))
	mux.Handle("POST /api/v1/ai/analyze/attack-chain", authChain(rp("ai.attack_chain.use")(http.HandlerFunc(d.AnalyzeAttackChain))))
	mux.Handle("POST /api/v1/ai/analyze/policy-recommendation", authChain(rp("ai.policy_recommendation.use")(http.HandlerFunc(d.AnalyzePolicyRecommendation))))
	mux.Handle("POST /api/v1/ai/analyze/what-if", authChain(rp("ai.what_if.use")(http.HandlerFunc(d.AnalyzeWhatIf))))
	mux.Handle("POST /api/v1/ai/analyze/root-cause", authChain(rp("ai.root_cause.use")(http.HandlerFunc(d.AnalyzeRootCause))))
	mux.Handle("POST /api/v1/ai/analyze/report-summary", authChain(rp("ai.report_summary.use")(http.HandlerFunc(d.AnalyzeReportSummary))))

	// ---- 草稿与推荐（任一草稿权限可读；创建/接受/拒绝同权限）----
	draftPerm := requireAnyPerm("ai.draft.exception", "ai.draft.blacklist", "ai.draft.cc_policy", "ai.draft.custom_rule")
	mux.Handle("GET /api/v1/ai/drafts", authChain(draftPerm(http.HandlerFunc(d.DraftList))))
	mux.Handle("GET /api/v1/ai/drafts/{id}", authChain(draftPerm(http.HandlerFunc(d.DraftGet))))
	mux.Handle("POST /api/v1/ai/drafts/{id}/discard", authChain(draftPerm(http.HandlerFunc(d.DraftDiscard))))
	mux.Handle("POST /api/v1/ai/drafts/{type}", authChain(draftPerm(http.HandlerFunc(d.DraftCreateByTool))))
	mux.Handle("GET /api/v1/ai/recommendations", authChain(draftPerm(http.HandlerFunc(d.DraftList))))
	mux.Handle("GET /api/v1/ai/recommendations/{id}", authChain(draftPerm(http.HandlerFunc(d.DraftGet))))
	mux.Handle("POST /api/v1/ai/recommendations/{id}/accept", authChain(draftPerm(http.HandlerFunc(d.RecommendationAccept))))
	mux.Handle("POST /api/v1/ai/recommendations/{id}/reject", authChain(draftPerm(http.HandlerFunc(d.RecommendationReject))))

	// ---- 模型供应商 / 模型 / 路由档位 ----
	mux.Handle("GET /api/v1/ai/models/providers", authChain(rp("ai.models.read")(http.HandlerFunc(d.ProviderList))))
	mux.Handle("POST /api/v1/ai/models/providers", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ProviderCreate))))
	mux.Handle("PATCH /api/v1/ai/models/providers/{id}", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ProviderPatch))))
	mux.Handle("POST /api/v1/ai/models/providers/{id}/rotate-key", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ProviderRotateKey))))
	mux.Handle("DELETE /api/v1/ai/models/providers/{id}", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ProviderDelete))))
	mux.Handle("GET /api/v1/ai/models", authChain(rp("ai.models.read")(http.HandlerFunc(d.ModelList))))
	mux.Handle("POST /api/v1/ai/models", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelCreate))))
	mux.Handle("PUT /api/v1/ai/models/{id}", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelUpdate))))
	mux.Handle("DELETE /api/v1/ai/models/{id}", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelDelete))))
	mux.Handle("POST /api/v1/ai/models/{id}/enable", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelEnable))))
	mux.Handle("POST /api/v1/ai/models/{id}/disable", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelDisable))))
	// 连通性探测不改配置：与 trusted_proxies/test、rate_limits/test 一致，允许只读权限查看健康
	mux.Handle("POST /api/v1/ai/models/{id}/test", authChain(rp("ai.models.read")(http.HandlerFunc(d.ModelTest))))
	mux.Handle("GET /api/v1/ai/models/routes", authChain(rp("ai.models.read")(http.HandlerFunc(d.ModelRoutesGet))))
	mux.Handle("PUT /api/v1/ai/models/routes", authChain(rp("ai.models.manage")(http.HandlerFunc(d.ModelRoutesPut))))

	// ---- Agent / Tool 管理 ----
	mux.Handle("GET /api/v1/ai/agents", authChain(rp("ai.agents.read")(http.HandlerFunc(d.AgentList))))
	mux.Handle("PATCH /api/v1/ai/agents/{id}", authChain(rp("ai.agents.manage")(http.HandlerFunc(d.AgentPatch))))
	mux.Handle("POST /api/v1/ai/agents/{id}/test", authChain(rp("ai.agents.read")(http.HandlerFunc(d.AgentTest))))
	mux.Handle("GET /api/v1/ai/tools", authChain(rp("ai.tools.read")(http.HandlerFunc(d.ToolList))))
	mux.Handle("PATCH /api/v1/ai/tools/{id}", authChain(rp("ai.tools.manage")(http.HandlerFunc(d.ToolPatch))))
	mux.Handle("POST /api/v1/ai/tools/{id}/test", authChain(rp("ai.tools.read")(http.HandlerFunc(d.ToolTest))))

	// ---- Prompt 管理 ----
	mux.Handle("GET /api/v1/ai/prompts", authChain(rp("ai.prompts.read")(http.HandlerFunc(d.PromptList))))
	mux.Handle("POST /api/v1/ai/prompts", authChain(rp("ai.prompts.create")(http.HandlerFunc(d.PromptCreate))))
	mux.Handle("GET /api/v1/ai/prompts/{id}/versions", authChain(rp("ai.prompts.read")(http.HandlerFunc(d.PromptVersionList))))
	mux.Handle("POST /api/v1/ai/prompts/{id}/versions", authChain(rp("ai.prompts.create")(http.HandlerFunc(d.PromptVersionCreate))))
	mux.Handle("GET /api/v1/ai/prompts/{id}/diff", authChain(rp("ai.prompts.read")(http.HandlerFunc(d.PromptDiff))))
	mux.Handle("POST /api/v1/ai/prompts/versions/{versionId}/test", authChain(rp("ai.prompts.test")(http.HandlerFunc(d.PromptVersionTest))))
	mux.Handle("POST /api/v1/ai/prompts/{id}/publish", authChain(rp("ai.prompts.publish")(http.HandlerFunc(d.PromptPublish))))
	mux.Handle("POST /api/v1/ai/prompts/{id}/rollback", authChain(rp("ai.prompts.rollback")(http.HandlerFunc(d.PromptRollback))))

	// ---- 记忆（属主隔离在 handler 内强制）----
	mux.Handle("GET /api/v1/ai/memories", authChain(rp("ai.memories.read_own")(http.HandlerFunc(d.MemoryList))))
	mux.Handle("POST /api/v1/ai/memories", authChain(rp("ai.memories.manage_own")(http.HandlerFunc(d.MemoryCreate))))
	mux.Handle("PUT /api/v1/ai/memories/{id}", authChain(rp("ai.memories.manage_own")(http.HandlerFunc(d.MemoryUpdate))))
	mux.Handle("DELETE /api/v1/ai/memories/{id}", authChain(rp("ai.memories.manage_own")(http.HandlerFunc(d.MemoryDelete))))
	mux.Handle("POST /api/v1/ai/memories/{id}/disable", authChain(rp("ai.memories.manage_own")(http.HandlerFunc(d.MemoryDisable))))

	// ---- AI 审计 ----
	mux.Handle("GET /api/v1/ai/audits", authChain(rp("ai.audits.read")(http.HandlerFunc(d.AuditList))))
	mux.Handle("POST /api/v1/ai/audits/verify", authChain(rp("ai.audits.read")(http.HandlerFunc(d.AuditVerify))))

	// ---- 用量与成本 ----
	mux.Handle("GET /api/v1/ai/usage/overview", authChain(rp("ai.usage.read")(http.HandlerFunc(d.UsageOverview))))
	mux.Handle("GET /api/v1/ai/usage/by-user", authChain(rp("ai.usage.read")(http.HandlerFunc(d.UsageByUser))))
	mux.Handle("GET /api/v1/ai/usage/by-agent", authChain(rp("ai.usage.read")(http.HandlerFunc(d.UsageByAgent))))
	mux.Handle("GET /api/v1/ai/usage/by-task", authChain(rp("ai.usage.read")(http.HandlerFunc(d.UsageByTask))))

	// ---- 评估（无独立 read 权限点：评估执行者或用量/审计只读者可看）----
	evalRead := requireAnyPerm("ai.evaluations.run", "ai.usage.read", "ai.audits.read")
	mux.Handle("GET /api/v1/ai/evaluation-sets", authChain(evalRead(http.HandlerFunc(d.EvalSetList))))
	mux.Handle("POST /api/v1/ai/evaluation-sets", authChain(rp("ai.evaluations.run")(http.HandlerFunc(d.EvalSetCreate))))
	mux.Handle("GET /api/v1/ai/evaluation-runs", authChain(evalRead(http.HandlerFunc(d.EvalRunList))))
	mux.Handle("POST /api/v1/ai/evaluations/run", authChain(rp("ai.evaluations.run")(http.HandlerFunc(d.EvalRun))))

	// ---- AI 自动降噪（簇查询/统计/状态流转 use；手动扫描与设置 manage）----
	mux.Handle("GET /api/v1/ai/noise/clusters", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseClusterList))))
	mux.Handle("GET /api/v1/ai/noise/clusters/{id}", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseClusterGet))))
	mux.Handle("POST /api/v1/ai/noise/clusters/{id}/suppress", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseClusterSuppress))))
	mux.Handle("POST /api/v1/ai/noise/clusters/{id}/resolve", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseClusterResolve))))
	mux.Handle("GET /api/v1/ai/noise/stats", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseStats))))
	mux.Handle("POST /api/v1/ai/noise/sweeps", authChain(rp("ai.noise_reduction.manage")(http.HandlerFunc(d.NoiseSweepTrigger))))
	mux.Handle("GET /api/v1/ai/noise/sweeps", authChain(rp("ai.noise_reduction.use")(http.HandlerFunc(d.NoiseSweepList))))
	mux.Handle("GET /api/v1/ai/noise/settings", authChain(rp("ai.noise_reduction.manage")(http.HandlerFunc(d.NoiseSettingsGet))))
	mux.Handle("PUT /api/v1/ai/noise/settings", authChain(rp("ai.noise_reduction.manage")(http.HandlerFunc(d.NoiseSettingsPut))))
}

// requireAnyPerm 任一权限满足即放行（多角色只读/草稿聚合场景）。
func requireAnyPerm(perms ...string) func(http.Handler) http.Handler {
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

// ---------- 共享工具 ----------

// chatRuntime 会话级运行态（停止信号；同一会话同时只跑一个任务，新任务取代旧任务）。
type chatRuntime struct {
	mu      sync.Mutex
	seq     int64
	running map[uuid.UUID]chatRun
}

type chatRun struct {
	seq    int64
	cancel context.CancelFunc
}

func newChatRuntime() *chatRuntime {
	return &chatRuntime{running: map[uuid.UUID]chatRun{}}
}

// register 注册运行中的任务（同会话已有任务先取消），返回序号供注销匹配。
func (c *chatRuntime) register(id uuid.UUID, cancel context.CancelFunc) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.running[id]; ok {
		old.cancel()
	}
	c.seq++
	c.running[id] = chatRun{seq: c.seq, cancel: cancel}
	return c.seq
}

// unregister 注销任务（仅匹配序号，避免旧任务注销新任务）。
func (c *chatRuntime) unregister(id uuid.UUID, seq int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.running[id]; ok && cur.seq == seq {
		delete(c.running, id)
	}
}

// stop 取消会话正在运行的任务。
func (c *chatRuntime) stop(id uuid.UUID) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	run, ok := c.running[id]
	if ok {
		run.cancel()
	}
	return ok
}

// sseEvent SSE 事件（data: {json}\n\n）。
type sseEvent struct {
	Type    string      `json:"type"`
	Text    string      `json:"text,omitempty"`
	Payload interface{} `json:"payload,omitempty"`
}

// writeSSE 写出一条 SSE 事件并立即 flush。
func writeSSE(w http.ResponseWriter, flusher http.Flusher, v sseEvent) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

// decodeJSON 解析请求 JSON（允许空 body，等价 {}）。
func decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	err := response.DecodeJSON(w, r, dst, maxBytes)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// loadOwnedSession 加载会话并强制属主隔离（非属主一律 404，不泄露存在性）。
func (d *Deps) loadOwnedSession(w http.ResponseWriter, r *http.Request) (*aiorchestrator.Session, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的会话ID")
		return nil, false
	}
	sess, err := d.Sessions.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, aiorchestrator.ErrSessionNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "会话不存在")
		} else {
			response.InternalError(w, r, err)
		}
		return nil, false
	}
	p := authz.PrincipalFrom(r.Context())
	if p == nil || sess.UserID != p.UserID {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "会话不存在")
		return nil, false
	}
	return sess, true
}

// recordAIAudit 写 AI 审计（独立短超时 ctx，避免请求取消后丢失；失败只记日志不吞主流程）。
func (d *Deps) recordAIAudit(p *authz.Principal, rec aiaudit.Record) {
	if p == nil || d.Audit == nil {
		return
	}
	rec.UserID = &p.UserID
	rec.Username = p.Username
	rec.RoleCodes = strings.Join(p.Roles, ",")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Audit.Record(ctx, rec); err != nil {
		slog.Error("record ai audit failed", "action", rec.Action, "error", err)
	}
}

// firstRole 取首个角色编码（配额按角色统计用）。
func firstRole(p *authz.Principal) string {
	if len(p.Roles) > 0 {
		return p.Roles[0]
	}
	return ""
}

// trunc 按字符截断。
func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
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

func queryBool(r *http.Request, key string) bool {
	v := strings.ToLower(r.URL.Query().Get(key))
	return v == "true" || v == "1" || v == "yes"
}
