// agents_handler.go APM Agent 控制面管理接口（阶段2 上半；设计 §16.2）。
//
// 全部挂在 APM_ENABLED 开关内、会话 + RBAC 链上（RegisterAgentAdminRoutes 注入 authz）：
//
//	POST /api/v1/apm/agents/enrollment-tokens  创建一次性注册令牌（原文仅本次响应返回）
//	GET  /api/v1/apm/agents                    Agent 列表（展示态含派生 OFFLINE）
//	POST /api/v1/apm/agents/{id}/revoke        撤销 Agent（证书指纹入撤销列表，终态）
//	GET  /api/v1/apm/policies/{scope}          读取当前生效签名策略（global / application:<uuid>）
//	PUT  /api/v1/apm/policies/{scope}          发布新策略版本（版本单调递增、重新签名）
//
// 权限点 apm.agents.manage / apm.settings.manage（迁移 000089 种子，仅 SECURITY_ADMIN）；
// 三个变更接口全部写高风险操作审计，纯 GET 不审计（沿用既有惯例）。
package apm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// 管理面权限点（迁移 000089 种子）。
const (
	PermAgentsManage   = "apm.agents.manage"
	PermSettingsManage = "apm.settings.manage"
)

// 令牌纪律：32 字节随机（hex 64 字符）+ 可识别前缀；只存 SHA-256 摘要；
// 有效期默认 60 分钟，合法区间 5 分钟 ~ 7 天（设计 §12.3：一次性、短有效期）。
const (
	enrollmentTokenPrefix  = "jzapm_"
	tokenRandomBytes       = 32
	defaultTokenTTLMinutes = 60
	minTokenTTLMinutes     = 5
	maxTokenTTLMinutes     = 7 * 24 * 60
)

// environmentSlug 环境标识格式（小写数字/中划线，≤64）。
var environmentSlug = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}[a-z0-9]$|^[a-z0-9]$`)

// auditRecorder 操作审计记录接口（*audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// AgentAdminHandler 控制面管理接口处理器。
type AgentAdminHandler struct {
	store  AgentRepository
	ca     *AgentCA
	cfg    AgentControlConfig
	audits auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	now    func() time.Time
}

// NewAgentAdminHandler 创建管理面处理器。
func NewAgentAdminHandler(store AgentRepository, ca *AgentCA, cfg AgentControlConfig) *AgentAdminHandler {
	return &AgentAdminHandler{store: store, ca: ca, cfg: cfg, now: time.Now}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *AgentAdminHandler) SetAudits(a auditRecorder) *AgentAdminHandler { h.audits = a; return h }

// RegisterAgentAdminRoutes 注册管理面路由（authz = 会话认证 + CSRF + 授权门控链）。
func RegisterAgentAdminRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *AgentAdminHandler) {
	mux.Handle("POST /api/v1/apm/agents/enrollment-tokens",
		authz(middleware.RequirePermission(PermAgentsManage)(http.HandlerFunc(h.CreateEnrollmentToken))))
	mux.Handle("GET /api/v1/apm/agents",
		authz(middleware.RequirePermission(PermAgentsManage)(http.HandlerFunc(h.ListAgents))))
	mux.Handle("POST /api/v1/apm/agents/{id}/revoke",
		authz(middleware.RequirePermission(PermAgentsManage)(http.HandlerFunc(h.RevokeAgent))))
	mux.Handle("GET /api/v1/apm/policies/{scope}",
		authz(middleware.RequirePermission(PermSettingsManage)(http.HandlerFunc(h.GetPolicy))))
	mux.Handle("PUT /api/v1/apm/policies/{scope}",
		authz(middleware.RequirePermission(PermSettingsManage)(http.HandlerFunc(h.PutPolicy))))
}

// ---------- 注册令牌 ----------

// createEnrollmentTokenRequest 创建一次性令牌入参。
type createEnrollmentTokenRequest struct {
	ApplicationID    *uuid.UUID `json:"application_id"`
	Environment      string     `json:"environment"`
	AllowedLanguages []string   `json:"allowed_languages"`
	ExpiresInMinutes *int       `json:"expires_in_minutes"`
	Note             string     `json:"note"`
}

// GenerateEnrollmentToken 生成令牌原文（仅创建响应返回一次；入库只有其 SHA-256 摘要）。
func GenerateEnrollmentToken() (plain, hashHex string, err error) {
	buf := make([]byte, tokenRandomBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	plain = enrollmentTokenPrefix + hex.EncodeToString(buf)
	return plain, HashEnrollmentToken(plain), nil
}

// HashEnrollmentToken 计算令牌 SHA-256 摘要（hex；登记/消费两侧共用口径）。
func HashEnrollmentToken(plain string) string {
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:])
}

// CreateEnrollmentToken POST /api/v1/apm/agents/enrollment-tokens
// （权限 apm.agents.manage，高风险审计；令牌原文只在本响应出现一次）。
func (h *AgentAdminHandler) CreateEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createEnrollmentTokenRequest
	if err := response.DecodeJSON(w, r, &req, 4096); err != nil {
		badRequest(w, r, "请求格式错误")
		return
	}
	env := strings.TrimSpace(req.Environment)
	if env == "" {
		env = "production"
	}
	if !environmentSlug.MatchString(env) {
		badRequest(w, r, "无效的 environment（小写字母/数字/中划线，不超过 64 字符）")
		return
	}
	langs, err := normalizeLanguages(req.AllowedLanguages)
	if err != nil {
		badRequest(w, r, err.Error())
		return
	}
	ttl := defaultTokenTTLMinutes
	if req.ExpiresInMinutes != nil {
		ttl = *req.ExpiresInMinutes
	}
	if ttl < minTokenTTLMinutes || ttl > maxTokenTTLMinutes {
		badRequest(w, r, fmt.Sprintf("expires_in_minutes 须在 %d~%d 分钟之间", minTokenTTLMinutes, maxTokenTTLMinutes))
		return
	}
	note := strings.TrimSpace(req.Note)
	if len(note) > 200 {
		badRequest(w, r, "note 不能超过 200 字符")
		return
	}
	if req.ApplicationID != nil {
		exists, err := h.store.ApplicationExists(r.Context(), *req.ApplicationID)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		if !exists {
			badRequest(w, r, "application_id 指向的应用不存在")
			return
		}
	}
	plain, hash, err := GenerateEnrollmentToken()
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	row := &EnrollmentTokenRow{
		ApplicationID:    req.ApplicationID,
		Environment:      env,
		AllowedLanguages: langs,
		ExpiresAt:        h.now().UTC().Add(time.Duration(ttl) * time.Minute),
		Note:             note,
		CreatedBy:        &p.UserID,
	}
	if err := h.store.CreateEnrollmentToken(r.Context(), row, hash); err != nil {
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(map[string]interface{}{
		"application_id": req.ApplicationID, "environment": env,
		"allowed_languages": langs, "expires_at": row.ExpiresAt.Format(time.RFC3339), "note": note,
	})
	h.recordAudit(r, p, "create", "apm_enrollment_token", row.ID.String(), env,
		"", string(after), audits.ResultSuccess, audits.RiskHigh)
	// 令牌原文仅此一次返回；响应不含摘要之外的任何令牌材料
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"token_id":          row.ID,
		"token":             plain,
		"application_id":    row.ApplicationID,
		"environment":       row.Environment,
		"allowed_languages": row.AllowedLanguages,
		"expires_at":        row.ExpiresAt,
		"note":              "令牌仅此一次返回，请立即复制保存；服务端只保留不可逆摘要",
	})
}

// normalizeLanguages 语言白名单校验 + 去重（空数组 = 不限制）。
func normalizeLanguages(in []string) ([]string, error) {
	out := []string{}
	seen := map[string]bool{}
	for _, l := range in {
		l = strings.ToLower(strings.TrimSpace(l))
		if !ValidateAgentLanguage(l) {
			return nil, fmt.Errorf("无效的 allowed_languages 元素 %q（支持 java/go/dotnet/nodejs/python/php）", l)
		}
		if !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	return out, nil
}

// ---------- Agent 列表与撤销 ----------

// ListAgents GET /api/v1/apm/agents（权限 apm.agents.manage；纯查询不审计）。
// status 过滤按展示态口径（含派生态 OFFLINE）；分页与既有列表同口径（夹紧不报错）。
func (h *AgentAdminHandler) ListAgents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := AgentsFilter{
		Status:   strings.ToUpper(strings.TrimSpace(q.Get("status"))),
		Language: strings.ToLower(strings.TrimSpace(q.Get("language"))),
		Keyword:  strings.TrimSpace(q.Get("keyword")),
	}
	if f.Status != "" {
		switch f.Status {
		case AgentStatusEnrolling, AgentStatusConnectedBaseline, AgentStatusDiagnosing, AgentStatusOffline, AgentStatusRevoked:
		default:
			badRequest(w, r, "无效的 status（支持 ENROLLING/CONNECTED_BASELINE/DIAGNOSING/OFFLINE/REVOKED）")
			return
		}
	}
	if f.Language != "" && !ValidateAgentLanguage(f.Language) {
		badRequest(w, r, "无效的 language")
		return
	}
	if v := strings.TrimSpace(q.Get("application_id")); v != "" {
		appID, err := uuid.Parse(v)
		if err != nil {
			badRequest(w, r, "无效的 application_id")
			return
		}
		f.ApplicationID = &appID
	}
	f.Page, f.PageSize = parsePage(r)
	list, total, err := h.store.ListAgents(r.Context(), f, h.cfg.OfflineAfter, h.now())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, list, total, f.Page, f.PageSize)
}

// revokeAgentRequest 撤销入参（reason 可选，落审计与登记行）。
type revokeAgentRequest struct {
	Reason string `json:"reason"`
}

// RevokeAgent POST /api/v1/apm/agents/{id}/revoke
// （权限 apm.agents.manage，高风险审计；证书指纹入撤销列表，REVOKED 终态不可恢复）。
func (h *AgentAdminHandler) RevokeAgent(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		badRequest(w, r, "无效的 id")
		return
	}
	var req revokeAgentRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := response.DecodeJSON(w, r, &req, 2048); err != nil {
			badRequest(w, r, "请求格式错误")
			return
		}
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 200 {
		badRequest(w, r, "reason 不能超过 200 字符")
		return
	}
	current, err := h.store.GetAgent(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	updated, err := h.store.RevokeAgent(r.Context(), id, reason, h.now())
	if err != nil {
		switch {
		case errors.Is(err, ErrAgentNotFound):
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "Agent 不存在")
		case errors.Is(err, ErrAgentAlreadyRevoked):
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "Agent 已处于撤销状态")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	before, _ := json.Marshal(map[string]interface{}{"status": current.StoredStatus})
	after, _ := json.Marshal(map[string]interface{}{
		"status": AgentStatusRevoked, "reason": reason, "cert_fingerprint": updated.CertFingerprint,
	})
	h.recordAudit(r, p, "revoke", "apm_agent", id.String(),
		fmt.Sprintf("%s/%s", updated.ServiceName, updated.InstanceID),
		string(before), string(after), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, updated)
}

// ---------- 策略 ----------

// GetPolicy GET /api/v1/apm/policies/{scope}（权限 apm.settings.manage；纯查询不审计；
// 无版本返回 404）。
func (h *AgentAdminHandler) GetPolicy(w http.ResponseWriter, r *http.Request) {
	scope := r.PathValue("scope")
	if err := ValidatePolicyScope(scope); err != nil {
		badRequest(w, r, err.Error())
		return
	}
	row, err := h.store.LatestPolicy(r.Context(), scope)
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "该作用域暂无策略版本")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, row.Envelope())
}

// putPolicyRequest 发布策略入参（policy 必填对象；expected_version 乐观并发：
// 声明读取时的当前版本，他人先发新版则 409 拒绝，防丢失更新；expires_in_hours
// 缺省 30 天——§9.2 策略必须带过期时间）。
type putPolicyRequest struct {
	Policy          map[string]interface{} `json:"policy"`
	ExpectedVersion *int64                 `json:"expected_version"`
	ExpiresInHours  *int                   `json:"expires_in_hours"`
}

// maxPolicyBodyBytes 策略请求体上限（64KB，与基数/体积防护口径一致）。
const maxPolicyBodyBytes = 65536

// PutPolicy PUT /api/v1/apm/policies/{scope}
// （权限 apm.settings.manage，高风险审计；版本由服务端取当前 max+1 单调递增，
// 落库前重新签名——签名覆盖 scope/version/签发与过期时间/策略正文）。
func (h *AgentAdminHandler) PutPolicy(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	scope := r.PathValue("scope")
	if err := ValidatePolicyScope(scope); err != nil {
		badRequest(w, r, err.Error())
		return
	}
	var req putPolicyRequest
	if err := response.DecodeJSON(w, r, &req, maxPolicyBodyBytes); err != nil {
		badRequest(w, r, "请求格式错误或策略体过大")
		return
	}
	if err := ValidateBaselinePolicy(req.Policy); err != nil {
		badRequest(w, r, err.Error())
		return
	}
	validity := h.cfg.PolicyValidity
	if req.ExpiresInHours != nil {
		if *req.ExpiresInHours < 1 || *req.ExpiresInHours > 24*90 {
			badRequest(w, r, "expires_in_hours 须在 1~2160 小时之间")
			return
		}
		validity = time.Duration(*req.ExpiresInHours) * time.Hour
	}
	// 应用级作用域要求应用存在（防指向悬空应用的策略堆积）
	if strings.HasPrefix(scope, policyScopeApplicationPrefix) {
		appID, _ := uuid.Parse(strings.TrimPrefix(scope, policyScopeApplicationPrefix))
		exists, err := h.store.ApplicationExists(r.Context(), appID)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		if !exists {
			badRequest(w, r, "application 作用域指向的应用不存在")
			return
		}
	}
	issuedAt := h.now().UTC()
	env := &PolicyEnvelope{
		Scope: scope, KeyID: PolicySignKeyID,
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(validity), Policy: req.Policy,
	}
	current, err := h.store.LatestPolicy(r.Context(), scope)
	if err != nil && !errors.Is(err, ErrPolicyNotFound) {
		response.InternalError(w, r, err)
		return
	}
	var currentVersion int64
	if current != nil {
		currentVersion = current.Version
	}
	// 客户端声明读取基线且已过期 → 早拒绝（不落库不签名）
	if req.ExpectedVersion != nil && *req.ExpectedVersion != currentVersion {
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
			fmt.Sprintf("策略已被他人更新（当前版本 %d），请刷新后重试", currentVersion))
		return
	}
	env.Version = currentVersion + 1
	// 版本须先于签名确定（版本号在签名覆盖范围内）；仓储在事务+作用域咨询锁内复核
	// expectedVersion=当前版本——并发下他人先发新版则冲突拒绝，保证落库版本与签名
	// 覆盖的版本号严格一致（宁可 409 重试，不出现签名与版本错配）。
	if err := h.ca.SignPolicy(env); err != nil {
		response.InternalError(w, r, err)
		return
	}
	row, err := h.store.CreatePolicyVersion(r.Context(), scope, req.Policy, env.Signature, env.KeyID,
		env.IssuedAt, env.ExpiresAt, &currentVersion, &p.UserID)
	if err != nil {
		if errors.Is(err, ErrPolicyVersionConflict) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "策略已被他人更新，请刷新后重试")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	after, _ := json.Marshal(map[string]interface{}{
		"scope": scope, "version": row.Version, "expires_at": row.ExpiresAt.Format(time.RFC3339),
	})
	h.recordAudit(r, p, "put_policy", "apm_agent_policy", fmt.Sprintf("%s#%d", scope, row.Version), scope,
		fmt.Sprintf(`{"version":%d}`, currentVersion), string(after), audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, row.Envelope())
}

// recordAudit 记录操作审计（审计未接线时安全跳过——仅测试场景；写入失败走兜底日志/计数，
// 与 apinodes.recordAudit 同一纪律：审计写失败不阻断已完成的变更）。
func (h *AgentAdminHandler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "apm",
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
