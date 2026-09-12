// agentapi_handler.go APM Agent 面控制面接口（阶段2 上半；设计 §9.1/§9.2/§12.3）。
//
// 机器端点，不走浏览器会话链（RegisterAgentDataRoutes 不注入 authz——无会话/CSRF 面；
// 本仓库网关节点既有机器通道为日志文件管道，无 HTTP 认证先例可复用，故按设计 §9
// 落地证书认证）：
//
//	POST /api/v1/apm/agent/register      一次性令牌 + CSR 注册（用后即作废，原子防重放）
//	POST /api/v1/apm/agent/heartbeat     心跳（证书 PoP 认证）
//	GET  /api/v1/apm/agent/policy        拉取当前生效签名策略（证书 PoP 认证）
//	POST /api/v1/apm/agent/rotate-cert   证书轮换（证书 PoP 认证 + 新 CSR；旧证入撤销列表）
//
// PoP 认证（mTLS 的应用层等价物，理由见 agentca.go 包注释）三要素头：
//
//	X-JiuZhang-Agent-Cert:       base64(DER) 客户端证书（本 CA 签发）
//	X-JiuZhang-Agent-Timestamp:  RFC3339（±5 分钟时钟偏差窗口）
//	X-JiuZhang-Agent-Signature:  hex(私钥签名(POP前缀\nMETHOD\nPATH\nTIMESTAMP\nSHA256(body)))
//
// 伪造防护（§12.3）：应用/环境/服务归属一律从令牌与证书登记身份推导，
// 不信任请求体自报；证书指纹未登记/已撤销/已过期/签名不符一律拒绝。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Agent 面请求体上限（注册/轮换含 CSR 取 32KB；心跳 16KB）。
const (
	agentRegisterMaxBody  = 32768
	agentHeartbeatMaxBody = 16384
)

// serviceNamePattern / instanceIDPattern 服务名与实例标识格式（OTel 语义约定子集：
// 字母数字与 . _ : -，≤128；防注入与基数爆炸——§13.3 基数预算纪律在控制面先行约束）。
var (
	serviceNamePattern = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
	instanceIDPattern  = regexp.MustCompile(`^[a-zA-Z0-9._:-]{1,128}$`)
	versionPattern     = regexp.MustCompile(`^[a-zA-Z0-9._:+/-]{0,64}$`)
)

// AgentAPIHandler Agent 面处理器（无会话；认证见文件头）。
type AgentAPIHandler struct {
	store AgentRepository
	ca    *AgentCA
	cfg   AgentControlConfig
	now   func() time.Time
}

// NewAgentAPIHandler 创建 Agent 面处理器。
func NewAgentAPIHandler(store AgentRepository, ca *AgentCA, cfg AgentControlConfig) *AgentAPIHandler {
	return &AgentAPIHandler{store: store, ca: ca, cfg: cfg, now: time.Now}
}

// RegisterAgentDataRoutes 注册 Agent 面路由（无 authz——自有机器认证，无 CSRF 面）。
func RegisterAgentDataRoutes(mux *http.ServeMux, h *AgentAPIHandler) {
	mux.Handle("POST /api/v1/apm/agent/register", http.HandlerFunc(h.Register))
	mux.Handle("POST /api/v1/apm/agent/heartbeat", http.HandlerFunc(h.Heartbeat))
	mux.Handle("GET /api/v1/apm/agent/policy", http.HandlerFunc(h.PullPolicy))
	mux.Handle("POST /api/v1/apm/agent/rotate-cert", http.HandlerFunc(h.RotateCert))
}

// agentError 机器端点错误输出（复用统一错误信封）。
func agentError(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	response.Error(w, r, status, code, msg)
}

// readAgentBody 限长读取请求正文（PoP 签名覆盖正文摘要，必须先取原文再解析）。
func readAgentBody(w http.ResponseWriter, r *http.Request, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBytes))
	if err != nil {
		return nil, err
	}
	return body, nil
}

// authenticateAgent 证书 PoP 认证：先做纯密码学校验（不触库，挡垃圾流量），
// 再按指纹反查登记身份并检查撤销/过期/终态。返回登记行（身份唯一来源）。
func (h *AgentAPIHandler) authenticateAgent(w http.ResponseWriter, r *http.Request, body []byte) (*AgentRow, bool) {
	certHeader := r.Header.Get("X-JiuZhang-Agent-Cert")
	ts := r.Header.Get("X-JiuZhang-Agent-Timestamp")
	sig := r.Header.Get("X-JiuZhang-Agent-Signature")
	if certHeader == "" || ts == "" || sig == "" {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "缺少 Agent 认证头（证书/时间戳/签名）")
		return nil, false
	}
	cert, err := ParseAgentCertHeader(certHeader)
	if err != nil {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "客户端证书解析失败")
		return nil, false
	}
	if err := CheckPoPTimestamp(ts, h.now()); err != nil {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "时间戳无效或超出允许时钟偏差")
		return nil, false
	}
	if err := VerifyPoP(cert, r.Method, r.URL.Path, ts, body, sig); err != nil {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "持有证明签名校验失败")
		return nil, false
	}
	now := h.now().UTC()
	if now.After(cert.NotAfter) {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "客户端证书已过期，请轮换证书或重新注册")
		return nil, false
	}
	fp := CertFingerprint(cert)
	agent, err := h.store.AgentByCertFingerprint(r.Context(), fp)
	if err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "客户端证书未登记")
			return nil, false
		}
		response.InternalError(w, r, err)
		return nil, false
	}
	if agent.StoredStatus == AgentStatusRevoked {
		agentError(w, r, http.StatusForbidden, response.CodePermissionDenied, "Agent 已撤销")
		return nil, false
	}
	if now.After(agent.CertNotAfter) {
		agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, "客户端证书已过期，请轮换证书或重新注册")
		return nil, false
	}
	revoked, err := h.store.IsFingerprintRevoked(r.Context(), fp)
	if err != nil {
		response.InternalError(w, r, err)
		return nil, false
	}
	if revoked {
		agentError(w, r, http.StatusForbidden, response.CodePermissionDenied, "客户端证书已撤销（轮换/顶替/撤销）")
		return nil, false
	}
	return agent, true
}

// ---------- 注册 ----------

// agentRegisterRequest 注册入参（归属不由请求体决定：应用/环境取自令牌，
// 请求体只提供服务名/实例/语言等范围内标签与 CSR）。
type agentRegisterRequest struct {
	Token        string   `json:"token"`
	CSR          string   `json:"csr"`
	ServiceName  string   `json:"service_name"`
	InstanceID   string   `json:"instance_id"`
	Language     string   `json:"language"`
	AgentVersion string   `json:"agent_version"`
	SdkVersion   string   `json:"sdk_version"`
	NodeInfo     NodeInfo `json:"node_info"`
}

// validate 入参校验（fail-closed：非法即 400；node_info 白名单键、去控制字符）。
func (req *agentRegisterRequest) validate() error {
	req.Token = strings.TrimSpace(req.Token)
	if req.Token == "" || len(req.Token) > 128 {
		return fmt.Errorf("token 缺失或过长")
	}
	if strings.TrimSpace(req.CSR) == "" || len(req.CSR) > 16384 {
		return fmt.Errorf("csr 缺失或过长")
	}
	req.ServiceName = strings.TrimSpace(req.ServiceName)
	if !serviceNamePattern.MatchString(req.ServiceName) {
		return fmt.Errorf("service_name 须为 1~128 位字母数字或 . _ : -")
	}
	req.InstanceID = strings.TrimSpace(req.InstanceID)
	if !instanceIDPattern.MatchString(req.InstanceID) {
		return fmt.Errorf("instance_id 须为 1~128 位字母数字或 . _ : -")
	}
	req.Language = strings.ToLower(strings.TrimSpace(req.Language))
	if !ValidateAgentLanguage(req.Language) {
		return fmt.Errorf("language 须为 java/go/dotnet/nodejs/python/php 之一")
	}
	req.AgentVersion = strings.TrimSpace(req.AgentVersion)
	req.SdkVersion = strings.TrimSpace(req.SdkVersion)
	if !versionPattern.MatchString(req.AgentVersion) || !versionPattern.MatchString(req.SdkVersion) {
		return fmt.Errorf("agent_version/sdk_version 含非法字符或超过 64 字符")
	}
	if req.NodeInfo != nil {
		if err := validateNodeInfo(req.NodeInfo); err != nil {
			return err
		}
	}
	return nil
}

// validateNodeInfo 节点信息白名单校验（≤8 键，键白名单，值 ≤200 字符且禁控制字符）。
func validateNodeInfo(info NodeInfo) error {
	if len(info) > 8 {
		return fmt.Errorf("node_info 键数不能超过 8 个")
	}
	for k, v := range info {
		if !nodeInfoAllowedKeys[k] {
			return fmt.Errorf("node_info 不支持的键 %q（支持 hostname/host_ip/os/arch/pod/namespace/container_id）", k)
		}
		if len(v) > 200 {
			return fmt.Errorf("node_info.%s 值不能超过 200 字符", k)
		}
		if strings.ContainsAny(v, "\r\n\t\x00") {
			return fmt.Errorf("node_info.%s 值含非法控制字符", k)
		}
	}
	return nil
}

// Register POST /api/v1/apm/agent/register（设计 §9.1 注册流程）。
// 事务纪律（BUG-01 修复）：入参校验、CSR 解析、证书签发等不改变数据库状态的步骤
// 全部先行；令牌消费、服务认领、顶替存量、登记新 Agent 与策略解析由
// store.EnrollAgent 单事务一次提交——任一步失败整体回滚，不存在
// "令牌已用但 Agent 未注册"或"旧 Agent 已顶替但新 Agent 不存在"的中间态。
// 重试语义：注册不幂等。服务端提交后若响应丢失（连接中断等），客户端持同一令牌
// 重试将得 401（令牌已用），须由管理面重新签发令牌再注册；同服务同实例的再注册
// 会顶替前次孤儿登记行，不会残留"健康"假像。反过来，任何失败路径都保证令牌不被
// 烧毁（语言不符/认领冲突/CA 失败/策略失败/落库失败 → 400/401/409/500，零状态变更）。
func (h *AgentAPIHandler) Register(w http.ResponseWriter, r *http.Request) {
	body, err := readAgentBody(w, r, agentRegisterMaxBody)
	if err != nil {
		agentError(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "请求体过大")
		return
	}
	var req agentRegisterRequest
	if err := json.Unmarshal(body, &req); err != nil {
		agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if err := req.validate(); err != nil {
		agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	// CSR 先于令牌消费校验（格式问题不烧毁令牌）
	csr, err := ParseAgentCSR(req.CSR)
	if err != nil {
		agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	now := h.now().UTC()
	// 证书签发为纯计算：先于一切 DB 写入完成，签发失败零状态变更
	certPEM, fingerprint, notAfter, err := h.ca.IssueCertificate(csr, h.cfg.CertTTL, now)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	agent := &AgentRow{
		ID: uuid.New(), InstanceID: req.InstanceID, Language: req.Language,
		AgentVersion: req.AgentVersion, SdkVersion: req.SdkVersion,
		CertFingerprint: fingerprint, CertNotAfter: notAfter,
		NodeInfo: req.NodeInfo, RegisteredAt: now,
	}
	if agent.NodeInfo == nil {
		agent.NodeInfo = NodeInfo{}
	}
	result, err := h.store.EnrollAgent(r.Context(), &EnrollAgentParams{
		TokenHash: HashEnrollmentToken(req.Token), Language: req.Language,
		ServiceName: req.ServiceName, Agent: agent, Now: now,
	}, h.resolvePolicyForAgent)
	if err != nil {
		switch {
		case errors.Is(err, ErrTokenInvalid):
			agentError(w, r, http.StatusUnauthorized, response.CodeUnauthenticated, ErrTokenInvalid.Error())
		case errors.Is(err, ErrTokenLanguageNotAllowed):
			agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "该注册令牌不允许此语言")
		case errors.Is(err, ErrServiceClaimConflict):
			agentError(w, r, http.StatusConflict, response.CodeResourceConflict,
				"服务（service_name+environment）已被其他应用认领，请更换服务名或由管理员处理")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	svc := result.Service
	resourceAttrs := map[string]interface{}{
		"service.name":            svc.ServiceName,
		"service.instance.id":     req.InstanceID,
		"deployment.environment":  svc.Environment,
		"jiuzhang.service_row_id": svc.ID.String(),
	}
	if svc.ApplicationID != nil {
		resourceAttrs["jiuzhang.application_id"] = svc.ApplicationID.String()
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"agent_id":            result.Agent.ID,
		"client_cert":         certPEM,
		"ca_cert":             h.ca.CertPEM(),
		"ca_public_key":       h.ca.PublicKeyHex(),
		"key_id":              PolicySignKeyID,
		"cert_not_after":      notAfter,
		"collector_addr":      h.cfg.CollectorAddr, // 空串 = 数据面未就绪（如实返回）
		"resource_attributes": resourceAttrs,
		"policy":              result.Policy.Envelope(),
	})
}

// ---------- 心跳 ----------

// agentHeartbeatRequest 心跳入参（全部可选；空体同样合法——仅刷新活性）。
type agentHeartbeatRequest struct {
	AgentVersion string   `json:"agent_version"`
	SdkVersion   string   `json:"sdk_version"`
	NodeInfo     NodeInfo `json:"node_info"`
}

// Heartbeat POST /api/v1/apm/agent/heartbeat（PoP 认证）。
// 只刷新活性与自报版本/节点信息；状态迁移仅 ENROLLING→CONNECTED_BASELINE
// （首心跳补进），OFFLINE 由查询侧按心跳超时推导（不落库）。
func (h *AgentAPIHandler) Heartbeat(w http.ResponseWriter, r *http.Request) {
	body, err := readAgentBody(w, r, agentHeartbeatMaxBody)
	if err != nil {
		agentError(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "请求体过大")
		return
	}
	agent, ok := h.authenticateAgent(w, r, body)
	if !ok {
		return
	}
	var req agentHeartbeatRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
			return
		}
		req.AgentVersion = strings.TrimSpace(req.AgentVersion)
		req.SdkVersion = strings.TrimSpace(req.SdkVersion)
		if !versionPattern.MatchString(req.AgentVersion) || !versionPattern.MatchString(req.SdkVersion) {
			agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "agent_version/sdk_version 含非法字符或超过 64 字符")
			return
		}
		if req.NodeInfo != nil {
			if err := validateNodeInfo(req.NodeInfo); err != nil {
				agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
				return
			}
		}
	}
	if err := h.store.RecordHeartbeat(r.Context(), agent.ID, req.AgentVersion, req.SdkVersion, req.NodeInfo, h.now()); err != nil {
		response.InternalError(w, r, err)
		return
	}
	policyVersion := int64(0)
	if p, err := h.resolvePolicyForAgent(r.Context(), h.store, agent.ApplicationID); err == nil {
		policyVersion = p.Version
	}
	renewRecommended := time.Until(agent.CertNotAfter) < h.cfg.CertTTL/3
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"status":                  "ok",
		"server_time":             h.now().UTC().Format(time.RFC3339),
		"policy_version":          policyVersion,
		"cert_not_after":          agent.CertNotAfter,
		"cert_renew_recommended":  renewRecommended,
		"heartbeat_interval_hint": int(h.cfg.OfflineAfter.Seconds() / 2),
	})
}

// ---------- 策略拉取 ----------

// PullPolicy GET /api/v1/apm/agent/policy（PoP 认证；返回当前生效签名策略。
// 应用级作用域优先，未发布回退全局基线；Agent 侧只接受版本递增且签名有效的策略）。
func (h *AgentAPIHandler) PullPolicy(w http.ResponseWriter, r *http.Request) {
	agent, ok := h.authenticateAgent(w, r, nil)
	if !ok {
		return
	}
	policy, err := h.resolvePolicyForAgent(r.Context(), h.store, agent.ApplicationID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, policy.Envelope())
}

// resolvePolicyForAgent 解析 Agent 生效策略：应用级优先 → 全局基线；
// 全局基线不存在时惰性创建默认基线（v1，签名落库——注册/拉取路径共用，
// 创建竞争由版本唯一约束 + 冲突重读兜底）。store 形参使注册事务内以
// txPolicyStore 调用（与登记最终态同提交），事务外传入 h.store。
func (h *AgentAPIHandler) resolvePolicyForAgent(ctx context.Context, store PolicyStore, applicationID *uuid.UUID) (*PolicyRow, error) {
	if applicationID != nil {
		row, err := store.LatestPolicy(ctx, ApplicationPolicyScope(*applicationID))
		if err == nil {
			return row, nil
		}
		if !errors.Is(err, ErrPolicyNotFound) {
			return nil, err
		}
	}
	return h.ensureDefaultGlobalPolicy(ctx, store)
}

// ensureDefaultGlobalPolicy 保证全局基线存在（缺省创建签名默认策略 v1）。
func (h *AgentAPIHandler) ensureDefaultGlobalPolicy(ctx context.Context, store PolicyStore) (*PolicyRow, error) {
	row, err := store.LatestPolicy(ctx, PolicyScopeGlobal)
	if err == nil {
		return row, nil
	}
	if !errors.Is(err, ErrPolicyNotFound) {
		return nil, err
	}
	now := h.now().UTC()
	env := &PolicyEnvelope{
		Scope: PolicyScopeGlobal, Version: 1, KeyID: PolicySignKeyID,
		IssuedAt: now, ExpiresAt: now.Add(h.cfg.PolicyValidity),
		Policy: DefaultBaselinePolicy(),
	}
	if err := h.ca.SignPolicy(env); err != nil {
		return nil, err
	}
	zero := int64(0)
	row, err = store.CreatePolicyVersion(ctx, PolicyScopeGlobal, env.Policy, env.Signature, env.KeyID,
		env.IssuedAt, env.ExpiresAt, &zero, nil)
	if errors.Is(err, ErrPolicyVersionConflict) {
		// 并发创建：重读既有版本
		return store.LatestPolicy(ctx, PolicyScopeGlobal)
	}
	return row, err
}

// ---------- 证书轮换 ----------

// agentRotateRequest 轮换入参（新 CSR；不依赖长期注册令牌——设计 §9.1 第 4 条）。
type agentRotateRequest struct {
	CSR string `json:"csr"`
}

// RotateCert POST /api/v1/apm/agent/rotate-cert（PoP 认证须使用当前生效证书；
// 新证书签发后旧指纹即入撤销列表，旧证书立即失效）。
func (h *AgentAPIHandler) RotateCert(w http.ResponseWriter, r *http.Request) {
	body, err := readAgentBody(w, r, agentRegisterMaxBody)
	if err != nil {
		agentError(w, r, http.StatusRequestEntityTooLarge, response.CodeInvalidArgument, "请求体过大")
		return
	}
	agent, ok := h.authenticateAgent(w, r, body)
	if !ok {
		return
	}
	var req agentRotateRequest
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.CSR) == "" {
		agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误（须携带 csr）")
		return
	}
	csr, err := ParseAgentCSR(req.CSR)
	if err != nil {
		agentError(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	certPEM, fingerprint, notAfter, err := h.ca.IssueCertificate(csr, h.cfg.CertTTL, h.now())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.RotateAgentCert(r.Context(), agent.ID, agent.CertFingerprint, fingerprint, notAfter, h.now()); err != nil {
		switch {
		case errors.Is(err, ErrCertFingerprintMismatch):
			agentError(w, r, http.StatusConflict, response.CodeResourceConflict, "出示证书非当前生效证书，请先同步状态")
		case errors.Is(err, ErrAgentAlreadyRevoked):
			agentError(w, r, http.StatusForbidden, response.CodePermissionDenied, "Agent 已撤销")
		default:
			response.InternalError(w, r, err)
		}
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"agent_id":       agent.ID,
		"client_cert":    certPEM,
		"ca_cert":        h.ca.CertPEM(),
		"cert_not_after": notAfter,
	})
}
