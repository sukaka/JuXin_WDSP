// handler.go 节点管理与版本校验 HTTP 处理器：
//
//	GET    /api/v1/api-security/nodes              节点列表（状态+版本+同步登记/结果+协同状态+逐项一致性标记）
//	POST   /api/v1/api-security/nodes              手动登记新网关节点（支持 admin_addr / sync_agent_addr / sync_secret）
//	GET    /api/v1/api-security/nodes/consistency  版本分组对比（明确回答所有节点版本是否一致）
//	PATCH  /api/v1/api-security/nodes/{id}         节点同步登记编辑（admin_addr / sync_agent_addr / sync_secret / sync_enabled）
//	DELETE /api/v1/api-security/nodes/{id}         删除网关节点（若属于主备高可用组返回 409）
//	POST   /api/v1/api-security/nodes/{id}/test    探测节点协同代理（hasyncd）或 Caddy Admin 连通性
//
// 只读接口接受 api_runtime.read 或 ha.read；写接口接受 api_policy.publish 或 ha.manage，
// 确保纯 WAF 形态与 WDSP 形态下均可通过 HA 权限管理集群节点。
package apinodes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/nodesync"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PermRuntimeRead 权限点（apillm 同款镜像字面量；apisecurity 运行时只读权限域）。
const PermRuntimeRead = "api_runtime.read"

// PermPolicyPublish 节点同步登记写操作权限点（复用策略发布权限域，W18-SYNC §200）。
const PermPolicyPublish = "api_policy.publish"

// PermHARead / PermHAManage 高可用读写权限点（纯 WAF 形态管理 HA 节点时放行）。
const (
	PermHARead   = "ha.read"
	PermHAManage = "ha.manage"
)

var nodeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Encryptor 节点协同密钥加密接口（*encryption.Service 实现；nil = 拒绝保存密钥，永不落明文）。
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
}

// NodeTester 节点 hasyncd 连通性探测函数（由 nodesync.Manager 注入）。
type NodeTester func(ctx context.Context, nodeID uuid.UUID) (*NodeTestResult, error)

// CaddyPinger Caddy Admin 连通性探测函数（默认使用 gatewayconfig.NewCaddyClient(addr).Ping）。
type CaddyPinger func(ctx context.Context, adminAddr string) error

// Handler 节点管理与版本校验处理器。
type Handler struct {
	store      Repository
	audits     auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
	enc        Encryptor     // nil 时拒绝设置 sync_secret（fail-closed）
	nodeTester NodeTester
	caddyPing  CaddyPinger
}

// NewHandler 创建处理器。
func NewHandler(store Repository) *Handler {
	return &Handler{
		store: store,
		caddyPing: func(ctx context.Context, adminAddr string) error {
			cli, err := gatewayconfig.NewCaddyClientForAdminAddr(adminAddr)
			if err != nil {
				return err
			}
			return cli.Ping(ctx)
		},
	}
}

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *Handler) SetAudits(a auditRecorder) *Handler { h.audits = a; return h }

// SetEncryptor 注入加密服务（用于加密存储 sync_secret_ciphertext）。
func (h *Handler) SetEncryptor(enc Encryptor) *Handler { h.enc = enc; return h }

// SetNodeTester 注入 hasyncd 协同代理连通性探测器（由 nodesync.Manager 装配）。
func (h *Handler) SetNodeTester(fn NodeTester) *Handler { h.nodeTester = fn; return h }

// SetCaddyPinger 覆盖 Caddy Admin 连通性探测器（测试注入）。
func (h *Handler) SetCaddyPinger(fn CaddyPinger) *Handler { h.caddyPing = fn; return h }

// requireAnyPerm 要求已登录且具备任一给定权限。
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

// RegisterRoutes 注册全部节点路由（统一 /api/v1/api-security 前缀）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/nodes",
		authz(requireAnyPerm(PermRuntimeRead, PermHARead)(http.HandlerFunc(h.ListNodes))))
	RegisterSyncRoutes(mux, authz, h)
}

// RegisterSyncRoutes 注册节点一致性校验与节点 CRUD/同步登记/探测路由（全产品形态均需挂接以支撑 HA 集群）。
func RegisterSyncRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/nodes/consistency",
		authz(requireAnyPerm(PermRuntimeRead, PermHARead)(http.HandlerFunc(h.Consistency))))
	mux.Handle("POST /api/v1/api-security/nodes",
		authz(requireAnyPerm(PermPolicyPublish, PermHAManage)(http.HandlerFunc(h.CreateNode))))
	mux.Handle("PATCH /api/v1/api-security/nodes/{id}",
		authz(requireAnyPerm(PermPolicyPublish, PermHAManage)(http.HandlerFunc(h.UpdateNode))))
	mux.Handle("DELETE /api/v1/api-security/nodes/{id}",
		authz(requireAnyPerm(PermPolicyPublish, PermHAManage)(http.HandlerFunc(h.DeleteNode))))
	mux.Handle("POST /api/v1/api-security/nodes/{id}/test",
		authz(requireAnyPerm(PermPolicyPublish, PermHAManage)(http.HandlerFunc(h.TestNode))))
}

// NodesResponse 列表出参（items + 总体一致性标记，口径与 /nodes/consistency 一致）。
type NodesResponse struct {
	Items          []Node `json:"items"`
	Total          int    `json:"total"`
	Consistent     bool   `json:"consistent"`      // 总体一致性标记（同 ConsistencyReport.Consistent）
	EvaluatedNodes int    `json:"evaluated_nodes"` // 参与判定节点数（0 = 无版本数据可比）
}

// ListNodes GET /api/v1/api-security/nodes
// 节点列表+状态+版本+一致性标记；version_consistent 为逐项标记
// （nil/JSON null = 未参与判定：SILENT 离线或未上报版本）。
func (h *Handler) ListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.store.ListNodes(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	report := EvaluateConsistency(nodes, now)
	for i := range nodes {
		nodes[i].VersionConsistent = versionConsistentFlag(nodes[i], report.DominantVersion, now)
	}
	response.JSON(w, r, http.StatusOK, NodesResponse{
		Items:          nodes,
		Total:          len(nodes),
		Consistent:     report.Consistent,
		EvaluatedNodes: report.EvaluatedNodes,
	})
}

// Consistency GET /api/v1/api-security/nodes/consistency
// 各活跃节点按 policy_version 分组对比，Consistent 字段明确回答
// 「所有节点版本是否一致」；SILENT 离线节点不参与判定但如实列出。
func (h *Handler) Consistency(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.store.ListNodes(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, EvaluateConsistency(nodes, time.Now().UTC()))
}

// createNodeRequest 手动登记新网关节点入参。
type createNodeRequest struct {
	NodeName      string `json:"node_name"`
	AdminAddr     string `json:"admin_addr"`
	SyncAgentAddr string `json:"sync_agent_addr"`
	SyncSecret    string `json:"sync_secret"`
	SyncEnabled   bool   `json:"sync_enabled"`
}

// CreateNode POST /api/v1/api-security/nodes
// 手动登记网关节点（用于备机上线前的节点注册，支持 Caddy Admin 地址与 hasyncd 协同代理配置）。
func (h *Handler) CreateNode(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req createNodeRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	nodeName := strings.TrimSpace(req.NodeName)
	if !nodeNameRE.MatchString(nodeName) {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"节点名非法（须为 1~128 位字母或数字开头，仅允许字母、数字、. _ -）")
		return
	}
	adminAddr := strings.TrimSpace(req.AdminAddr)
	if adminAddr != "" {
		if err := gatewayconfig.ValidateNodeAdminAddr(adminAddr); err != nil {
			detail := strings.TrimPrefix(err.Error(), gatewayconfig.ErrAdminAddrDenied.Error()+": ")
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"管理通道地址非法（仅支持 unix socket 路径或内网 http(s)://host[:port]）："+detail)
			return
		}
	}
	syncAgentAddr := strings.TrimSpace(req.SyncAgentAddr)
	if syncAgentAddr != "" {
		if err := nodesync.ValidateSyncAgentAddr(syncAgentAddr); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"协同代理地址非法（仅支持内网 http(s)://host:port）："+err.Error())
			return
		}
	}
	var secretCipher string
	rawSecret := strings.TrimSpace(req.SyncSecret)
	if rawSecret != "" {
		if _, err := nodesync.ParseSecretHex(rawSecret); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"协同代理密钥格式非法（须为至少 64 位十六进制字符串）："+err.Error())
			return
		}
		if h.enc == nil {
			response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError,
				"未装配加密服务，无法安全保存协同代理密钥")
			return
		}
		encVal, err := h.enc.Encrypt(strings.ToLower(rawSecret))
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		secretCipher = encVal
	}

	created, err := h.store.CreateNode(r.Context(), CreateNodeInput{
		NodeName:             nodeName,
		AdminAddr:            adminAddr,
		SyncAgentAddr:        syncAgentAddr,
		SyncSecretCiphertext: secretCipher,
		SyncEnabled:          req.SyncEnabled,
	})
	if err != nil {
		if errors.Is(err, ErrNodeNameExists) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "节点名已存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "create", "api_gateway_node", created.ID.String(), created.NodeName,
		"",
		syncRegSummary(created.AdminAddr, created.SyncAgentAddr, created.HasSyncSecret, created.SyncEnabled),
		audits.ResultSuccess, audits.RiskMedium)
	response.JSON(w, r, http.StatusCreated, created)
}

// updateNodeSyncRequest 节点同步登记编辑入参（字段均可选，至少提供一项）。
// SyncSecret 指针语义：nil/省略 = 保持不变，"" = 清除密钥，非空 = 校验并加密替换。
type updateNodeSyncRequest struct {
	AdminAddr     *string `json:"admin_addr"`
	SyncAgentAddr *string `json:"sync_agent_addr"`
	SyncSecret    *string `json:"sync_secret"`
	SyncEnabled   *bool   `json:"sync_enabled"`
}

// UpdateNode PATCH /api/v1/api-security/nodes/{id}
// 节点同步登记编辑：支持 admin_addr、sync_agent_addr、sync_secret（加密落库，永不回显）与 sync_enabled。
func (h *Handler) UpdateNode(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的节点ID")
		return
	}
	var req updateNodeSyncRequest
	if err := response.DecodeJSON(w, r, &req, 16384); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.AdminAddr == nil && req.SyncAgentAddr == nil && req.SyncSecret == nil && req.SyncEnabled == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "至少提供一项待更新字段")
		return
	}
	current, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	adminAddr := current.AdminAddr
	if req.AdminAddr != nil {
		adminAddr = strings.TrimSpace(*req.AdminAddr)
	}
	syncAgentAddr := current.SyncAgentAddr
	if req.SyncAgentAddr != nil {
		syncAgentAddr = strings.TrimSpace(*req.SyncAgentAddr)
	}
	syncEnabled := current.SyncEnabled
	if req.SyncEnabled != nil {
		syncEnabled = *req.SyncEnabled
	}
	if adminAddr != "" {
		if err := gatewayconfig.ValidateNodeAdminAddr(adminAddr); err != nil {
			// 用户可见消息不出现英文 sentinel，仅保留中文原因（地址为空/非内网地址等）
			detail := strings.TrimPrefix(err.Error(), gatewayconfig.ErrAdminAddrDenied.Error()+": ")
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"管理通道地址非法（仅支持 unix socket 路径或内网 http(s)://host[:port]）："+detail)
			return
		}
	}
	if syncAgentAddr != "" {
		if err := nodesync.ValidateSyncAgentAddr(syncAgentAddr); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"协同代理地址非法（仅支持内网 http(s)://host:port）："+err.Error())
			return
		}
	}

	var secretCipher *string
	afterHasSecret := current.HasSyncSecret
	if req.SyncSecret != nil {
		rawSecret := strings.TrimSpace(*req.SyncSecret)
		if rawSecret == "" {
			empty := ""
			secretCipher = &empty
			afterHasSecret = false
		} else {
			if _, err := nodesync.ParseSecretHex(rawSecret); err != nil {
				response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
					"协同代理密钥格式非法（须为至少 64 位十六进制字符串）："+err.Error())
				return
			}
			if h.enc == nil {
				response.Error(w, r, http.StatusInternalServerError, response.CodeInternalError,
					"未装配加密服务，无法安全保存协同代理密钥")
				return
			}
			encVal, err := h.enc.Encrypt(strings.ToLower(rawSecret))
			if err != nil {
				response.InternalError(w, r, err)
				return
			}
			secretCipher = &encVal
			afterHasSecret = true
		}
	}

	if err := h.store.UpdateNodeRegistration(r.Context(), id, SyncRegistrationUpdate{
		AdminAddr:            adminAddr,
		SyncAgentAddr:        syncAgentAddr,
		SyncSecretCiphertext: secretCipher,
		SyncEnabled:          syncEnabled,
	}); err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_gateway_node", id.String(), current.NodeName,
		syncRegSummary(current.AdminAddr, current.SyncAgentAddr, current.HasSyncSecret, current.SyncEnabled),
		syncRegSummary(adminAddr, syncAgentAddr, afterHasSecret, syncEnabled),
		audits.ResultSuccess, audits.RiskMedium)
	updated, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, updated)
}

// DeleteNode DELETE /api/v1/api-security/nodes/{id}
// 删除网关节点（若节点仍属于任一主备高可用组返回 409 Conflict）。
func (h *Handler) DeleteNode(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的节点ID")
		return
	}
	current, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.DeleteNode(r.Context(), id); err != nil {
		if errors.Is(err, ErrNodeInHAGroup) {
			response.Error(w, r, http.StatusConflict, response.CodeResourceConflict,
				"该节点仍属于主备高可用组，请先从主备组移除或删除主备组后再删除节点")
			return
		}
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete", "api_gateway_node", id.String(), current.NodeName,
		syncRegSummary(current.AdminAddr, current.SyncAgentAddr, current.HasSyncSecret, current.SyncEnabled),
		"",
		audits.ResultSuccess, audits.RiskHigh)
	response.JSON(w, r, http.StatusOK, map[string]string{"message": "节点已删除"})
}

// TestNode POST /api/v1/api-security/nodes/{id}/test
// 探测节点连通性：优先探测 hasyncd GET /v1/health，未配置协同代理时降级探测 Caddy Admin Ping。
func (h *Handler) TestNode(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的节点ID")
		return
	}
	current, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	probeCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if strings.TrimSpace(current.SyncAgentAddr) != "" {
		if h.nodeTester == nil {
			response.JSON(w, r, http.StatusOK, NodeTestResult{
				OK:      false,
				Channel: "hasyncd",
				Error:   "节点协同探测服务未初始化",
			})
			return
		}
		res, err := h.nodeTester(probeCtx, id)
		if err != nil {
			response.JSON(w, r, http.StatusOK, NodeTestResult{
				OK:      false,
				Channel: "hasyncd",
				Error:   err.Error(),
			})
			return
		}
		if res == nil {
			res = &NodeTestResult{OK: false, Channel: "hasyncd", Error: "探测返回空结果"}
		}
		if res.Channel == "" {
			res.Channel = "hasyncd"
		}
		response.JSON(w, r, http.StatusOK, res)
		return
	}

	if strings.TrimSpace(current.AdminAddr) != "" {
		if err := gatewayconfig.ValidateNodeAdminAddr(current.AdminAddr); err != nil {
			response.JSON(w, r, http.StatusOK, NodeTestResult{
				OK:      false,
				Channel: "caddy_admin",
				Error:   "管理通道地址校验失败: " + err.Error(),
			})
			return
		}
		start := time.Now()
		err := h.caddyPing(probeCtx, current.AdminAddr)
		latency := time.Since(start).Milliseconds()
		reachable := err == nil
		res := NodeTestResult{
			OK:             reachable,
			Channel:        "caddy_admin",
			LatencyMs:      latency,
			CaddyReachable: &reachable,
		}
		if err != nil {
			res.Error = err.Error()
		}
		response.JSON(w, r, http.StatusOK, res)
		return
	}

	response.JSON(w, r, http.StatusOK, NodeTestResult{
		OK:      false,
		Channel: "none",
		Error:   "节点未配置协同代理地址或 Caddy 管理地址",
	})
}

// syncRegSummary 审计 before/after 摘要（绝不包含明文或密文密钥，仅记录 has_sync_secret 布尔）。
// 输出合法 JSON：audits.Record 的 MaskSensitiveJSON 对非 JSON 输入会整体替换为
// "(unstructured, masked)"，JSON 摘要（无敏感键）才能如实留存 before/after。
func syncRegSummary(adminAddr, syncAgentAddr string, hasSyncSecret, syncEnabled bool) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"admin_addr":      adminAddr,
		"sync_agent_addr": syncAgentAddr,
		"has_sync_secret": hasSyncSecret,
		"sync_enabled":    syncEnabled,
	})
	return string(raw)
}

// recordAudit 记录操作审计（审计未接线时安全跳过——仅测试场景；写入失败走兜底日志/计数，
// 与 apisecurity.recordAudit 同一纪律：审计写失败不阻断已完成的登记编辑）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action, objType, objID, objName, before, after, result, risk string) {
	if h.audits == nil || p == nil {
		return
	}
	audits.RecordWithFallback(r.Context(), h.audits, audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "api_security",
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
