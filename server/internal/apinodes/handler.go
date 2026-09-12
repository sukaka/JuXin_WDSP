// handler.go 节点版本校验 HTTP 处理器：
//
//	GET   /api/v1/api-security/nodes              节点列表（状态+版本+同步登记/结果+逐项一致性标记）
//	GET   /api/v1/api-security/nodes/consistency  版本分组对比（明确回答所有节点版本是否一致）
//	PATCH /api/v1/api-security/nodes/{id}         节点同步登记编辑（W18-SYNC §200：admin_addr/sync_enabled）
//
// 只读接口权限点 api_runtime.read（与 apisecurity 运行时只读接口同一权限域）；
// 登记编辑复用 api_policy.publish 权限点（配置面分发能力，与策略发布同级管控）。
package apinodes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// PermRuntimeRead 权限点（apillm 同款镜像字面量；apisecurity 运行时只读权限域）。
const PermRuntimeRead = "api_runtime.read"

// PermPolicyPublish 节点同步登记写操作权限点（复用策略发布权限域，W18-SYNC §200）。
const PermPolicyPublish = "api_policy.publish"

// auditRecorder 操作审计记录接口（由 *audits.Service 实现；单测注入 spy）。
type auditRecorder interface {
	Record(ctx context.Context, in audits.RecordInput) error
}

// Handler 节点版本校验处理器。
type Handler struct {
	store  Repository
	audits auditRecorder // nil 时写操作不记审计（仅测试便利；生产装配必须注入）
}

// NewHandler 创建处理器。
func NewHandler(store Repository) *Handler { return &Handler{store: store} }

// SetAudits 注入操作审计记录器（生产由 app 装配 *audits.Service）。
func (h *Handler) SetAudits(a auditRecorder) *Handler { h.audits = a; return h }

// RegisterRoutes 注册路由（统一 /api/v1/api-security 前缀）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/api-security/nodes",
		authz(middleware.RequirePermission(PermRuntimeRead)(http.HandlerFunc(h.ListNodes))))
	mux.Handle("GET /api/v1/api-security/nodes/consistency",
		authz(middleware.RequirePermission(PermRuntimeRead)(http.HandlerFunc(h.Consistency))))
	mux.Handle("PATCH /api/v1/api-security/nodes/{id}",
		authz(middleware.RequirePermission(PermPolicyPublish)(http.HandlerFunc(h.UpdateNode))))
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

// updateNodeSyncRequest 节点同步登记编辑入参（两字段均可选，至少提供一项）。
type updateNodeSyncRequest struct {
	AdminAddr   *string `json:"admin_addr"`
	SyncEnabled *bool   `json:"sync_enabled"`
}

// UpdateNode PATCH /api/v1/api-security/nodes/{id}
// 节点同步登记编辑（W18-SYNC §200 配置面主动同步 v2 登记入口）：admin_addr 为节点
// Caddy Admin 通道标识（unix socket 绝对路径 / unix:///path / http(s)://host[:port]，
// 仅内网管理面地址，校验口径见 gatewayconfig.ValidateNodeAdminAddr；空串 = 清除登记），
// sync_enabled 控制该节点是否参与发布扇出。写操作记操作审计。
func (h *Handler) UpdateNode(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "无效的节点ID")
		return
	}
	var req updateNodeSyncRequest
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if req.AdminAddr == nil && req.SyncEnabled == nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "admin_addr 与 sync_enabled 至少提供一项")
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
	if err := h.store.UpdateSyncRegistration(r.Context(), id, adminAddr, syncEnabled); err != nil {
		if errors.Is(err, ErrNodeNotFound) {
			response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "节点不存在")
			return
		}
		response.InternalError(w, r, err)
		return
	}
	h.recordAudit(r, p, "update", "api_gateway_node", id.String(), current.NodeName,
		syncRegSummary(current.AdminAddr, current.SyncEnabled),
		syncRegSummary(adminAddr, syncEnabled),
		audits.ResultSuccess, audits.RiskMedium)
	updated, err := h.store.GetNode(r.Context(), id)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, updated)
}

// syncRegSummary 审计 before/after 摘要（登记两要素）。
// 输出合法 JSON：audits.Record 的 MaskSensitiveJSON 对非 JSON 输入会整体替换为
// "(unstructured, masked)"，JSON 摘要（无敏感键）才能如实留存 before/after。
func syncRegSummary(adminAddr string, syncEnabled bool) string {
	raw, _ := json.Marshal(map[string]interface{}{
		"admin_addr":   adminAddr,
		"sync_enabled": syncEnabled,
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
