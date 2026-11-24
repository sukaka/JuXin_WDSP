// 主备高可用 REST 接口（docs/HA_ACTIVE_STANDBY_DESIGN.md §8.4）。
// 全部写操作：CSRF + 参数校验 + 操作审计（高危）；配置生效 = 保存 DB +
// 原子写本机 sidecars/ha-vip.json（如本机为成员或单机模式）+ 可选 RemoteSyncer 推送远端成员。
package hagroups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/response"
)

// Encryptor 认证串加解密接口（*encryption.Service 实现；nil = 未装配，
// 设置 auth_pass 将被拒绝并报错，不出现明文落库）。
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(encoded string) (string, error)
}

// NodeLister 网关节点查询（*apinodes.Store 适配）。
type NodeLister interface {
	Exists(ctx context.Context, nodeID string) (bool, error)
	// Names 批量取节点名（下发构造 member.node 用；未知节点省略）。
	Names(ctx context.Context, nodeIDs []string) (map[string]string, error)
}

// BridgePortChecker 检查指定节点集合上某接口是否为网桥成员口（返回冲突节点名与桥名；空串 = 未入桥）。
type BridgePortChecker func(ctx context.Context, nodeNames []string, iface string) (conflictNode, bridgeName string, err error)

// RemoteSyncer 远端成员节点 ha-vip.json 同步接口（Phase 3 nodesync 装配）。
type RemoteSyncer interface {
	PushHaVip(ctx context.Context, nodeName string, payload []byte) error
	DeleteHaVip(ctx context.Context, nodeName string) error
}

// NodeRuntimeStatus 单节点汇聚后的 HA VIP 运行状态快照。
type NodeRuntimeStatus struct {
	NodeName  string          `json:"node_name"`
	Status    json.RawMessage `json:"status,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
	Fresh     bool            `json:"fresh"`
	Source    string          `json:"source,omitempty"` // "local" | "remote"
}

// NodeStatusProvider 节点级 ha-vip-status 汇聚提供者（Phase 3 apinodes/nodesync 装配）。
// 返回 map[nodeName]NodeRuntimeStatus（调用方按统一新鲜度阈值计算 Fresh 并合并本机状态）。
type NodeStatusProvider interface {
	GetNodeHaVipStatuses(ctx context.Context, nodeNames []string) (map[string]NodeRuntimeStatus, error)
}

// SyncResult 单节点边车配置同步结果。
type SyncResult struct {
	NodeName string `json:"node_name"`
	Scope    string `json:"scope"`  // "local" | "remote"
	Status   string `json:"status"` // "SUCCESS" | "FAILED"
	Error    string `json:"error,omitempty"`
}

var errBridgePortCheckInternal = errors.New("check bridge port conflict failed")

// Handler 主备组处理器。
type Handler struct {
	store          Repository
	nodes          NodeLister
	enc            Encryptor // nil = 未装配加密服务
	audits         *audits.Service
	sidecarDir     string
	localNodeName  string
	now            func() time.Time
	bridgeChecker  BridgePortChecker
	remoteSyncer   RemoteSyncer
	statusProvider NodeStatusProvider
}

// NewHandler 创建处理器。
func NewHandler(store Repository, nodes NodeLister, enc Encryptor, audit *audits.Service) *Handler {
	return &Handler{store: store, nodes: nodes, enc: enc, audits: audit, now: time.Now}
}

// SetSidecarDir 覆盖边车目录（测试用临时目录）。
func (h *Handler) SetSidecarDir(dir string) { h.sidecarDir = dir }

// SetBridgePortChecker 注入网桥成员口冲突检查器（禁止将网桥成员口用作 HA VRRP 承载网卡）。
func (h *Handler) SetBridgePortChecker(fn BridgePortChecker) *Handler {
	h.bridgeChecker = fn
	return h
}

// SetRemoteSyncer 注入远端节点 ha-vip.json 同步器（Phase 3 nodesync 接入）。
func (h *Handler) SetRemoteSyncer(s RemoteSyncer) *Handler {
	h.remoteSyncer = s
	return h
}

// SetLocalNodeName 设置管理面所在本地网关节点名（为空表示兼容单机/未区分节点模式）。
func (h *Handler) SetLocalNodeName(name string) *Handler {
	h.localNodeName = strings.TrimSpace(name)
	return h
}

// SetNodeStatusProvider 注入全量节点 HA 运行状态提供者（Phase 3 apinodes/nodesync 接入）。
func (h *Handler) SetNodeStatusProvider(p NodeStatusProvider) *Handler {
	h.statusProvider = p
	return h
}

func (h *Handler) dir() string {
	if h.sidecarDir != "" {
		return h.sidecarDir
	}
	return DefaultSidecarDir
}

// RegisterRoutes 注册主备接口（权限：ha.read / ha.manage）。
func RegisterRoutes(mux *http.ServeMux, authzFn func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/ha/groups", authzFn(middleware.RequirePermission("ha.read")(http.HandlerFunc(h.List))))
	mux.Handle("POST /api/v1/ha/groups", authzFn(middleware.RequirePermission("ha.manage")(http.HandlerFunc(h.Create))))
	mux.Handle("GET /api/v1/ha/groups/{id}", authzFn(middleware.RequirePermission("ha.read")(http.HandlerFunc(h.Get))))
	mux.Handle("PATCH /api/v1/ha/groups/{id}", authzFn(middleware.RequirePermission("ha.manage")(http.HandlerFunc(h.Update))))
	mux.Handle("DELETE /api/v1/ha/groups/{id}", authzFn(middleware.RequirePermission("ha.manage")(http.HandlerFunc(h.Delete))))
	mux.Handle("POST /api/v1/ha/groups/{id}/failback", authzFn(middleware.RequirePermission("ha.manage")(http.HandlerFunc(h.Failback))))
	mux.Handle("GET /api/v1/ha/events", authzFn(middleware.RequirePermission("ha.read")(http.HandlerFunc(h.ListEvents))))
}

// List GET /api/v1/ha/groups
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	groups, err := h.store.List(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	nodeStatuses := h.collectMemberStatuses(r.Context(), groups)
	splitBrain := false
	for i := range groups {
		if isGroupSplitBrain(&groups[i], nodeStatuses) {
			splitBrain = true
			break
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items":         groups,
		"status":        readHaVipStatus(h.dir()),
		"node_statuses": nodeStatuses,
		"split_brain":   splitBrain,
	})
}

// Get GET /api/v1/ha/groups/{id}
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	g, err := h.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "主备组不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	nodeStatuses := h.collectMemberStatuses(r.Context(), []Group{*g})
	response.JSON(w, r, http.StatusOK, map[string]any{
		"group":         g,
		"status":        readHaVipStatus(h.dir()),
		"node_statuses": nodeStatuses,
		"split_brain":   isGroupSplitBrain(g, nodeStatuses),
	})
}

// ListEvents GET /api/v1/ha/events
func (h *Handler) ListEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	filter := EventFilter{
		GroupID:   strings.TrimSpace(q.Get("group_id")),
		NodeName:  strings.TrimSpace(q.Get("node_name")),
		EventType: strings.TrimSpace(q.Get("event_type")),
	}
	if filter.GroupID != "" {
		if _, err := uuid.Parse(filter.GroupID); err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "group_id 参数必须为合法 UUID")
			return
		}
	}
	if rawPage := strings.TrimSpace(q.Get("page")); rawPage != "" {
		v, err := strconv.Atoi(rawPage)
		if err != nil || v < 1 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "page 参数必须为正整数")
			return
		}
		filter.Page = v
	}
	if rawSize := strings.TrimSpace(q.Get("page_size")); rawSize != "" {
		v, err := strconv.Atoi(rawSize)
		if err != nil || v < 1 {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "page_size 参数必须为正整数")
			return
		}
		filter.PageSize = v
	}
	page, pageSize := normalizeEventPagination(filter.Page, filter.PageSize)
	filter.Page, filter.PageSize = page, pageSize

	items, total, err := h.store.ListEvents(r.Context(), filter)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.Page(w, r, items, total, page, pageSize)
}

// Create POST /api/v1/ha/groups
func (h *Handler) Create(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var in UpsertInput
	if err := response.DecodeJSON(w, r, &in, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	g, err := h.validate(r, &in)
	if err != nil {
		if errors.Is(err, errBridgePortCheckInternal) {
			response.InternalError(w, r, err)
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	authCipher, err := h.resolveAuthOnCreate(in.AuthPass)
	if err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if err := h.store.Create(r.Context(), g, authCipher); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	// 重新读取（回填 HasAuthPass/Version/时间戳，下发与响应以此为准）
	ng, err := h.store.Get(r.Context(), g.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	g = ng
	syncResults, err := h.syncSidecarPush(r.Context(), g, nil)
	if err != nil {
		h.recordAudit(r, p, "create_ha_group", g, audits.ResultFailure, "配置已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, "create_ha_group", g, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{
		"group":        g,
		"sync_results": syncResults,
	})
}

// Update PATCH /api/v1/ha/groups/{id}
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	old, err := h.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "主备组不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var in UpsertInput
	if err := response.DecodeJSON(w, r, &in, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	g, err := h.validate(r, &in)
	if err != nil {
		if errors.Is(err, errBridgePortCheckInternal) {
			response.InternalError(w, r, err)
			return
		}
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	g.ID = old.ID
	g.Version = in.Version
	var authCipher *string // nil = 不变更
	if in.AuthPass != nil {
		v, err := h.resolveAuth(*in.AuthPass)
		if err != nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
			return
		}
		authCipher = &v
	}
	if err := h.store.Update(r.Context(), g, authCipher); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	ng, err := h.store.Get(r.Context(), g.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	syncResults, err := h.syncSidecarPush(r.Context(), ng, old)
	if err != nil {
		h.recordAudit(r, p, "update_ha_group", ng, audits.ResultFailure, "配置已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, "update_ha_group", ng, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{
		"group":        ng,
		"sync_results": syncResults,
	})
}

// Delete DELETE /api/v1/ha/groups/{id}
// 收回主备能力：仅在本机属于该组（或无其他组占用本机）时删本机边车配置，
// 并经可选 RemoteSyncer 同步收回远端成员配置，最后删 DB。
func (h *Handler) Delete(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	g, err := h.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "主备组不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	syncResults, err := h.syncSidecarDelete(r.Context(), g)
	if err != nil {
		h.recordAudit(r, p, "delete_ha_group", g, audits.ResultFailure, "边车配置删除失败: "+err.Error())
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.Delete(r.Context(), g.ID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete_ha_group", g, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{
		"message":      "主备组已删除，VIP 已随配置收回释放",
		"sync_results": syncResults,
	})
}

// Failback POST /api/v1/ha/groups/{id}/failback
// 人工回切（把 VIP 切到指定节点）：调整成员优先级后整体更新并重新下发。
// 请求体 {"node_id":"..."} = 期望持有 VIP 的节点。
//
// 判定以「VIP 实际持有」为准而非配置优先级：优先综合全部成员的新鲜汇聚状态
// （NodeStatusProvider + 本机状态文件），未装配汇聚提供者时回退本机状态文件。
func (h *Handler) Failback(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	g, err := h.store.Get(r.Context(), r.PathValue("id"))
	if errors.Is(err, ErrNotFound) {
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "主备组不存在")
		return
	}
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var req struct {
		NodeID string `json:"node_id"`
	}
	if err := response.DecodeJSON(w, r, &req, 8192); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	if len(g.Members) != 2 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "组成员异常（非 2 个），无法回切")
		return
	}
	ti := -1
	for i := range g.Members {
		if g.Members[i].NodeID == req.NodeID {
			ti = i
			break
		}
	}
	if ti < 0 {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "node_id 不是本组成员")
		return
	}
	target, peer := &g.Members[ti], &g.Members[1-ti]

	nodeStatuses := h.collectMemberStatuses(r.Context(), []Group{*g})
	holder := vipHolderFromStatuses(g, nodeStatuses, readHaVipRuntime(h.dir(), h.now()))
	if holder != "" && holder == target.NodeName {
		response.JSON(w, r, http.StatusOK, map[string]any{"message": "目标节点已持有 VIP，无需回切", "group": g})
		return
	}
	var msg string
	switch {
	case target.Priority < peer.Priority:
		// 常规回切：交换优先级，目标升为全组最高；持有方优先级变化触发其
		// keepalived 实例重载释放 VIP（发 0 优先级通告），目标随即接管。
		target.Priority, peer.Priority = peer.Priority, target.Priority
		msg = "已交换成员优先级并重新下发，VIP 将随选举回切"
	case holder == "":
		// 目标已是高优先级但持有方未知（havipd 未上报/状态过期）：不做变更——
		// 盲目下调对端优先级会使重复回切请求持续漂移配置。
		response.JSON(w, r, http.StatusOK, map[string]any{
			"message": "目标节点已是高优先级，且当前无法确认 VIP 实际持有节点（havipd 未上报或状态已过期），未做变更",
			"group":   g,
		})
		return
	default:
		// 目标已是高优先级但确认未持有 VIP（nopreempt 故障转移后的典型场景）：
		// keepalived 仅在自身实例参数变化的重载中释放 VIP，故下调对端优先级
		// 强制其重载让位；目标保持全组最高，主备语义不变。
		oldPeer := peer.Priority
		switch {
		case peer.Priority > 1:
			peer.Priority--
		case target.Priority > 2:
			// 对端已在下限 1：上移对端到 2（目标优先级 >2 时合法且仍全组最高）。
			peer.Priority = 2
		default:
			// 极端情形（对端 1、目标 2）：整体上移一级，对端参数仍发生变化。
			target.Priority, peer.Priority = 3, 2
		}
		msg = fmt.Sprintf("目标已是高优先级但未持有 VIP，已微调对端优先级（%d→%d）强制其重载让位，VIP 将随重新选举回切", oldPeer, peer.Priority)
	}
	if err := h.store.Update(r.Context(), g, nil); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	ng, err := h.store.Get(r.Context(), g.ID)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	syncResults, err := h.syncSidecarPush(r.Context(), ng, nil)
	if err != nil {
		h.recordAudit(r, p, "failback_ha_group", ng, audits.ResultFailure, "优先级已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	opUser := ""
	if p != nil {
		opUser = p.Username
	}
	h.recordEvent(r.Context(), HaEvent{
		GroupID:   ng.ID,
		GroupName: ng.Name,
		NodeName:  target.NodeName,
		EventType: EventTypeFailback,
		Detail: map[string]any{
			"target_node_id":   target.NodeID,
			"target_node_name": target.NodeName,
			"peer_node_name":   peer.NodeName,
			"previous_holder":  holder,
			"message":          msg,
			"operator":         opUser,
			"sync_results":     syncResults,
		},
		OccurredAt: h.now().UTC(),
	})
	h.recordAudit(r, p, "failback_ha_group", ng, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{
		"message":      msg,
		"group":        ng,
		"sync_results": syncResults,
	})
}

// vipHolderName 由单节点运行状态推断当前 VIP 持有节点名（"" = 未知）：
//   - 该节点 MASTER/已持有 VIP → 该节点；
//   - 该节点 BACKUP 且 keepalived 存活 → 组内另一成员（2 节点组的健康推断）；
//   - 其他（FAULT/DISABLED/STOPPED/状态缺失/节点不在组内）→ 未知。
func vipHolderName(g *Group, st *haVipRuntime) string {
	if st == nil || st.Node == "" {
		return ""
	}
	if st.Group != "" && st.Group != g.Name {
		return ""
	}
	self := -1
	for i := range g.Members {
		if g.Members[i].NodeName == st.Node {
			self = i
			break
		}
	}
	if self < 0 {
		return ""
	}
	if isMasterOrHoldingVIP(st) {
		return st.Node
	}
	if strings.EqualFold(st.State, "BACKUP") && st.KeepalivedRunning {
		return g.Members[1-self].NodeName
	}
	return ""
}

// vipHolderFromStatuses 优先基于全部成员的新鲜汇聚状态判定当前 VIP 持有方，
// 缺失或不可判定时回退至本机状态文件（vipHolderName）。
func vipHolderFromStatuses(g *Group, statuses map[string]NodeRuntimeStatus, localFallback *haVipRuntime) string {
	if len(g.Members) != 2 {
		return ""
	}
	runtimes := make(map[string]*haVipRuntime, len(g.Members))
	masters := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		ns, ok := statuses[m.NodeName]
		if !ok || !ns.Fresh || len(ns.Status) == 0 {
			continue
		}
		var rt haVipRuntime
		if err := json.Unmarshal(ns.Status, &rt); err != nil {
			continue
		}
		if rt.Group != "" && rt.Group != g.Name {
			continue
		}
		if rt.Node == "" {
			rt.Node = m.NodeName
		}
		runtimes[m.NodeName] = &rt
		if isMasterOrHoldingVIP(&rt) {
			masters = append(masters, m.NodeName)
		}
	}
	if len(masters) == 1 {
		return masters[0]
	}
	if len(masters) >= 2 {
		// 脑裂态：双方均声称持有 VIP，不判定为唯一持有方
		return ""
	}
	// 无明确 MASTER 时，若恰有一侧新鲜上报 BACKUP+running 且对端无新鲜非 MASTER 状态，按 2 节点健康推断对端持有
	for i, m := range g.Members {
		rt := runtimes[m.NodeName]
		if rt == nil {
			continue
		}
		peerName := g.Members[1-i].NodeName
		if _, peerHasFresh := runtimes[peerName]; peerHasFresh {
			// 对端也有新鲜状态但未报 MASTER/VIP（如双方均 BACKUP 或 FAULT），不盲猜
			continue
		}
		if strings.EqualFold(rt.State, "BACKUP") && rt.KeepalivedRunning {
			return peerName
		}
	}
	if len(runtimes) > 0 {
		return ""
	}
	return vipHolderName(g, localFallback)
}

// ---------- 内部 ----------

func groupHasNode(g *Group, nodeName string) bool {
	if g == nil || nodeName == "" {
		return false
	}
	for _, m := range g.Members {
		if m.NodeName == nodeName {
			return true
		}
	}
	return false
}

func (h *Handler) shouldWriteLocal(g *Group) bool {
	return h.localNodeName == "" || groupHasNode(g, h.localNodeName)
}

func (h *Handler) collectMemberStatuses(ctx context.Context, groups []Group) map[string]NodeRuntimeStatus {
	now := h.now().UTC()
	memberSet := map[string]bool{}
	memberNames := make([]string, 0, len(groups)*2)
	for i := range groups {
		for _, m := range groups[i].Members {
			if m.NodeName != "" && !memberSet[m.NodeName] {
				memberSet[m.NodeName] = true
				memberNames = append(memberNames, m.NodeName)
			}
		}
	}

	out := map[string]NodeRuntimeStatus{}
	if h.statusProvider != nil && len(memberNames) > 0 {
		remoteStatuses, err := h.statusProvider.GetNodeHaVipStatuses(ctx, memberNames)
		if err != nil {
			slog.Warn("获取远端节点 HA 运行状态失败（降级为本机状态）", "error", err)
		} else {
			for nodeName, ns := range remoteStatuses {
				if !memberSet[nodeName] {
					continue
				}
				ns.NodeName = nodeName
				if ns.Source == "" {
					ns.Source = "remote"
				}
				if len(ns.Status) > 0 {
					var tmp any
					if err := json.Unmarshal(ns.Status, &tmp); err != nil {
						slog.Warn("远端节点 ha_vip_status JSON 非法，忽略", "node", nodeName, "error", err)
						ns.Status = nil
					}
				}
				ns.Fresh = len(ns.Status) > 0 && ns.UpdatedAt != nil && now.Sub(*ns.UpdatedAt) <= vipStatusFreshCutoff
				out[nodeName] = ns
			}
		}
	}

	// 合并本机 sidecar 状态文件（仅当该节点属于请求组集合时纳入，且仅在更年轻/缺失时覆盖）
	localRaw, localMod := readHaVipStatusWithMeta(h.dir())
	if len(localRaw) > 0 && localMod != nil {
		var rt haVipRuntime
		_ = json.Unmarshal(localRaw, &rt)
		localNode := strings.TrimSpace(rt.Node)
		if localNode == "" {
			localNode = h.localNodeName
		}
		if localNode != "" && memberSet[localNode] {
			localFresh := now.Sub(*localMod) <= vipStatusFreshCutoff
			existing, hasExisting := out[localNode]
			if !hasExisting || existing.UpdatedAt == nil || localMod.After(*existing.UpdatedAt) || (localFresh && !existing.Fresh) {
				out[localNode] = NodeRuntimeStatus{
					NodeName:  localNode,
					Status:    localRaw,
					UpdatedAt: localMod,
					Fresh:     localFresh,
					Source:    "local",
				}
			}
		}
	}
	return out
}

func isGroupSplitBrain(g *Group, statuses map[string]NodeRuntimeStatus) bool {
	masters := 0
	for _, m := range g.Members {
		ns, ok := statuses[m.NodeName]
		if !ok || !ns.Fresh || len(ns.Status) == 0 {
			continue
		}
		var rt haVipRuntime
		if err := json.Unmarshal(ns.Status, &rt); err != nil {
			continue
		}
		if rt.Group != "" && rt.Group != g.Name {
			continue
		}
		if isMasterOrHoldingVIP(&rt) {
			masters++
		}
	}
	return masters >= 2
}

// validate 校验并归一化输入（成员节点存在性经 NodeLister），并解析成员
// 节点名入 Group.Members[].NodeName（下发 member.node 的数据源）。
func (h *Handler) validate(r *http.Request, in *UpsertInput) (*Group, error) {
	g, err := ValidateInput(in, func(nodeID string) bool {
		ok, err := h.nodes.Exists(r.Context(), nodeID)
		return err == nil && ok
	})
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(g.Members))
	for _, m := range g.Members {
		ids = append(ids, m.NodeID)
	}
	names, err := h.nodes.Names(r.Context(), ids)
	if err != nil {
		return nil, fmt.Errorf("解析成员节点名: %w", err)
	}
	for i := range g.Members {
		g.Members[i].NodeName = names[g.Members[i].NodeID]
	}
	if h.bridgeChecker != nil {
		memberNodes := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			if m.NodeName != "" {
				memberNodes = append(memberNodes, m.NodeName)
			}
		}
		conflictNode, bridgeName, err := h.bridgeChecker(r.Context(), memberNodes, g.Iface)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", errBridgePortCheckInternal, err)
		}
		if bridgeName != "" {
			return nil, fmt.Errorf("接口 %s 在节点 %s 上已作为网桥 %s 成员口，禁止用作 HA VRRP 承载网卡", g.Iface, conflictNode, bridgeName)
		}
	}
	return g, nil
}

// resolveAuthOnCreate 创建时认证串处理（nil/空 = 不配置）。
func (h *Handler) resolveAuthOnCreate(authPass *string) (string, error) {
	if authPass == nil || *authPass == "" {
		return "", nil
	}
	return h.resolveAuth(*authPass)
}

// resolveAuth 加密认证串（未装配加密服务时拒绝——不出现明文落库）。
func (h *Handler) resolveAuth(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if h.enc == nil {
		return "", fmt.Errorf("未装配加密服务，无法安全保存 VRRP 认证串")
	}
	return h.enc.Encrypt(plain)
}

// buildSidecarPayload 构造并序列化 ha-vip.json 字节（认证串取库内密文解密；解密失败显式报错）。
func (h *Handler) buildSidecarPayload(ctx context.Context, g *Group) ([]byte, error) {
	plain := ""
	if g.HasAuthPass {
		if h.enc == nil {
			return nil, fmt.Errorf("组配置了 VRRP 认证串，但未装配加密服务，无法下发")
		}
		cipher, err := h.storeAuthCiphertext(ctx, g.ID)
		if err != nil {
			return nil, fmt.Errorf("读取认证串密文: %w", err)
		}
		plain, err = h.enc.Decrypt(cipher)
		if err != nil {
			return nil, fmt.Errorf("认证串解密失败: %w", err)
		}
	}
	var peers []string
	if g.Unicast {
		peers = g.UnicastPeers
	}
	return marshalHaVipFile(buildHaVipFile(g, plain, peers, h.now()))
}

// syncSidecarPush 下发 ha-vip.json 到本机（若本机属该组或单机模式）及远端成员（若已装配 RemoteSyncer）。
// 若 prev 非空且成员发生变更，同步向被移出成员发出收回删除，防止旧节点残留 VIP。
func (h *Handler) syncSidecarPush(ctx context.Context, g *Group, prev *Group) ([]SyncResult, error) {
	payload, err := h.buildSidecarPayload(ctx, g)
	if err != nil {
		return nil, err
	}
	results := make([]SyncResult, 0, len(g.Members)+1)

	if h.shouldWriteLocal(g) {
		if err := writeHaVipBytes(h.dir(), payload); err != nil {
			h.recordEvent(ctx, HaEvent{
				GroupID:   g.ID,
				GroupName: g.Name,
				NodeName:  h.localNodeName,
				EventType: EventTypeSyncFailed,
				Detail: map[string]any{
					"scope": "local",
					"op":    "push",
					"error": err.Error(),
				},
				OccurredAt: h.now().UTC(),
			})
			return nil, err
		}
		results = append(results, SyncResult{
			NodeName: h.localNodeName,
			Scope:    "local",
			Status:   "SUCCESS",
		})
	} else if prev != nil && h.localNodeName != "" && groupHasNode(prev, h.localNodeName) {
		// 本机原本在该组、本次更新被移出组：删除本机 ha-vip.json 收回 VIP
		if err := deleteHaVipJSON(h.dir()); err != nil {
			return nil, err
		}
		results = append(results, SyncResult{
			NodeName: h.localNodeName,
			Scope:    "local",
			Status:   "SUCCESS",
		})
	}

	if h.remoteSyncer != nil {
		newSet := map[string]bool{}
		for _, m := range g.Members {
			if m.NodeName == "" {
				continue
			}
			newSet[m.NodeName] = true
			if m.NodeName == h.localNodeName {
				continue
			}
			if err := h.remoteSyncer.PushHaVip(ctx, m.NodeName, payload); err != nil {
				slog.Warn("推送远端节点 ha-vip.json 失败", "group", g.Name, "node", m.NodeName, "error", err)
				results = append(results, SyncResult{
					NodeName: m.NodeName,
					Scope:    "remote",
					Status:   "FAILED",
					Error:    err.Error(),
				})
				h.recordEvent(ctx, HaEvent{
					GroupID:   g.ID,
					GroupName: g.Name,
					NodeName:  m.NodeName,
					EventType: EventTypeSyncFailed,
					Detail: map[string]any{
						"scope": "remote",
						"op":    "push",
						"error": err.Error(),
					},
					OccurredAt: h.now().UTC(),
				})
				continue
			}
			results = append(results, SyncResult{
				NodeName: m.NodeName,
				Scope:    "remote",
				Status:   "SUCCESS",
			})
		}

		// 若本次更新移除了旧成员，通知被移除远端节点收回 ha-vip.json
		if prev != nil {
			for _, om := range prev.Members {
				if om.NodeName == "" || om.NodeName == h.localNodeName || newSet[om.NodeName] {
					continue
				}
				if err := h.remoteSyncer.DeleteHaVip(ctx, om.NodeName); err != nil {
					slog.Warn("收回已移出成员的远端 ha-vip.json 失败", "group", g.Name, "node", om.NodeName, "error", err)
					results = append(results, SyncResult{
						NodeName: om.NodeName,
						Scope:    "remote",
						Status:   "FAILED",
						Error:    err.Error(),
					})
					h.recordEvent(ctx, HaEvent{
						GroupID:   g.ID,
						GroupName: g.Name,
						NodeName:  om.NodeName,
						EventType: EventTypeSyncFailed,
						Detail: map[string]any{
							"scope": "remote",
							"op":    "delete_removed_member",
							"error": err.Error(),
						},
						OccurredAt: h.now().UTC(),
					})
					continue
				}
				results = append(results, SyncResult{
					NodeName: om.NodeName,
					Scope:    "remote",
					Status:   "SUCCESS",
				})
			}
		}
	}
	return results, nil
}

// syncSidecarDelete 删除组时收回本机（按成员归属防误删）与远端成员的 ha-vip.json。
func (h *Handler) syncSidecarDelete(ctx context.Context, g *Group) ([]SyncResult, error) {
	results := make([]SyncResult, 0, len(g.Members)+1)

	shouldDeleteLocal, err := h.shouldDeleteLocal(ctx, g)
	if err != nil {
		return nil, err
	}
	if shouldDeleteLocal {
		if err := deleteHaVipJSON(h.dir()); err != nil {
			h.recordEvent(ctx, HaEvent{
				GroupID:   g.ID,
				GroupName: g.Name,
				NodeName:  h.localNodeName,
				EventType: EventTypeSyncFailed,
				Detail: map[string]any{
					"scope": "local",
					"op":    "delete",
					"error": err.Error(),
				},
				OccurredAt: h.now().UTC(),
			})
			return nil, err
		}
		results = append(results, SyncResult{
			NodeName: h.localNodeName,
			Scope:    "local",
			Status:   "SUCCESS",
		})
	}

	if h.remoteSyncer != nil {
		for _, m := range g.Members {
			if m.NodeName == "" || m.NodeName == h.localNodeName {
				continue
			}
			if err := h.remoteSyncer.DeleteHaVip(ctx, m.NodeName); err != nil {
				slog.Warn("删除远端节点 ha-vip.json 失败", "group", g.Name, "node", m.NodeName, "error", err)
				results = append(results, SyncResult{
					NodeName: m.NodeName,
					Scope:    "remote",
					Status:   "FAILED",
					Error:    err.Error(),
				})
				h.recordEvent(ctx, HaEvent{
					GroupID:   g.ID,
					GroupName: g.Name,
					NodeName:  m.NodeName,
					EventType: EventTypeSyncFailed,
					Detail: map[string]any{
						"scope": "remote",
						"op":    "delete",
						"error": err.Error(),
					},
					OccurredAt: h.now().UTC(),
				})
				continue
			}
			results = append(results, SyncResult{
				NodeName: m.NodeName,
				Scope:    "remote",
				Status:   "SUCCESS",
			})
		}
	}
	return results, nil
}

// shouldDeleteLocal 仅当本机属于待删组（或未设置本机节点名且本机文件归属该组/无其他存活组）时删除本机 ha-vip.json。
func (h *Handler) shouldDeleteLocal(ctx context.Context, g *Group) (bool, error) {
	if h.localNodeName != "" {
		return groupHasNode(g, h.localNodeName), nil
	}
	if localGroup := readLocalHaVipGroupName(h.dir()); localGroup != "" {
		return localGroup == g.Name, nil
	}
	groups, err := h.store.List(ctx)
	if err != nil {
		return false, err
	}
	for _, other := range groups {
		if other.ID != g.ID {
			return false, nil
		}
	}
	return true, nil
}

func (h *Handler) recordEvent(ctx context.Context, ev HaEvent) {
	if err := h.store.RecordEvent(ctx, ev); err != nil {
		slog.Error("record ha event failed", "group", ev.GroupName, "event_type", ev.EventType, "error", err)
	}
}

// storeAuthCiphertext 取库内认证串密文（Repository 契约外能力，经类型断言）。
func (h *Handler) storeAuthCiphertext(ctx context.Context, id string) (string, error) {
	type auther interface {
		AuthCiphertext(ctx context.Context, id string) (string, error)
	}
	if s, ok := h.store.(auther); ok {
		return s.AuthCiphertext(ctx, id)
	}
	return "", fmt.Errorf("仓储不支持认证串读取")
}

// writeStoreError 仓储错误统一映射。
func (h *Handler) writeStoreError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		response.Error(w, r, http.StatusNotFound, response.CodeResourceNotFound, "主备组不存在")
	case errors.Is(err, ErrVersionConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "配置已被他人修改，请刷新后重试")
	case errors.Is(err, ErrNameConflict):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "组名已存在")
	case errors.Is(err, ErrNodeAlreadyInGroup):
		response.Error(w, r, http.StatusConflict, response.CodeResourceConflict, "所选成员节点已归属其他主备组，单个节点同一时间仅可加入一个主备组")
	default:
		response.InternalError(w, r, err)
	}
}

// recordAudit 写操作审计（主备/VIP 属高危，RiskHigh）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, action string, g *Group, result, failReason string) {
	if h.audits == nil || p == nil {
		return
	}
	raw, _ := json.Marshal(g)
	const limit = 4000
	summary := string(raw)
	if len(summary) > limit {
		summary = summary[:limit]
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "ha",
		Action:        action,
		ObjectType:    "ha_groups",
		ObjectID:      g.ID,
		ObjectName:    g.Name,
		AfterSummary:  summary,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskHigh,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record ha group audit failed", "group", g.Name, "error", err)
	}
}
