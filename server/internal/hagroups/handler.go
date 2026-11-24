// 主备高可用 REST 接口（docs/HA_ACTIVE_STANDBY_DESIGN.md §8.4，M2 范围）。
// 全部写操作：CSRF + 参数校验 + 操作审计（高危）；配置生效 = 保存 DB +
// 原子写 sidecars/ha-vip.json（havipd 执行），与 network.json 同一边车纪律。
package hagroups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

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

var errBridgePortCheckInternal = errors.New("check bridge port conflict failed")

// Handler 主备组处理器。
type Handler struct {
	store         Repository
	nodes         NodeLister
	enc           Encryptor // nil = 未装配加密服务
	audits        *audits.Service
	sidecarDir    string
	now           func() time.Time
	bridgeChecker BridgePortChecker
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
}

// List GET /api/v1/ha/groups
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	groups, err := h.store.List(r.Context())
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	response.JSON(w, r, http.StatusOK, map[string]any{
		"items":  groups,
		"status": readHaVipStatus(h.dir()),
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
	response.JSON(w, r, http.StatusOK, map[string]any{
		"group":  g,
		"status": readHaVipStatus(h.dir()),
	})
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
	if err := h.pushSidecar(r.Context(), g); err != nil {
		h.recordAudit(r, p, "create_ha_group", g, audits.ResultFailure, "配置已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, "create_ha_group", g, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{"group": g})
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
	if err := h.pushSidecar(r.Context(), ng); err != nil {
		h.recordAudit(r, p, "update_ha_group", ng, audits.ResultFailure, "配置已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, "update_ha_group", ng, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{"group": ng})
}

// Delete DELETE /api/v1/ha/groups/{id}
// 收回主备能力：先删边车配置（havipd 停止实例释放 VIP），再删 DB。
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
	if err := deleteHaVipJSON(h.dir()); err != nil {
		h.recordAudit(r, p, "delete_ha_group", g, audits.ResultFailure, "边车配置删除失败: "+err.Error())
		response.InternalError(w, r, err)
		return
	}
	if err := h.store.Delete(r.Context(), g.ID); err != nil {
		h.writeStoreError(w, r, err)
		return
	}
	h.recordAudit(r, p, "delete_ha_group", g, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{"message": "主备组已删除，VIP 已随配置收回释放"})
}

// Failback POST /api/v1/ha/groups/{id}/failback
// 人工回切（把 VIP 切到指定节点）：调整成员优先级后整体更新并重新下发。
// 请求体 {"node_id":"..."} = 期望持有 VIP 的节点。
//
// 判定以「VIP 实际持有」为准而非配置优先级：nopreempt 自动故障转移后，配置
// 高优先级节点并不持有 VIP，此时回切必须可执行（MED-29）。持有方判定来源为
// 本节点 havipd 回写状态（仅本节点卷，双节点汇聚待采集通道，见设计 §15 M2 边界）。
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

	holder := vipHolderName(g, readHaVipRuntime(h.dir(), h.now()))
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
	if err := h.pushSidecar(r.Context(), ng); err != nil {
		h.recordAudit(r, p, "failback_ha_group", ng, audits.ResultFailure, "优先级已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, "failback_ha_group", ng, audits.ResultSuccess, "")
	response.JSON(w, r, http.StatusOK, map[string]any{"message": msg, "group": ng})
}

// vipHolderName 由本节点运行状态推断当前 VIP 持有节点名（"" = 未知）：
//   - 本节点 MASTER/已持有 VIP → 本节点；
//   - 本节点 BACKUP 且 keepalived 存活 → 组内另一成员（2 节点组的健康推断：
//     本机不持有则对端持有）；
//   - 其他（FAULT/DISABLED/STOPPED/状态缺失/本节点不在组内）→ 未知。
func vipHolderName(g *Group, st *haVipRuntime) string {
	if st == nil || st.Node == "" {
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
	if st.State == "MASTER" || len(st.VIPsPresent) > 0 {
		return st.Node
	}
	if st.State == "BACKUP" && st.KeepalivedRunning {
		return g.Members[1-self].NodeName
	}
	return ""
}

// ---------- 内部 ----------

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

// pushSidecar 构造并写 ha-vip.json（认证串取库内密文解密；解密失败显式报错）。
func (h *Handler) pushSidecar(ctx context.Context, g *Group) error {
	plain := ""
	if g.HasAuthPass {
		if h.enc == nil {
			return fmt.Errorf("组配置了 VRRP 认证串，但未装配加密服务，无法下发")
		}
		cipher, err := h.storeAuthCiphertext(ctx, g.ID)
		if err != nil {
			return fmt.Errorf("读取认证串密文: %w", err)
		}
		plain, err = h.enc.Decrypt(cipher)
		if err != nil {
			return fmt.Errorf("认证串解密失败: %w", err)
		}
	}
	var peers []string
	if g.Unicast {
		peers = g.UnicastPeers
	}
	return writeHaVipJSON(h.dir(), buildHaVipFile(g, plain, peers, h.now()))
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
