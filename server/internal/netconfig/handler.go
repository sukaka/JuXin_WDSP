package netconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/authz"
	"github.com/jiuzhang-waf/server/internal/middleware"
	"github.com/jiuzhang-waf/server/internal/nodeinterfaces"
	"github.com/jiuzhang-waf/server/internal/response"
)

// HAVRRPIfaceChecker 检查接口是否正被启用的主备组用作 VRRP 承载网卡（返回冲突组名；空串 = 未占用）。
type HAVRRPIfaceChecker func(ctx context.Context, nodeName, iface string) (conflictGroup string, err error)

// RemoteSyncer 远端网关节点 network.json 推送接口（由 *nodesync.Manager 实现）。
type RemoteSyncer interface {
	PushNetworkConfig(ctx context.Context, nodeName string, payload []byte) error
}

// RemoteStatusProvider 远端网关节点网络配置可编辑性与汇聚状态查询接口（由 *nodesync.Manager 实现）。
type RemoteStatusProvider interface {
	IsRemoteEditable(ctx context.Context, nodeName string) (bool, error)
	GetNodeNetworkStatus(ctx context.Context, nodeName string) (json.RawMessage, error)
}

// RemoteEditableNodeLister 可选扩展接口：列举所有支持远端推送的节点名（用于 DNS/NTP 重写扇出）。
type RemoteEditableNodeLister interface {
	ListRemoteEditableNodes(ctx context.Context) ([]string, error)
}

// Handler 节点网络配置（网桥/路由牵引）处理器。
type Handler struct {
	store          Repository
	ifaces         InterfaceLister
	audits         *audits.Service
	defaultNode    string // 本网关节点名（cfg.WAF.GatewayNodeName）
	sidecarDir     string // 边车配置目录（空用 DefaultSidecarDir）
	haIfaceChecker HAVRRPIfaceChecker
	onChange       func(ctx context.Context)
	remoteSyncer   RemoteSyncer
	remoteStatus   RemoteStatusProvider
}

// NewHandler 创建处理器（构造注入审计服务与默认节点名，语义同 nodeinterfaces）。
func NewHandler(store Repository, ifaces InterfaceLister, audit *audits.Service, defaultNode string) *Handler {
	return &Handler{store: store, ifaces: ifaces, audits: audit, defaultNode: defaultNode}
}

// SetSidecarDir 覆盖边车配置目录（默认 DefaultSidecarDir；测试用临时目录）。
func (h *Handler) SetSidecarDir(dir string) { h.sidecarDir = dir }

// SetHAVRRPIfaceChecker 注入主备组 VRRP 接口冲突检查器（禁止将活跃 VRRP 承载网卡加入网桥）。
func (h *Handler) SetHAVRRPIfaceChecker(fn HAVRRPIfaceChecker) *Handler {
	h.haIfaceChecker = fn
	return h
}

// SetOnChange 注册网络配置保存成功后的联动回调（如刷新 mirrorcap.json / tproxyd.json）。
func (h *Handler) SetOnChange(fn func(ctx context.Context)) *Handler {
	h.onChange = fn
	return h
}

// SetRemoteSyncer 注入远端节点 network.json 同步器（Phase 3 nodesync 装配）。
func (h *Handler) SetRemoteSyncer(s RemoteSyncer) *Handler {
	h.remoteSyncer = s
	return h
}

// SetRemoteStatusProvider 注入远端节点网络可编辑性与汇聚状态提供者（Phase 3 nodesync 装配）。
func (h *Handler) SetRemoteStatusProvider(p RemoteStatusProvider) *Handler {
	h.remoteStatus = p
	return h
}

// RewriteSidecar 按当前数据库配置与系统设置（network:dns_servers/ntp_servers）重写默认节点 network.json，
// 若装配了远端同步器则同时向远端可编辑节点推送最新 DNS/NTP 配置（单节点失败记告警日志不阻断本机）。
func (h *Handler) RewriteSidecar(ctx context.Context) error {
	var dns, ntp []string
	if sr, ok := h.store.(ServersReader); ok {
		d, n, err := sr.NetworkServers(ctx)
		if err != nil {
			slog.Warn("load network dns/ntp settings failed during rewrite", "node", h.defaultNode, "error", err)
		} else {
			dns, ntp = d, n
		}
	}

	cfg, _, found, err := h.store.Get(ctx, h.defaultNode)
	if err != nil {
		return err
	}
	if !found {
		cfg = DefaultConfig()
	}
	cfg.DNSServers = dns
	cfg.NTPServers = ntp
	now := time.Now().UTC()
	if err := writeNetworkJSON(h.dir(), cfg, now); err != nil {
		return err
	}

	if h.remoteSyncer != nil && h.remoteStatus != nil {
		if lister, ok := h.remoteStatus.(RemoteEditableNodeLister); ok {
			nodes, listErr := lister.ListRemoteEditableNodes(ctx)
			if listErr != nil {
				slog.Warn("list remote editable nodes failed during network sidecar rewrite", "error", listErr)
				return nil
			}
			for _, nodeName := range nodes {
				if nodeName == "" || nodeName == h.defaultNode {
					continue
				}
				rcfg, _, rfound, gErr := h.store.Get(ctx, nodeName)
				if gErr != nil {
					slog.Warn("load remote node network config failed during rewrite", "node", nodeName, "error", gErr)
					continue
				}
				if !rfound {
					rcfg = DefaultConfig()
				}
				rcfg.DNSServers = dns
				rcfg.NTPServers = ntp
				payload, mErr := marshalNetworkJSON(rcfg, now)
				if mErr != nil {
					slog.Warn("marshal remote network.json failed during rewrite", "node", nodeName, "error", mErr)
					continue
				}
				if pErr := h.remoteSyncer.PushNetworkConfig(ctx, nodeName, payload); pErr != nil {
					slog.Warn("push remote network.json failed during dns/ntp rewrite", "node", nodeName, "error", pErr)
				}
			}
		}
	}
	return nil
}

func (h *Handler) dir() string {
	if h.sidecarDir != "" {
		return h.sidecarDir
	}
	return DefaultSidecarDir
}

// RegisterRoutes 注册网络配置接口（权限：读 system_health.read，写 system_settings.update，
// 复用既有权限点不新增，对齐 nodeinterfaces）。
func RegisterRoutes(mux *http.ServeMux, authz func(http.Handler) http.Handler, h *Handler) {
	mux.Handle("GET /api/v1/gateway/network-config", authz(middleware.RequirePermission("system_health.read")(http.HandlerFunc(h.Get))))
	mux.Handle("PUT /api/v1/gateway/network-config", authz(middleware.RequirePermission("system_settings.update")(http.HandlerFunc(h.Update))))
}

// Desired 是 GET/PUT 响应中的期望配置（UpdatedAt 为 DB 保存时间，无记录时 null）。
type Desired struct {
	Config
	UpdatedAt *time.Time `json:"updated_at"`
}

// resolveNode 解析目标节点：空值回落默认节点。
func (h *Handler) resolveNode(nodeName string) string {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" {
		return h.defaultNode
	}
	return nodeName
}

// Get GET /api/v1/gateway/network-config?node_name=
// 返回 {desired, status, default_node, remote_editable}：desired 为 DB 期望配置（无记录返回空配置）；
// status 本机节点透传 sidecars/network-status.json，远端节点透传汇聚快照（缺失/解析失败为 null）。
func (h *Handler) Get(w http.ResponseWriter, r *http.Request) {
	nodeName := h.resolveNode(r.URL.Query().Get("node_name"))
	cfg, updatedAt, found, err := h.store.Get(r.Context(), nodeName)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	if !found {
		cfg = DefaultConfig()
	}
	desired := Desired{Config: cfg}
	if found {
		desired.UpdatedAt = &updatedAt
	}
	var status json.RawMessage
	remoteEditable := nodeName == h.defaultNode
	if nodeName == h.defaultNode {
		status = readNetworkStatus(h.dir())
	} else if h.remoteStatus != nil {
		if editable, err := h.remoteStatus.IsRemoteEditable(r.Context(), nodeName); err != nil {
			slog.Warn("check remote network editability failed", "node", nodeName, "error", err)
		} else {
			remoteEditable = editable && h.remoteSyncer != nil
		}
		if st, err := h.remoteStatus.GetNodeNetworkStatus(r.Context(), nodeName); err != nil {
			slog.Warn("load remote network status failed", "node", nodeName, "error", err)
		} else if len(st) > 0 && json.Valid(st) {
			status = st
		}
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"desired":         desired,
		"status":          status,
		"default_node":    h.defaultNode,
		"remote_editable": remoteEditable,
	})
}

// updateRequest 是 PUT 请求体（契约同 network.json 配置段；node_name 可选，
// 缺省默认节点；updated_at 由服务端生成，不接受客户端传入）。
type updateRequest struct {
	NodeName  string   `json:"node_name"`
	Bridges   []Bridge `json:"bridges"`
	IPForward bool     `json:"ip_forward"`
	Routes    []Route  `json:"routes"`
}

// Update PUT /api/v1/gateway/network-config
// 整体替换节点网络期望配置：严格校验 → 保存 DB → 本机写 sidecars/network.json 或远端经 hasyncd 推送 → 审计。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateRequest
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	nodeName := h.resolveNode(req.NodeName)
	isRemote := nodeName != h.defaultNode
	if isRemote {
		if h.remoteSyncer == nil || h.remoteStatus == nil {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				"当前仅支持配置本网关节点: "+h.defaultNode)
			return
		}
		editable, err := h.remoteStatus.IsRemoteEditable(r.Context(), nodeName)
		if err != nil {
			response.InternalError(w, r, err)
			return
		}
		if !editable {
			response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
				fmt.Sprintf("节点 %s 未配置协同代理，无法远程下发网络配置", nodeName))
			return
		}
	}
	cfg := Config{Bridges: req.Bridges, IPForward: req.IPForward, Routes: req.Routes}

	// 合并系统设置 network 组的 DNS/NTP 服务器（随 network.json 下发；读失败
	// 记日志降级为空，不阻断网络配置保存；空设置 = 不写字段，netmgrd 继承宿主机现状）
	if sr, ok := h.store.(ServersReader); ok {
		dns, ntp, err := sr.NetworkServers(r.Context())
		if err != nil {
			slog.Warn("load network dns/ntp settings failed", "node", nodeName, "error", err)
		} else {
			cfg.DNSServers = dns
			cfg.NTPServers = ntp
		}
	}

	groups, err := h.ifaces.ListGrouped(r.Context(), nodeName)
	if err != nil {
		response.InternalError(w, r, err)
		return
	}
	var ifaces []nodeinterfaces.Interface
	for _, g := range groups {
		ifaces = append(ifaces, g.Interfaces...)
	}
	if err := Validate(&cfg, ifaces); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, err.Error())
		return
	}
	if h.haIfaceChecker != nil {
		for _, b := range cfg.Bridges {
			for _, port := range b.Ports {
				conflictGroup, err := h.haIfaceChecker(r.Context(), nodeName, port)
				if err != nil {
					response.InternalError(w, r, err)
					return
				}
				if conflictGroup != "" {
					response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
						fmt.Sprintf("接口 %s 正被主备组 %s 用作 VRRP 承载网卡，禁止加入桥 %s", port, conflictGroup, b.Name))
					return
				}
			}
		}
	}

	// 审计 before 摘要（读取失败不阻断主流程，降级为空摘要并记日志）
	before := ""
	if old, _, found, err := h.store.Get(r.Context(), nodeName); err != nil {
		slog.Warn("load network config for audit before-summary failed", "node", nodeName, "error", err)
	} else if found {
		before = configSummary(old)
	}

	if err := h.store.Save(r.Context(), nodeName, cfg); err != nil {
		response.InternalError(w, r, err)
		return
	}
	now := time.Now().UTC()
	var status json.RawMessage
	if !isRemote {
		if err := writeNetworkJSON(h.dir(), cfg, now); err != nil {
			slog.Error("write network sidecar config failed", "node", nodeName, "error", err)
			h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultFailure,
				"配置已入库，但边车配置写入失败: "+err.Error())
			response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
			return
		}
		status = readNetworkStatus(h.dir())
	} else {
		payload, err := marshalNetworkJSON(cfg, now)
		if err != nil {
			h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultFailure,
				"配置已入库，但序列化边车配置失败: "+err.Error())
			response.InternalError(w, r, err)
			return
		}
		if err := h.remoteSyncer.PushNetworkConfig(r.Context(), nodeName, payload); err != nil {
			slog.Error("push remote network sidecar config failed", "node", nodeName, "error", err)
			h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultFailure,
				"配置已入库，但远端边车配置推送失败: "+err.Error())
			response.InternalError(w, r, fmt.Errorf("配置已保存，但推送远端节点 %s 边车配置失败: %w", nodeName, err))
			return
		}
		if st, err := h.remoteStatus.GetNodeNetworkStatus(r.Context(), nodeName); err == nil && len(st) > 0 && json.Valid(st) {
			status = st
		}
	}
	if h.onChange != nil {
		h.onChange(r.Context())
	}
	h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultSuccess, "")

	desired := Desired{Config: cfg, UpdatedAt: &now}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"desired":         desired,
		"status":          status,
		"default_node":    h.defaultNode,
		"remote_editable": true,
	})
}

// recordAudit 写操作审计（网络变更 MEDIUM 风险；审计服务/主体为 nil 时跳过）。
func (h *Handler) recordAudit(r *http.Request, p *authz.Principal, nodeName, before, after, result, failReason string) {
	if h.audits == nil || p == nil {
		return
	}
	if err := h.audits.Record(r.Context(), audits.RecordInput{
		UserID:        &p.UserID,
		Username:      p.Username,
		SourceIP:      middleware.RemoteIP(r),
		ConnectionIP:  middleware.ConnectionIP(r),
		UserAgent:     r.UserAgent(),
		Module:        "system",
		Action:        "update_gateway_network_config",
		ObjectType:    "node_network_configs",
		ObjectID:      nodeName,
		ObjectName:    nodeName,
		BeforeSummary: before,
		AfterSummary:  after,
		Result:        result,
		FailureReason: failReason,
		RiskLevel:     audits.RiskMedium,
		RequestID:     response.RequestIDFrom(r),
	}); err != nil {
		slog.Error("record network config audit failed", "node", nodeName, "error", err)
	}
}

// configSummary 生成配置审计摘要（紧凑 JSON，截断防爆长）。
func configSummary(cfg Config) string {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	const limit = 4000
	if len(raw) > limit {
		return string(raw[:limit])
	}
	return string(raw)
}
