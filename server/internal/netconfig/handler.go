package netconfig

import (
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

// Handler 节点网络配置（网桥/路由牵引）处理器。
type Handler struct {
	store       Repository
	ifaces      InterfaceLister
	audits      *audits.Service
	defaultNode string // 本网关节点名（cfg.WAF.GatewayNodeName）
	sidecarDir  string // 边车配置目录（空用 DefaultSidecarDir）
}

// NewHandler 创建处理器（构造注入审计服务与默认节点名，语义同 nodeinterfaces）。
func NewHandler(store Repository, ifaces InterfaceLister, audit *audits.Service, defaultNode string) *Handler {
	return &Handler{store: store, ifaces: ifaces, audits: audit, defaultNode: defaultNode}
}

// SetSidecarDir 覆盖边车配置目录（默认 DefaultSidecarDir；测试用临时目录）。
func (h *Handler) SetSidecarDir(dir string) { h.sidecarDir = dir }

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
// 返回 {desired, status}：desired 为 DB 期望配置（无记录返回空配置）；
// status 透传 sidecars/network-status.json（仅默认节点；文件不存在/解析失败为 null）。
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
	// network-status.json 位于本网关节点共享卷，仅默认节点可透传（其他节点无本卷状态）
	if nodeName == h.defaultNode {
		status = readNetworkStatus(h.dir())
	}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{"desired": desired, "status": status})
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
// 整体替换节点网络期望配置：严格校验（见包注释）→ 保存 DB → 原子写
// sidecars/network.json → 审计（module=system，网络变更 MEDIUM 风险）。
func (h *Handler) Update(w http.ResponseWriter, r *http.Request) {
	p := authz.PrincipalFrom(r.Context())
	var req updateRequest
	if err := response.DecodeJSON(w, r, &req, 65536); err != nil {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument, "请求格式错误")
		return
	}
	nodeName := h.resolveNode(req.NodeName)
	// 安全约束：sidecar 卷属于本网关节点，写非默认节点即把配置下发到错误执行端
	if nodeName != h.defaultNode {
		response.Error(w, r, http.StatusBadRequest, response.CodeInvalidArgument,
			"当前仅支持配置本网关节点: "+h.defaultNode)
		return
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
	if err := writeNetworkJSON(h.dir(), cfg, now); err != nil {
		slog.Error("write network sidecar config failed", "node", nodeName, "error", err)
		h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultFailure,
			"配置已入库，但边车配置写入失败: "+err.Error())
		response.InternalError(w, r, fmt.Errorf("配置已保存，但下发边车配置失败: %w", err))
		return
	}
	h.recordAudit(r, p, nodeName, before, configSummary(cfg), audits.ResultSuccess, "")

	desired := Desired{Config: cfg, UpdatedAt: &now}
	response.JSON(w, r, http.StatusOK, map[string]interface{}{
		"desired": desired,
		"status":  readNetworkStatus(h.dir()),
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
