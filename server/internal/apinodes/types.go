// types.go 节点实体、聚合结果与一致性报告类型（sweeper/store/handler 共用）。
package apinodes

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// 节点状态词表（按最近事件距当前时刻的时长判定，边界口径见 StatusFor）。
const (
	StatusActive = "ACTIVE" // 5 分钟内有事件
	StatusStale  = "STALE"  // 5 分钟~1 小时无事件
	StatusSilent = "SILENT" // 超过 1 小时无事件（或从未有事件）
)

// 状态判定窗口（任务书口径：ACTIVE 5min 内 / STALE 5min-1h / SILENT >1h）。
const (
	ActiveWindow = 5 * time.Minute
	StaleWindow  = time.Hour
)

// Node 节点版本视图行（api_gateway_nodes）。
type Node struct {
	ID                uuid.UUID `json:"id"`
	NodeName          string    `json:"node_name"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`        // 最近活性时间（业务事件与心跳取新；状态判定基准）
	LastPolicyVersion string    `json:"last_policy_version"` // 心跳上报优先，否则最新业务事件版本；空串 = 未上报（旧版网关）
	LastModelVersion  string    `json:"last_model_version"`  // 最新业务事件模型版本；空串 = 未上报
	EventCount        int64     `json:"event_count"`         // 业务事件总数（心跳不计数）
	Status            string    `json:"status"`
	// W18-SYNC §200 配置面主动同步登记与结果（只读带出；登记编辑走 PATCH /nodes/{id}）：
	AdminAddr         string     `json:"admin_addr"`           // Caddy Admin 通道标识；空串 = 未登记
	SyncEnabled       bool       `json:"sync_enabled"`         // 是否参与发布扇出
	LastSyncAt        *time.Time `json:"last_sync_at"`         // 最近同步尝试时间；nil = 从未同步
	LastSyncResult    string     `json:"last_sync_result"`     // SUCCESS/FAILED/HASH_MISMATCH；空串 = 从未同步
	LastSyncError     string     `json:"last_sync_error"`      // 最近失败原因（截断）；空串 = 无错误
	LastSyncVersionID *uuid.UUID `json:"last_sync_version_id"` // 最近同步尝试的配置版本；nil = 从未同步
	// HA Phase 3 协同代理与遥测汇聚字段（000236；sync_secret 永不回显，仅返回 has_sync_secret）：
	SyncAgentAddr   string          `json:"sync_agent_addr"`   // hasyncd 协同代理地址；空串 = 未配置
	HasSyncSecret   bool            `json:"has_sync_secret"`   // 是否已配置 hasyncd 共享密钥
	ReportedVersion string          `json:"reported_version"`  // hasyncd 上报的系统版本
	HaVipStatus     json.RawMessage `json:"ha_vip_status"`     // 节点汇聚的 ha-vip-status.json 快照
	HaVipStatusAt   *time.Time      `json:"ha_vip_status_at"`  // ha_vip_status 最近采集时间
	NetworkStatus   json.RawMessage `json:"network_status"`    // 节点汇聚的 network-status.json 快照
	NetworkStatusAt *time.Time      `json:"network_status_at"` // network_status 最近采集时间
	// VersionConsistent 该节点策略版本是否与活跃多数派一致（读接口读出时计算，
	// 不落库）；nil = 未参与判定（SILENT 离线或未上报版本）。
	VersionConsistent *bool     `json:"version_consistent"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// CreateNodeInput 管理员手动登记新网关节点的持久化入参（SyncSecretCiphertext 已由上层加密）。
type CreateNodeInput struct {
	NodeName             string
	AdminAddr            string
	SyncAgentAddr        string
	SyncSecretCiphertext string
	SyncEnabled          bool
}

// SyncRegistrationUpdate 节点同步登记更新参数（SyncSecretCiphertext nil = 保持不变，*"" = 清除，非空 = 替换密文）。
type SyncRegistrationUpdate struct {
	AdminAddr            string
	SyncAgentAddr        string
	SyncSecretCiphertext *string
	SyncEnabled          bool
}

// NodeSyncCredentials 节点协同代理凭据与状态快照（内部服务使用，绝不直接序列化返回前端）。
type NodeSyncCredentials struct {
	NodeID               uuid.UUID
	NodeName             string
	AdminAddr            string
	SyncAgentAddr        string
	SyncSecretCiphertext string `json:"-"`
	SyncEnabled          bool
	ReportedVersion      string
	HaVipStatus          json.RawMessage
	HaVipStatusAt        *time.Time
	NetworkStatus        json.RawMessage
	NetworkStatusAt      *time.Time
}

// NodeTelemetryUpdate 节点协同遥测周期拉取（GET /v1/status）回填参数。
type NodeTelemetryUpdate struct {
	NodeName        string
	LastSeenAt      time.Time
	PolicyVersion   string
	ReportedVersion string
	HaVipStatus     json.RawMessage
	HaVipStatusAt   *time.Time
	NetworkStatus   json.RawMessage
	NetworkStatusAt *time.Time
}

// NodeTestResult 节点连通性探测结果（POST /api/v1/api-security/nodes/{id}/test）。
type NodeTestResult struct {
	OK             bool   `json:"ok"`
	Channel        string `json:"channel"` // "hasyncd" | "caddy_admin" | "none"
	LatencyMs      int64  `json:"latency_ms"`
	Version        string `json:"version,omitempty"`
	CaddyReachable *bool  `json:"caddy_reachable,omitempty"`
	HostctlReady   *bool  `json:"hostctl_ready,omitempty"`
	UpgradeReady   *bool  `json:"upgrade_ready,omitempty"`
	Error          string `json:"error,omitempty"`
}

// NodeAggregate 单节点聚合结果（api_runtime_events 按 gateway_node 分组）。
type NodeAggregate struct {
	NodeName          string
	FirstSeenAt       time.Time
	LastSeenAt        time.Time
	LastPolicyVersion string // 最新非空策略版本；空串 = 未上报
	LastModelVersion  string // 最新非空模型版本；空串 = 未上报
	EventCount        int64
}

// VersionGroup 一致性分组（活跃节点按 last_policy_version 分组；
// PolicyVersion 为空串的组 = 已上报缺失（旧版网关未携带版本），如实单列）。
type VersionGroup struct {
	PolicyVersion string   `json:"policy_version"`
	NodeCount     int      `json:"node_count"`
	Nodes         []string `json:"nodes"`
}

// ConsistencyReport 一致性报告（/nodes/consistency 出参；判定口径见 EvaluateConsistency）。
type ConsistencyReport struct {
	// Consistent 活跃且已上报版本的节点版本去重 ≤ 1。
	// 参与判定节点为 0（无版本数据可比）时如实为 true——不谎报不一致，
	// 以 EvaluatedNodes=0 呈现「无数据可判」。
	Consistent      bool           `json:"consistent"`
	EvaluatedNodes  int            `json:"evaluated_nodes"`  // 参与判定节点数
	DominantVersion string         `json:"dominant_version"` // 多数派版本（无参与节点时为空串）
	Groups          []VersionGroup `json:"groups"`           // 活跃节点分组（含未上报空串组）
	SilentNodes     []string       `json:"silent_nodes"`     // SILENT 节点（离线不参与判定，如实列出）
	GeneratedAt     time.Time      `json:"generated_at"`
}
