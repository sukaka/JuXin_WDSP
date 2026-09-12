// types.go 节点实体、聚合结果与一致性报告类型（sweeper/store/handler 共用）。
package apinodes

import (
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
	// VersionConsistent 该节点策略版本是否与活跃多数派一致（读接口读出时计算，
	// 不落库）；nil = 未参与判定（SILENT 离线或未上报版本）。
	VersionConsistent *bool     `json:"version_consistent"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
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
