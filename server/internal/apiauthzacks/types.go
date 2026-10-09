// types.go 节点授权 ACK 视图类型（NG-AZ-02 D6；docs/nextgen/NG-AZ-02-watermark-lease-ack.md）。
//
// 本包实现 §1.4 只读查询 API：GET /api/v1/api-security/authz/node-acks——
// 全节点 ACK 视图（每节点 ack_state 五态派生 + 陈旧秒数 + 租约），顶层附
// max_staleness_seconds（最大陈旧窗口）与 management_watermark（管理面向量水位）。
// 事实源：api_gateway_nodes（节点活性）LEFT JOIN api_node_authz_acks（迁移 000173，
// 心跳 ACK 落库，见 apinodes.Store.RecordHeartbeat）；管理面向量水位 =
// api_authz_manual_revocation_seq 单行 manual_seq + api_authority_watermarks 逐来源合并。
package apiauthzacks

import (
	"time"

	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// ack_state 词表（NG-AZ-02 D6 派生规则；优先级自上而下，见 derive.go）。
const (
	StateFresh            = "FRESH"              // 水位 ≥ 管理面向量水位且 staleness ≤ lease
	StateStaleWithinLease = "STALE_WITHIN_LEASE" // staleness ≤ lease（或无租约）但水位落后管理面
	StateStaleExpired     = "STALE_EXPIRED"      // staleness > lease（陈旧越出租约）
	StateNeverAcked       = "NEVER_ACKED"        // 无 ACK 行（旧版网关/未启用授权快照，如实显示非报错）
	StateClockSkew        = "CLOCK_SKEW"         // |时钟漂移| > 上限（D8：该节点任何时效判定不可信）
)

// NodeAck 单节点授权 ACK 视图行（node-acks 出参 items 元素；§1.4 冻结字段集）。
// 指针字段 nil 序列化为 null——「无此事实」如实呈现，不伪造零值占位。
type NodeAck struct {
	NodeName           string                      `json:"node_name"`
	Status             string                      `json:"status"`               // 节点活性（api_gateway_nodes：ACTIVE/STALE/SILENT）
	AuthzPolicyVersion string                      `json:"authz_policy_version"` // 授权快照策略版本戳；空串 = 未上报
	AuthzWatermark     *apiruntime.VectorWatermark `json:"authz_watermark"`      // 节点当前应用快照的向量水位；null = 未上报
	AuthzAppliedAt     *time.Time                  `json:"authz_applied_at"`     // 节点应用快照时刻；null = 未应用过
	LastAckAt          *time.Time                  `json:"last_ack_at"`          // 管理面最近收拍时刻；null = 从未 ACK
	StalenessSeconds   *int64                      `json:"staleness_seconds"`    // now − authz_applied_at（可为负：节点时钟超前）；null = 未应用过授权快照（不参与最大陈旧窗口）
	LeaseSeconds       *int64                      `json:"lease_seconds"`        // 授权租约秒数；null = 未配置租约（v1 语义：不启用租约约束）
	AckState           string                      `json:"ack_state"`            // 五态词表（派生规则见 derive.go）
}

// View node-acks 顶层响应（§1.4：items + max_staleness_seconds + management_watermark）。
type View struct {
	Items               []NodeAck                  `json:"items"`
	MaxStalenessSeconds *int64                     `json:"max_staleness_seconds"` // 全节点最大陈旧窗口；null = 无参与节点（均从未应用授权快照）
	ManagementWatermark apiruntime.VectorWatermark `json:"management_watermark"`  // 当前管理面向量水位（比较基准）
	GeneratedAt         time.Time                  `json:"generated_at"`          // 视图生成时刻（staleness 计算基准，管理面时钟）
}

// AckRow 单节点 ACK 联查行（api_gateway_nodes LEFT JOIN api_node_authz_acks；
// store 出参，派生函数入参——与 DB 行一一对应，不含派生字段）。
type AckRow struct {
	NodeName           string
	Status             string
	HasAck             bool // 是否存在 api_node_authz_acks 行（false → NEVER_ACKED）
	LastAckAt          *time.Time
	AuthzPolicyVersion string
	AuthzWatermark     *apiruntime.VectorWatermark
	AuthzAppliedAt     *time.Time
	AuthzLeaseSeconds  *int64
	ClockSkewSeconds   *int64 // 实测漂移（server_now − 心跳时刻，可为负）；nil 按 0 参与判定
}
