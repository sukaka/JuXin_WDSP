// derive.go ack_state 五态派生与视图组装（NG-AZ-02 D6 冻结规则，纯函数便于单测）。
//
// 派生优先级（自上而下，首中即停）：
//  1. NEVER_ACKED：无 ACK 行（旧版网关/未启用授权快照——如实显示而非报错，D10）；
//  2. CLOCK_SKEW：|clock_skew_seconds| > 上限（D8：漂移达到租约尺度时该节点任何
//     时效判定不可信，优先生效于陈旧/水位判定）；
//  3. STALE_EXPIRED：staleness > lease（配置了租约但 applied_at 缺失 → 陈旧无界，
//     保守落 STALE_EXPIRED——无法证明在租约内即不得展示为新鲜）；
//  4. STALE_WITHIN_LEASE：staleness ≤ lease（或未配置租约——v1 语义不启用租约约束，
//     无过期一说）但水位落后管理面向量水位；
//  5. FRESH：水位 ≥ 管理面向量水位且 staleness ≤ lease（或无租约）。
//
// 水位缺失（节点 ACK 但未上报水位）按零向量参与比较（与 D3「缺失视为水位 0」同口径）。
package apiauthzacks

import (
	"time"

	"github.com/jiuzhang-waf/server/internal/apiruntime"
)

// 时钟漂移上限（D8）：默认 60 秒（与租约缺省同量级——漂移达到租约尺度时任何时效
// 判定都不可信）；系统设置 gateway_runtime.authz_clock_skew_max_seconds 覆盖，夹紧 10~300s
// （下限防止操作员压到心跳间隔以下造成系统性误报，上限防止放宽到失去约束意义）。
const (
	ClockSkewSettingGroup      = "gateway_runtime"
	ClockSkewSettingKey        = "authz_clock_skew_max_seconds"
	DefaultClockSkewMaxSeconds = 60
	minClockSkewMaxSeconds     = 10
	maxClockSkewMaxSeconds     = 300
)

// ClampClockSkewMax 漂移上限夹紧到 [10, 300]（与 gateway_runtime 设置校验同口径，
// 供 apiauthzacks 与 apiauthzwizard 共享唯一事实源）。
func ClampClockSkewMax(v int) int64 {
	if v < minClockSkewMaxSeconds {
		return minClockSkewMaxSeconds
	}
	if v > maxClockSkewMaxSeconds {
		return maxClockSkewMaxSeconds
	}
	return int64(v)
}

func clampClockSkewMax(v int) int64 {
	return ClampClockSkewMax(v)
}

// deriveNodeAck 单节点 ack_state 派生（规则见文件头注释；staleness 在任何
// 有 applied_at 的节点上都如实计算——包括 CLOCK_SKEW 节点，数值本身不隐瞒，
// 其不可信由 ack_state 标记承担）。
func deriveNodeAck(row AckRow, mgmt apiruntime.VectorWatermark, now time.Time, skewMaxSeconds int64) NodeAck {
	out := NodeAck{NodeName: row.NodeName, Status: row.Status, AckState: StateNeverAcked}
	if !row.HasAck {
		return out
	}
	out.AuthzPolicyVersion = row.AuthzPolicyVersion
	out.AuthzWatermark = row.AuthzWatermark
	out.AuthzAppliedAt = row.AuthzAppliedAt
	out.LastAckAt = row.LastAckAt
	out.LeaseSeconds = row.AuthzLeaseSeconds
	if row.AuthzAppliedAt != nil {
		v := int64(now.Sub(*row.AuthzAppliedAt) / time.Second)
		out.StalenessSeconds = &v
	}
	var skew int64
	if row.ClockSkewSeconds != nil {
		skew = *row.ClockSkewSeconds
	}
	if skew > skewMaxSeconds || skew < -skewMaxSeconds {
		out.AckState = StateClockSkew
		return out
	}
	leaseConfigured := row.AuthzLeaseSeconds != nil && *row.AuthzLeaseSeconds > 0
	if leaseConfigured && (out.StalenessSeconds == nil || *out.StalenessSeconds > *row.AuthzLeaseSeconds) {
		out.AckState = StateStaleExpired
		return out
	}
	wm := apiruntime.VectorWatermark{}
	if row.AuthzWatermark != nil {
		wm = *row.AuthzWatermark
	}
	if !wm.AtLeast(mgmt) {
		out.AckState = StateStaleWithinLease
		return out
	}
	out.AckState = StateFresh
	return out
}

// BuildView 组装全节点 ACK 视图：逐节点派生 ack_state，max_staleness_seconds 取
// 参与节点（有 applied_at 者，含 CLOCK_SKEW——数值如实上报）陈旧秒数最大值；
// 无参与节点为 null（不伪造 0——「无数据」与「最大陈旧为 0 秒」是两回事）。
// management_watermark 的 sources 保证非 null（空对象 = 尚无权威来源水位）。
func BuildView(rows []AckRow, mgmt apiruntime.VectorWatermark, now time.Time, skewMaxSeconds int64) View {
	items := make([]NodeAck, 0, len(rows))
	var maxStaleness *int64
	for _, row := range rows {
		ack := deriveNodeAck(row, mgmt, now, skewMaxSeconds)
		if ack.StalenessSeconds != nil && (maxStaleness == nil || *ack.StalenessSeconds > *maxStaleness) {
			v := *ack.StalenessSeconds
			maxStaleness = &v
		}
		items = append(items, ack)
	}
	if mgmt.Sources == nil {
		mgmt.Sources = map[string]int64{}
	}
	return View{
		Items:               items,
		MaxStalenessSeconds: maxStaleness,
		ManagementWatermark: mgmt,
		GeneratedAt:         now,
	}
}
