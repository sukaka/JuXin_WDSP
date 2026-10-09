// authz_watermark.go 授权快照向量撤销水位与冲突对象（NG-AZ-02 决策消费侧类型）。
//
// 跨仓线契约（与 server/internal/gatewayconfig/guard.go RevocationWatermark /
// GuardAuthzConflictedObject、jiuzhang_guard authzWatermarkJSON 同形状同语义）：
// 向量水位 = {manual_seq, sources}；分量比较 A ≥ B ⇔ manual_seq 不小于且
// B.sources 每键在 A 中有不小于的值（任何一侧缺键按 0 计——旧版本快照缺水位
// 字段即水位 0 参与比较）。
package detectors

import "time"

// RevocationWatermark 向量撤销水位（NG-AZ-02 §1.1；快照编译时刻管理面水位的随行副本）。
type RevocationWatermark struct {
	ManualSeq int64            `json:"manual_seq"`
	Sources   map[string]int64 `json:"sources,omitempty"`
}

// AtLeast 分量比较：w ≥ other（D3/D4 比较语义唯一事实源；nil 视为零水位——
// other 为 nil 恒真，w 为 nil 仅当 other 各分量均为 0 时为真）。
func (w *RevocationWatermark) AtLeast(other *RevocationWatermark) bool {
	if other == nil {
		return true
	}
	if w == nil {
		w = &RevocationWatermark{}
	}
	if w.ManualSeq < other.ManualSeq {
		return false
	}
	for k, ov := range other.Sources {
		if w.Sources[k] < ov {
			return false
		}
	}
	return true
}

// ConflictedObject 决策侧排除对象键（NG-AZ-02 D7；与 api_authority_conflicts 同键口径：
// tenant_domain 空串 = COALESCE(tenant_id,”)）。
type ConflictedObject struct {
	ApplicationID string `json:"application_id"`
	ObjectType    string `json:"object_type"`
	TenantDomain  string `json:"tenant_domain,omitempty"`
	ObjectRef     string `json:"object_ref"`
}

// conflictedIndexKey 冲突集查找键（D7：app+object_type+object_ref——tenant 不入键
// （HMAC ref 本身域隔离，按对象保守归并：宁可 UNKNOWN 不放过；与快照编译侧索引同口径）。
func conflictedIndexKey(applicationID, objectType, objectRef string) string {
	return applicationID + "\x00" + objectType + "\x00" + objectRef
}

// BuildConflictedObjectIndex 冲突集 O(1) 查找索引（快照装配期构建，不可变共享）。
func BuildConflictedObjectIndex(objects []ConflictedObject) map[string]struct{} {
	if len(objects) == 0 {
		return nil
	}
	idx := make(map[string]struct{}, len(objects))
	for _, o := range objects {
		idx[conflictedIndexKey(o.ApplicationID, o.ObjectType, o.ObjectRef)] = struct{}{}
	}
	return idx
}

// Conflicted 命中判定（D7；nil 索引恒 false，v1 快照零开销）。
func Conflicted(idx map[string]struct{}, applicationID, objectType, objectRef string) bool {
	if idx == nil {
		return false
	}
	_, ok := idx[conflictedIndexKey(applicationID, objectType, objectRef)]
	return ok
}

// AuthzSnapshotSchemaV2 v2 快照 schema 闸门值（NG-AZ-02 D4-3；缺失/其他值按 v1 逐字节兼容）。
const AuthzSnapshotSchemaV2 = "authz-snap/2"

// authzV2 v2 语义启用判定（schema 闸门；v1 快照以下所有 v2 逻辑零介入）。
func authzV2(cfg AuthorizationConfig) bool { return cfg.Schema == AuthzSnapshotSchemaV2 }

// authzClockSkewMaxOrDefault 漂移上限（D8：≤0 缺省 60s；装配侧已夹紧 10~300，此处防御归一）。
func authzClockSkewMaxOrDefault(sec int) int {
	if sec <= 0 {
		return 60
	}
	if sec < 10 {
		return 10
	}
	if sec > 300 {
		return 300
	}
	return sec
}

// authzClockSkewExceeded D8 节点侧漂移自检：快照 produced_at 超前节点本地时钟超上限
// （节点时钟落后于管理面）即漂移。
//
// 语义修正（集成批实测登记的实现偏差）：原设计字面公式 |now − produced_at| > 阈值
// 会把快照**自然老化**误判为漂移——快照有效期 24h，任何快照在产生后 >60s 即全部
// 落入 AUTHZ-CLOCK-001（stage5 实测复现：发布 60s 后所有授权决策退化）。正向差值
// （快照比节点旧）是正常老化，归 D5 租约/陈旧口径与服务端心跳 skew（B 轨）处理；
// 节点侧自检只对无歧义的负向差值（produced_at 在未来 = 节点时钟落后）生效。
func authzClockSkewExceeded(cfg AuthorizationConfig, now time.Time) bool {
	if !authzV2(cfg) || cfg.ProducedAt == nil {
		return false
	}
	return cfg.ProducedAt.UTC().After(now.Add(time.Duration(authzClockSkewMaxOrDefault(cfg.ClockSkewMaxSeconds)) * time.Second))
}

// authzLeaseExpired D5 租约过期判定：本地时钟 vs 快照应用时刻（applied_at 由装配侧
// 以节点时钟写入——不依赖管理面时钟；v1/未配置租约/无应用时刻恒 false）。
func authzLeaseExpired(cfg AuthorizationConfig, now time.Time) bool {
	if !authzV2(cfg) || cfg.LeaseSeconds <= 0 || cfg.AppliedAt.IsZero() {
		return false
	}
	return now.After(cfg.AppliedAt.Add(time.Duration(cfg.LeaseSeconds) * time.Second))
}

// authzTimedOutReason strict 端点（OnLeaseExpired != "degraded"）时效拒绝原因：
// 漂移（D8）优先于租约（D5）；degraded 端点/无时效问题返回空串（照常评估+事后标记）。
func authzTimedOutReason(model ObjectModel, skewExceeded, leaseExpired bool) string {
	if model.OnLeaseExpired == "degraded" {
		return ""
	}
	if skewExceeded {
		return "AUTHZ-CLOCK-001"
	}
	if leaseExpired {
		return "AUTHZ-LEASE-001"
	}
	return ""
}

// authzDegradedMarkerReason degraded 端点的事后标记 reason（D5/D8：评估继续但
// 强制 OBSERVE 级 + UNKNOWN 标记；租约与漂移并存时租约优先标记）。
func authzDegradedMarkerReason(model ObjectModel, skewExceeded, leaseExpired bool) string {
	if model.OnLeaseExpired != "degraded" || (!skewExceeded && !leaseExpired) {
		return ""
	}
	if leaseExpired {
		return "AUTHZ-LEASE-002"
	}
	return "AUTHZ-CLOCK-001"
}
