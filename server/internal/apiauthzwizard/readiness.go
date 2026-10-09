// Package apiauthzwizard PROTECT 切换向导服务端（NG-AZ-04，docs/nextgen/NG-AZ-04-protect-wizard.md）。
//
// 四个端点（§1.1~§1.4 冻结契约）：
//   - GET  /api/v1/api-security/authz/enforcement-readiness（§1.2 六态派生 + reasons 全列）
//   - POST /api/v1/api-security/authz/enforcement-impact（§1.3 影响评估 + manage 签发 confirm_token）
//   - GET  /api/v1/api-security/authz/enforcement-confirmations（确认单查询）+ POST .../{id}/sign（签署）
//   - GET  /api/v1/api-security/authz/conflicts（D1 注：OPEN 冲突独立分页查询）
//
// readiness 派生规则为本包唯一事实源（与网关消费侧同语义的服务端翻译——前端只渲染
// 徽章与 reasons，不在 JS 复制判定逻辑）；权限全部沿用既有点（read/evidence_read/manage，
// 零新增）。
package apiauthzwizard

import (
	"fmt"
	"strings"
)

// readiness 词表（§1.2 冻结六态 + PROTECT_ACTIVE 展示态）。
const (
	ReadinessReady               = "READY"
	ReadinessProtectActive       = "PROTECT_ACTIVE"
	ReadinessNotPublishable      = "NOT_PUBLISHABLE"
	ReadinessBlockedByNoRelation = "BLOCKED_BY_NO_RELATION"
	ReadinessBlockedByConflict   = "BLOCKED_BY_CONFLICT"
	ReadinessBlockedByStale      = "BLOCKED_BY_STALE"
	ReadinessBlockedByNode       = "BLOCKED_BY_NODE"
)

// ReadinessInput readiness 派生输入（按对象模型行逐行；全部事实由 store 层采集，
// 本结构不含任何 IO——派生为纯函数，测试矩阵直接构造）。
type ReadinessInput struct {
	// 资格字段（§1.2：publishable+OWNER+排他+端点 CONFIRMED）
	Publishable       bool
	RequiredRelation  string
	OwnerExclusive    bool
	EndpointConfirmed bool
	// Enforcement 当前值（PROTECT → PROTECT_ACTIVE 展示态）
	Enforcement string
	// 关系事实：该端点对象类型存在有效 OWNER 关系（CONFIRMED 且窗口内）
	HasEffectiveOwnerRelation bool
	// 冲突事实：该端点对象类型存在 OPEN 冲突
	HasOpenConflict bool
	// 时效事实（§1.2 BLOCKED_BY_STALE：快照过期/租约过期/时钟偏差）
	SnapshotExpired bool
	LeaseExpired    bool
	ClockSkew       bool
	// 通道事实（§1.2 BLOCKED_BY_NODE：节点 ACK≠FRESH / 能力自报 < az/3）
	NodeNotFresh      bool
	NodeCapabilityLow bool
	// NodeStateReasons 节点状态明细（原文随 reasons 带出，不丢信息）
	NodeStateReasons []string
}

// DeriveReadiness 派生 readiness 徽章与 reasons（全部不真因子原文，而非仅首个）。
// 徽章优先级（冻结）：NOT_PUBLISHABLE（资格语义前提）> BLOCKED_BY_CONFLICT >
// BLOCKED_BY_NO_RELATION > BLOCKED_BY_STALE > BLOCKED_BY_NODE > READY；
// enforcement=PROTECT 恒展示 PROTECT_ACTIVE（reasons 照算随附供排障）。
func DeriveReadiness(in ReadinessInput) (string, []string) {
	reasons := []string{}
	badge := ReadinessReady

	if !in.Publishable {
		reasons = append(reasons, "publishable=false（发布资格未声明）")
		badge = ReadinessNotPublishable
	}
	if strings.TrimSpace(in.RequiredRelation) != "OWNER" {
		reasons = append(reasons, "required_relation≠OWNER（首批仅 OWNER 词表）")
		badge = ReadinessNotPublishable
	}
	if !in.OwnerExclusive {
		reasons = append(reasons, "owner_exclusive=false（排他所有权未显式声明——VERIFIED_VIOLATION 语义前提）")
		badge = ReadinessNotPublishable
	}
	if !in.EndpointConfirmed {
		reasons = append(reasons, "端点非 CONFIRMED（资产状态未确认，模型不进入发布编译）")
		badge = ReadinessNotPublishable
	}
	if in.HasOpenConflict && badge == ReadinessReady {
		badge = ReadinessBlockedByConflict
	}
	if in.HasOpenConflict {
		reasons = append(reasons, "存在 OPEN 冲突对象（D7 UNKNOWN 不阻断——冲突不可信，不可信不阻断）")
	}
	if !in.HasEffectiveOwnerRelation && badge == ReadinessReady {
		badge = ReadinessBlockedByNoRelation
	}
	if !in.HasEffectiveOwnerRelation {
		reasons = append(reasons, "无有效 OWNER 关系（OTHER_OWNER 不成立，VERIFIED_VIOLATION 永不产生）")
	}
	if badge == ReadinessReady && (in.SnapshotExpired || in.LeaseExpired || in.ClockSkew) {
		badge = ReadinessBlockedByStale
	}
	if in.SnapshotExpired {
		reasons = append(reasons, "授权快照已过期（节点 snapshot_expires_at 早于当前——D7 UNKNOWN 不阻断）")
	}
	if in.LeaseExpired {
		reasons = append(reasons, "授权租约已过期（strict 端点 UNKNOWN+AUTHZ-LEASE-001——D7 不阻断）")
	}
	if in.ClockSkew {
		reasons = append(reasons, "节点时钟偏差超上限（AUTHZ-CLOCK-001 UNKNOWN——任何时效判定不可信）")
	}
	if badge == ReadinessReady && (in.NodeNotFresh || in.NodeCapabilityLow) {
		badge = ReadinessBlockedByNode
	}
	if in.NodeNotFresh {
		reasons = append(reasons, "存在 ACK 非 FRESH 节点（快照未应用/水位落后——实断配置未到全部节点）")
	}
	if in.NodeCapabilityLow {
		reasons = append(reasons, "节点能力自报不足 az/3 或能力清单不可用（含 PROTECT 快照将被能力门 fail-closed 拒绝）")
	}
	reasons = append(reasons, in.NodeStateReasons...)

	if strings.EqualFold(strings.TrimSpace(in.Enforcement), "PROTECT") {
		return ReadinessProtectActive, reasons
	}
	return badge, reasons
}

// confirmTextV1 冻结确认语义文案（§1.4 v1 模板；占位符替换后随确认单落库）。
func confirmTextV1(windowDays, observeViolationCount, distinctPrincipalCount int, confirmedByName string) string {
	return fmt.Sprintf("我已知悉：本端点切换 PROTECT 后，经显式资格判定成立的违规请求将被实断（403 AUTHZ_VIOLATION_DENIED）；UNKNOWN 永不阻断。近 %d 天观测违规 %d 次、涉及主体 %d 个；我（%s）作为业务负责人确认承担实断影响。（确认文案 v1）",
		windowDays, observeViolationCount, distinctPrincipalCount, confirmedByName)
}
