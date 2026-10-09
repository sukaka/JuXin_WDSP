// authz_watermark.go 进程级授权快照水位注册表（NG-AZ-02 D4-1 水位记忆 + D6 心跳合并源）。
//
// 语义与纪律：
//   - 每应用一条已应用快照状态（Guard 实例随配置热加载整体替换；注册表跨实例存活——
//     水位记忆不能随实例替换丢失，否则回退拒绝形同虚设）；
//   - 回退拒绝（D4-1）：新快照携带 v2 水位且低于本应用已应用水位（分量比较）即拒绝
//     整个配置加载（Provision 返回错误 → Caddy 拒绝 /load → 节点保留旧配置与旧水位——
//     「保留已应用快照」的字面实现）；v1 快照（无水位字段）按 D4-3 兼容不校验；
//   - 心跳合并（D6）：节点级 ACK 状态取各应用最保守口径——min(lease_seconds)、
//     分量最小向量水位、最旧 applied_at、最早 snapshot_expires_at、最旧 produced_at；
//   - 本文件与 apiheartbeat/apiprotect 的装配点互相只读，不构成请求热路径依赖。
package jiuzhang_guard

import (
	"fmt"
	"strconv"
	"sync"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	"github.com/jiuzhang-waf/gateway/dynamic_security/detectors"
	"github.com/jiuzhang-waf/gateway/modules/jiuzhang_guard/apievents"
	"go.uber.org/zap"
)

// authzAppliedEntry 单应用已应用授权快照状态。
type authzAppliedEntry struct {
	watermark     *authzWatermarkJSON
	leaseSeconds  int
	appliedAt     time.Time
	policyVersion string
	expiresAt     *time.Time
	producedAt    *time.Time
}

// authzAppliedRegistry 进程级注册表（并发安全；写少读多）。
type authzAppliedRegistry struct {
	mu      sync.RWMutex
	entries map[string]authzAppliedEntry
}

// defaultAuthzRegistry 节点级默认注册表（Provision 写入、apiheartbeat/apiprotect 读取）。
var defaultAuthzRegistry = &authzAppliedRegistry{entries: map[string]authzAppliedEntry{}}

func (r *authzAppliedRegistry) get(appID string) (authzAppliedEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.entries[appID]
	return e, ok
}

func (r *authzAppliedRegistry) put(appID string, e authzAppliedEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[appID] = e
}

func (r *authzAppliedRegistry) remove(appID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, appID)
}

// authzACKState 心跳 ACK 合并状态（D6；全部应用的最保守视图）。
type authzACKState struct {
	PolicyVersion     string
	Watermark         *authzWatermarkJSON
	LeaseSeconds      int
	AppliedAt         time.Time
	SnapshotExpiresAt *time.Time
}

// merged 合并全部应用状态（D6 口径：min(lease)、分量最小水位、最旧 appliedAt、最早过期时刻；
// 无注册应用返回 false——心跳不携带 authz 字段（v1 零变化））。
func (r *authzAppliedRegistry) merged() (authzACKState, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.entries) == 0 {
		return authzACKState{}, false
	}
	out := authzACKState{Watermark: &authzWatermarkJSON{Sources: map[string]int64{}}}
	var minApplied time.Time
	minManualSet := false
	for _, e := range r.entries {
		if out.PolicyVersion == "" {
			out.PolicyVersion = e.policyVersion
		}
		if minApplied.IsZero() || e.appliedAt.Before(minApplied) {
			minApplied = e.appliedAt
		}
		if e.leaseSeconds > 0 && (out.LeaseSeconds == 0 || e.leaseSeconds < out.LeaseSeconds) {
			out.LeaseSeconds = e.leaseSeconds
		}
		if e.expiresAt != nil && (out.SnapshotExpiresAt == nil || e.expiresAt.Before(*out.SnapshotExpiresAt)) {
			t := *e.expiresAt
			out.SnapshotExpiresAt = &t
		}
		if e.watermark != nil {
			if !minManualSet || e.watermark.ManualSeq < out.Watermark.ManualSeq {
				out.Watermark.ManualSeq = e.watermark.ManualSeq
				minManualSet = true
			}
			for k, v := range e.watermark.Sources {
				if cur, ok := out.Watermark.Sources[k]; !ok || v < cur {
					out.Watermark.Sources[k] = v
				}
			}
		}
	}
	out.AppliedAt = minApplied
	return out, true
}

// resetAuthzRegistryForTest 清空注册表（仅测试使用）。
func resetAuthzRegistryForTest() {
	defaultAuthzRegistry.mu.Lock()
	defer defaultAuthzRegistry.mu.Unlock()
	defaultAuthzRegistry.entries = map[string]authzAppliedEntry{}
}

// authzWatermarkToDetectors 线水位 → detectors 水位（跨包类型转换，键值逐项拷贝不共享）。
func authzWatermarkToDetectors(w *authzWatermarkJSON) *detectors.RevocationWatermark {
	if w == nil {
		return nil
	}
	out := &detectors.RevocationWatermark{ManualSeq: w.ManualSeq}
	if len(w.Sources) > 0 {
		out.Sources = map[string]int64{}
		for k, v := range w.Sources {
			out.Sources[k] = v
		}
	}
	return out
}

// authzConflictsToDetectors 线冲突集 → detectors 冲突集。
func authzConflictsToDetectors(in []authzConflictedObjectJSON) []detectors.ConflictedObject {
	if len(in) == 0 {
		return nil
	}
	out := make([]detectors.ConflictedObject, 0, len(in))
	for _, c := range in {
		out = append(out, detectors.ConflictedObject{
			ApplicationID: c.ApplicationID, ObjectType: c.ObjectType,
			TenantDomain: c.TenantDomain, ObjectRef: c.ObjectRef,
		})
	}
	return out
}

// checkAuthzWatermarkRegression NG-AZ-02 D4-1：v2 快照水位低于本应用已应用水位即拒绝
// 配置加载（fail-closed——Caddy 拒绝 /load 保留旧配置；AUTHZ_WATERMARK_REGRESSION 告警
// 入 API 事件日志与 zap，管理面经采集链可见）。
func (g *Guard) checkAuthzWatermarkRegression() error {
	incoming := g.APIAuthzRevocationWatermark
	if incoming == nil {
		return nil // v1 快照（无水位字段）按 D4-3 兼容不校验
	}
	prev, ok := defaultAuthzRegistry.get(g.AppID)
	if !ok || prev.watermark == nil {
		return nil // 本应用首次应用 v2 快照
	}
	if incoming.atLeast(prev.watermark) {
		return nil
	}
	g.logger.Error("AUTHZ_WATERMARK_REGRESSION: incoming authz snapshot watermark below applied, config load rejected (fail-closed)",
		zap.String("app_id", g.AppID),
		zap.Int64("incoming_manual_seq", incoming.ManualSeq),
		zap.Int64("applied_manual_seq", prev.watermark.ManualSeq))
	if g.apiEvents != nil {
		_ = g.apiEvents.Emit(apievents.Record{
			RequestID:   "azwm-" + strconv.FormatInt(time.Now().UTC().UnixNano(), 36),
			OccurredAt:  time.Now().UTC(),
			EndpointKey: "__authz_watermark_regression__",
			FinalAction: "OBSERVE",
			RiskLevel:   "NONE",
			Details: []dsctx.DetectorMatch{{
				Detector: "api_authz", RuleID: "AUTHZ_WATERMARK_REGRESSION", Category: "OBSERVE", Severity: "HIGH",
				Message: "incoming authz snapshot watermark below applied, config load rejected",
				Evidence: map[string]string{
					"reason_code":         "AUTHZ_WATERMARK_REGRESSION",
					"incoming_manual_seq": strconv.FormatInt(incoming.ManualSeq, 10),
					"applied_manual_seq":  strconv.FormatInt(prev.watermark.ManualSeq, 10),
				},
			}},
			GatewayNode: g.GatewayNode,
		})
	}
	return fmt.Errorf("api_authz: revocation watermark regression (incoming manual_seq=%d < applied=%d), config load rejected", incoming.ManualSeq, prev.watermark.ManualSeq)
}

// registerAuthzAppliedState 登记本应用已应用授权快照状态（Provision 成功后调用；
// 无授权内容时清除注册项——v1 快照保留既有水位记忆（后续 v2 仍按最后 v2 水位比较，
// 管理面水位单调不下降保证了该比较不误伤））。
func (g *Guard) registerAuthzAppliedState() {
	if g.APIAuthzRevocationWatermark == nil {
		if len(g.APIAuthzModels) == 0 && g.APIAuthzPreviousValid == nil {
			defaultAuthzRegistry.remove(g.AppID)
		}
		return
	}
	var expiresAt *time.Time
	if g.APIAuthzSnapshotExpiresAt != nil {
		t := g.APIAuthzSnapshotExpiresAt.UTC()
		expiresAt = &t
	}
	defaultAuthzRegistry.put(g.AppID, authzAppliedEntry{
		watermark:     g.APIAuthzRevocationWatermark,
		leaseSeconds:  g.APIAuthzLeaseSeconds,
		appliedAt:     time.Now().UTC(),
		policyVersion: g.APIAuthzSnapshotPolicyVersion(),
		expiresAt:     expiresAt,
		producedAt:    g.APIAuthzProducedAt,
	})
}

// APIAuthzSnapshotPolicyVersion 授权快照版本（ACK 上报口径：取首个模型的
// policy_version（编译期全模型同戳）；无模型回退全局 api_policy_version）。
func (g *Guard) APIAuthzSnapshotPolicyVersion() string {
	for _, m := range g.APIAuthzModels {
		if m.PolicyVersion != "" {
			return m.PolicyVersion
		}
	}
	return g.APIPolicyVersion
}

// authzSnapshotAppliedAt 本应用快照应用时刻（D5 租约判定基准：注册表记录值；
// 未登记（v1/无授权内容）返回零值——authzLeaseExpired 恒 false 零介入）。
func (g *Guard) authzSnapshotAppliedAt() time.Time {
	if e, ok := defaultAuthzRegistry.get(g.AppID); ok {
		return e.appliedAt
	}
	return time.Time{}
}

// clampAuthzLeaseSeconds 租约夹紧（D5：≤0=未启用；15~300）。
func clampAuthzLeaseSeconds(sec int) int {
	if sec <= 0 {
		return 0
	}
	if sec < 15 {
		return 15
	}
	if sec > 300 {
		return 300
	}
	return sec
}

// clampAuthzClockSkewMax 漂移上限夹紧（D8：≤0=缺省 60；10~300）。
func clampAuthzClockSkewMax(sec int) int {
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
