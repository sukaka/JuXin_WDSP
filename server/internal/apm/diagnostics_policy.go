// diagnostics_policy.go 诊断会话的策略叠加与基线恢复（阶段4；设计 §6.3 第 3/5 步、
// §9.2 策略内容"诊断会话范围、能力、有效期和熔断阈值"）。
//
// 机制（复用 WP8 签名/版本纪律，单调递增语义不被破坏）：
//   - 诊断策略 = 当前生效基线的深拷贝 + diagnostics 子树整体替换为
//     {enabled:true, max_duration_minutes, session:{id, capabilities, sampling_rate,
//     expires_at, scope}}；以 application:<uuid> 作用域发布为新版本（max+1），
//     匹配的 Agent 下次拉取（GET /apm/agent/policy 应用级优先）即生效；
//   - 诊断策略信封的 expires_at = 会话硬截止（不是基线的 30 天）——Agent 失联
//     兜底：控制面不可达时过期诊断策略必须本地自动失效（§9.2），不依赖恢复下发；
//   - 恢复 = 取该作用域最新版本，剥除诊断叠加（diagnostics 复位默认关闭），
//     以新版本重新发布（信封有效期回归 PolicyValidity）；发布失败由到期扫描任务
//     按 baseline_restored=false 对账重试（§21.2"1 分钟内恢复基线"）。
//
// 说明：diagnostics.session 子树只允许出现在系统生成的叠加策略中；
// ValidateBaselinePolicy（管理面 PUT 基线）继续 fail-closed 拒绝该子键，
// 防止管理员把会话状态写进基线。
package apm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// diagnosticPolicyScope 诊断会话的策略作用域（应用级；创建时 scope 已收敛到单应用）。
func diagnosticPolicyScope(sess *DiagnosticSession) string {
	return ApplicationPolicyScope(sess.Scope.ApplicationID)
}

// deepCopyPolicy 策略深拷贝（策略源自 jsonb，JSON 往返即深拷贝；失败返回 nil + err）。
func deepCopyPolicy(policy map[string]interface{}) (map[string]interface{}, error) {
	raw, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("encode policy: %w", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return out, nil
}

// overlayDiagnosticPolicy 在基线之上叠加诊断会话（返回新 map，不改入参）。
// expires_at 硬截止以 RFC3339 秒级精度入策略正文（供 Agent 侧本地失效判定与审计对齐）。
func overlayDiagnosticPolicy(base map[string]interface{}, sess *DiagnosticSession) (map[string]interface{}, error) {
	out, err := deepCopyPolicy(base)
	if err != nil {
		return nil, err
	}
	caps := make([]interface{}, 0, len(sess.Capabilities))
	for _, c := range sess.Capabilities {
		caps = append(caps, c)
	}
	instances := make([]interface{}, 0, len(sess.Scope.InstanceIDs))
	for _, id := range sess.Scope.InstanceIDs {
		instances = append(instances, id)
	}
	sessionScope := map[string]interface{}{"application_id": sess.Scope.ApplicationID.String()}
	if sess.Scope.Service != "" {
		sessionScope["service"] = sess.Scope.Service
	}
	if sess.Scope.Environment != "" {
		sessionScope["environment"] = sess.Scope.Environment
	}
	if len(instances) > 0 {
		sessionScope["instance_ids"] = instances
	}
	out["diagnostics"] = map[string]interface{}{
		"enabled":              true,
		"max_duration_minutes": float64(sess.DurationMinutes),
		"session": map[string]interface{}{
			"id":            sess.ID.String(),
			"capabilities":  caps,
			"sampling_rate": sess.SamplingRate,
			"expires_at":    sess.ExpiresAt.UTC().Format(time.RFC3339),
			"scope":         sessionScope,
		},
	}
	return out, nil
}

// stripDiagnosticOverlay 剥除诊断叠加（diagnostics 复位默认关闭口径；返回新 map）。
// 对无叠加的基线为幂等操作（创建路径取叠加底稿与恢复路径共用，顺带自愈
// 恢复失败残留的叠加态）。
func stripDiagnosticOverlay(policy map[string]interface{}) (map[string]interface{}, error) {
	out, err := deepCopyPolicy(policy)
	if err != nil {
		return nil, err
	}
	out["diagnostics"] = map[string]interface{}{"enabled": false, "max_duration_minutes": 30.0}
	return out, nil
}

// resolveBaselineForDiagnostic 解析诊断叠加底稿：应用级最新策略（剥叠加）→ 全局基线
// → 内置默认基线（与 Agent 面 resolvePolicyForAgent 的优先级一致，但不触发惰性落库）。
func resolveBaselineForDiagnostic(ctx context.Context, store AgentRepository, appID uuid.UUID) (map[string]interface{}, error) {
	if row, err := store.LatestPolicy(ctx, ApplicationPolicyScope(appID)); err == nil {
		return stripDiagnosticOverlay(row.Policy)
	} else if !errors.Is(err, ErrPolicyNotFound) {
		return nil, err
	}
	if row, err := store.LatestPolicy(ctx, PolicyScopeGlobal); err == nil {
		return row.Policy, nil
	} else if !errors.Is(err, ErrPolicyNotFound) {
		return nil, err
	}
	return DefaultBaselinePolicy(), nil
}

// publishScopedPolicy 发布指定作用域的新策略版本（WP8 纪律：先读当前版本 →
// 版本+1 入签 → 仓储在事务+作用域咨询锁内复核 expectedVersion；并发冲突重试一次）。
// envelopeExpiresAt 为信封过期时间（诊断叠加=会话硬截止；基线恢复=now+validity）。
func publishScopedPolicy(ctx context.Context, store AgentRepository, ca *AgentCA, scope string,
	policy map[string]interface{}, envelopeExpiresAt, now time.Time, createdBy *uuid.UUID) (*PolicyRow, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		current, err := store.LatestPolicy(ctx, scope)
		if err != nil && !errors.Is(err, ErrPolicyNotFound) {
			return nil, err
		}
		var currentVersion int64
		if current != nil {
			currentVersion = current.Version
		}
		env := &PolicyEnvelope{
			Scope: scope, Version: currentVersion + 1, KeyID: PolicySignKeyID,
			IssuedAt: now.UTC(), ExpiresAt: envelopeExpiresAt.UTC(), Policy: policy,
		}
		if err := ca.SignPolicy(env); err != nil {
			return nil, err
		}
		row, err := store.CreatePolicyVersion(ctx, scope, policy, env.Signature, env.KeyID,
			env.IssuedAt, env.ExpiresAt, &currentVersion, createdBy)
		if errors.Is(err, ErrPolicyVersionConflict) {
			lastErr = err
			continue // 他人先发新版：重读重签重试一次
		}
		return row, err
	}
	return nil, lastErr
}

// restoreBaselinePolicy 下发基线恢复策略（作用域最新版本剥除诊断叠加后重新发布）。
// 作用域下不存在任何版本（异常态——创建路径必已发布叠加版本）时返回 nil, nil，
// 由调用侧按"无需恢复"处理并如实记录。
func restoreBaselinePolicy(ctx context.Context, store AgentRepository, ca *AgentCA,
	appID uuid.UUID, validity time.Duration, now time.Time, createdBy *uuid.UUID) (*PolicyRow, error) {
	scope := ApplicationPolicyScope(appID)
	latest, err := store.LatestPolicy(ctx, scope)
	if errors.Is(err, ErrPolicyNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	stripped, err := stripDiagnosticOverlay(latest.Policy)
	if err != nil {
		return nil, err
	}
	return publishScopedPolicy(ctx, store, ca, scope, stripped, now.UTC().Add(validity), now, createdBy)
}
