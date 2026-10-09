// finalize.go 强流程响应回程收口（NG-FLOW-03 §1.4/§1.5，D4/D5）：
// 请求相位成功预留（Reservation）后，按源站响应事实执行 commit / 异步受理标记 /
// INDETERMINATE 标记。
//
// 语义冻结：
//   - 判定式命中（三形态可组合与全真）→ Lua commit（携带 fencing token）；
//     commit 成功 → 步骤 CONFIRMED + COMMIT OK 事件；全步骤确认 → INSTANCE_CONFIRMED；
//     token 过期被拒 → COMMIT REJECTED FENCE-001 如实（不静默；新预留持有活的
//     事实，本实例不入 INDETERMINATE）。
//   - F04 红线：超时/连接失败/判定式不命中/形态无法解析 → 步骤 UNKNOWN +
//     实例 INDETERMINATE 热状态 + INSTANCE_INDETERMINATE 事件——绝不自动 release
//     为可重试（超时可能已成功，回滚诱导重复扣款）；恢复由管理对账链收口。
//   - allows_202：步骤允许且响应 202 → 已受理待完成（槽位 accepted_202=1 +
//     RESERVE OK 条目 reason_code=FLOW-ACCEPTED-202 如实），实例保持 ACTIVE，
//     不把 202 自动记完成。
//   - 无成功判定式配置的步骤恒 UNKNOWN（运行期防御分支；FLOW-01 装配校验已
//     保证必填）。
//   - 与实断解耦：commit/INDETERMINATE 与 OBSERVE/PROTECT 实断无关（PROTECT
//     违规判定已在 reserve 路径完成）；Valkey 故障 → UNKNOWN 披露不切本地内存
//     （D8 同一纪律）。
package flowguard

import (
	"net/http"
	"strconv"
	"time"

	dsctx "github.com/jiuzhang-waf/gateway/dynamic_security/context"
	dsevents "github.com/jiuzhang-waf/gateway/dynamic_security/events"
)

// ResponseFacts 响应回程事实（装配侧采集：状态码 + 有界体样本 + 下游错误标记）。
type ResponseFacts struct {
	// Status 源站响应状态码（下游错误时不可信，按 DownstreamErr 分支处理）。
	Status int
	// Body 响应体有界样本（≤64KB；仅配置了 body 判定式的步骤采集，否则为 nil）。
	Body []byte
	// BodyTruncated 体超 64KB 有界上限（超限按判定不命中 UNKNOWN 如实处理）。
	BodyTruncated bool
	// DownstreamErr 下游错误（超时/连接失败/下游中断——F04 UNKNOWN 分支；
	// 网关未能获得源站执行证据，不区分拨号失败与写后断连，宁可对账不伪造）。
	DownstreamErr bool
}

// FinalizeResponse 响应回程收口（Runtime 方法；nil Runtime/无成功预留 = 零行为）。
// 动作条目与判定明细追加到请求上下文（sflow.actions 通道与 DetectorMatch），
// 由装配层随主事件统一输出——本方法自身不做任何 IO 之外的副作用。
func (rt *Runtime) FinalizeResponse(ctx *dsctx.RequestContext, facts ResponseFacts, now time.Time) {
	if rt == nil || ctx == nil {
		return
	}
	res := ReservationFromContext(ctx)
	if res == nil {
		return // 无成功预留（reserve 违规/未知/未命中绑定）：零行为
	}
	if now.IsZero() {
		now = time.Now().UTC()
		if rt.Now != nil {
			now = rt.Now().UTC()
		}
	}

	// 1) 下游错误（超时/连接失败/中断）→ F04 UNKNOWN + INDETERMINATE，绝不自动回滚
	if facts.DownstreamErr {
		rt.markStepUnknown(ctx, res, "downstream_error", nil, now)
		return
	}

	// 2) allows_202 异步受理：202 = 已受理待完成，实例保持 ACTIVE，不自动记完成
	if facts.Status == http.StatusAccepted && res.Allows202 {
		rt.markAccepted(ctx, res, facts, now)
		return
	}

	// 3) 成功判定式求值（无配置恒 UNKNOWN——D4：2xx 不是通用成功证据）
	verdict := EvaluateSuccess(res.SuccessRule, facts.Status, facts.Body, facts.BodyTruncated)
	if !verdict.Hit {
		rt.markStepUnknown(ctx, res, verdict.Detail, verdict.Evidence, now)
		return
	}

	// 4) 判定式命中 → commit（fencing token 随 Reservation）
	out := rt.Store.Commit(res.InstanceID, res.StepKey, res.AllStepKeys, res.FencingToken, res.IdemHash, res.Digest)
	switch out.Outcome {
	case "OK":
		appendActionEntry(ctx, res, dsevents.SFlowActionCommit, dsevents.SFlowResultOK, "", out.Token, now)
		if out.InstanceConfirmed {
			appendActionEntry(ctx, res, dsevents.SFlowActionInstanceConfirmed, dsevents.SFlowResultOK, "", out.Token, now)
		}
		evidence := baseEvidence(res, verdict.Evidence)
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "flowguard",
			RuleID:     "flowguard.step_confirmed",
			Category:   "INFO",
			Severity:   "INFO",
			Message:    "strong flow step confirmed by success rule",
			Confidence: 1.0,
			Evidence:   evidence,
		})
	case "UNKNOWN":
		// commit 依赖不可用：步骤结果未知 → F04 同一语义（INDETERMINATE 如实披露；
		// 标记同样可能失败——条目仍如实记录 UNKNOWN，PG 事件可对账，§1.8）
		rt.markStepUnknown(ctx, res, "commit_"+out.Detail, verdict.Evidence, now)
	default: // REJECTED/CONFLICT
		// fencing 过期提交被拒（F05：迟到响应不覆盖新状态）——新预留持有活的事实，
		// 本实例不入 INDETERMINATE；事件如实记录拒绝（§8.4-2 裁决：事件
		// fencing_token=被拒旧 token（out.Token），当前 fence 读数移 evidence
		// fence_current——与同步骤后续 COMMIT OK 不再同键碰撞）
		appendActionEntry(ctx, res, dsevents.SFlowActionCommit, dsevents.SFlowResultRejected, out.Reason, out.Token, now)
		evidence := baseEvidence(res, verdict.Evidence)
		evidence["reason_code"] = out.Reason
		evidence["detail"] = out.Detail
		evidence["fence_current"] = strconv.FormatInt(out.FenceCurrent, 10)
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "flowguard",
			RuleID:     "flowguard.commit_rejected",
			Category:   "OBSERVE",
			Severity:   "MEDIUM",
			Message:    "strong flow commit rejected (stale fencing token, newer state preserved)",
			Confidence: 1.0,
			Evidence:   evidence,
		})
	}
}

// markAccepted allows_202 受理标记（202 → 已受理待完成，不自动完成；§8.4-2 裁决：
// 受理即预留轮换——MarkAccepted INCR fence 取新 token，事件携新 token 与首
// RESERVE 不再同键碰撞）。
func (rt *Runtime) markAccepted(ctx *dsctx.RequestContext, res *Reservation, facts ResponseFacts, now time.Time) {
	out := rt.Store.MarkAccepted(res.InstanceID, res.StepKey, res.FencingToken, res.LeaseSeconds)
	switch out.Outcome {
	case "OK":
		appendActionEntry(ctx, res, dsevents.SFlowActionReserve, dsevents.SFlowResultOK, ReasonAccepted202, out.Token, now)
		ctx.AddMatch(dsctx.DetectorMatch{
			Detector:   "flowguard",
			RuleID:     "flowguard.step_accepted_202",
			Category:   "INFO",
			Severity:   "INFO",
			Message:    "strong flow step accepted (202 pending completion, not auto-confirmed)",
			Confidence: 1.0,
			Evidence:   baseEvidence(res, map[string]string{"status": strconv.Itoa(facts.Status), "reason_code": ReasonAccepted202}),
		})
	case "UNKNOWN":
		appendActionEntry(ctx, res, dsevents.SFlowActionReserve, dsevents.SFlowResultUnknown, ReasonUnknown, out.Token, now)
		evidence := baseEvidence(res, map[string]string{"detail": "mark_accepted_" + out.Detail, "dependency_unavailable": "true"})
		addFinalizeUnknownFinding(ctx, evidence)
	default: // REJECTED
		appendActionEntry(ctx, res, dsevents.SFlowActionReserve, dsevents.SFlowResultRejected, out.Reason, out.Token, now)
		evidence := baseEvidence(res, map[string]string{"reason_code": out.Reason, "detail": out.Detail})
		addFinalizeRejectedFinding(ctx, evidence)
	}
}

// markStepUnknown F04 统一收口：实例 INDETERMINATE 热状态标记（不自动 release——
// 步骤槽保持 PENDING 待对账）+ INSTANCE_INDETERMINATE 事件 + 判定读数明细。
func (rt *Runtime) markStepUnknown(ctx *dsctx.RequestContext, res *Reservation, detail string, ruleEvidence map[string]string, now time.Time) {
	out := rt.Store.MarkIndeterminate(res.InstanceID)
	appendActionEntry(ctx, res, dsevents.SFlowActionInstanceIndeterminate, dsevents.SFlowResultUnknown, ReasonUnknown, res.FencingToken, now)
	evidence := baseEvidence(res, ruleEvidence)
	evidence["detail"] = detail
	switch out.Outcome {
	case "OK":
		evidence["indeterminate_marked"] = "true"
	case "UNKNOWN":
		evidence["dependency_unavailable"] = "true"
		evidence["indeterminate_marked"] = "false"
	default:
		// 幂等重放（已 INDETERMINATE/终态）：如实呈现未重复迁移
		evidence["indeterminate_marked"] = "already"
	}
	addFinalizeUnknownFinding(ctx, evidence)
}

func appendActionEntry(ctx *dsctx.RequestContext, res *Reservation, action, result, reason string, token int64, now time.Time) {
	appendActions(ctx, &dsevents.StrongFlowAction{
		DefinitionID:      res.DefinitionID,
		DefinitionVersion: res.DefinitionVersion,
		InstanceID:        res.InstanceID,
		StepKey:           res.StepKey,
		Action:            action,
		FencingToken:      token,
		LeaseSeconds:      res.LeaseSeconds,
		Result:            result,
		ReasonCode:        reason,
		OccurredAt:        now,
	})
}

// baseEvidence 判定读数证据基座（reservation 维度 + 判定读数；AZ-03 证据纪律：
// 事实读数内嵌，不新建通道）。
func baseEvidence(res *Reservation, ruleEvidence map[string]string) map[string]string {
	ev := map[string]string{
		"definition_id":      res.DefinitionID,
		"definition_version": strconv.Itoa(res.DefinitionVersion),
		"instance_id":        res.InstanceID,
		"step_key":           res.StepKey,
		"fencing_token":      strconv.FormatInt(res.FencingToken, 10),
	}
	for k, v := range ruleEvidence {
		ev[k] = v
	}
	return ev
}

func addFinalizeUnknownFinding(ctx *dsctx.RequestContext, evidence map[string]string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "flowguard",
		RuleID:     "flowguard.step_unknown",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "strong flow step outcome unknown (F04: not auto-released, pending reconciliation)",
		Confidence: 1.0,
		Evidence:   evidence,
	})
}

func addFinalizeRejectedFinding(ctx *dsctx.RequestContext, evidence map[string]string) {
	ctx.AddMatch(dsctx.DetectorMatch{
		Detector:   "flowguard",
		RuleID:     "flowguard.commit_rejected",
		Category:   "OBSERVE",
		Severity:   "MEDIUM",
		Message:    "strong flow response-phase action rejected (fencing)",
		Confidence: 1.0,
		Evidence:   evidence,
	})
}
