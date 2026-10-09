// apply.go 批次应用（NG-AZ-01）：snapshot 原子切换与 delta 增量应用。
// 纪律：
//   - 全部关系变更/幂等账本/水位在单一事务内——任何中断/校验失败整体回滚，
//     一行不动（snapshot 绝不把未导入对象当撤销——全量语义只在切换成功时成立）；
//   - 第 3 步重放检查在事务内水位 FOR UPDATE 锁下完成（防并发导入竞态）；
//   - GRANT 冲突规则：同对象已有不同 principal 的有效 OWNER 且本事件非同键认领 →
//     不落关系行，只记 ConflictRecord（不按最后到达者覆盖；冲突拒绝的事件照常记
//     幂等账本——冲突解除后来源须重新签发新事件才落关系）；
//   - 水位单调：last_sequence/revocation_watermark 只增不减；
//     缺口由幂等账本重算（补齐自动消除）。
package apiauthzauthority

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// objKey 冲突评估对象键。
type objKey struct {
	appID   uuid.UUID
	objType string
	objRef  string
	tenant  string // COALESCE(tenant_id,'') 口径
}

// applyBatch 应用批次（返回计数；fail=业务拒绝（已回滚），err=基础设施错误（已回滚））。
func (s *Service) applyBatch(ctx context.Context, source *AuthoritySource, p *ImportBatchPayload, batchID uuid.UUID) (BatchCounts, *batchFailure, error) {
	var counts BatchCounts

	// tenant_domain → application_id 解析（第 5 步语义层落点；解析失败批次级拒绝）
	apps := map[string]uuid.UUID{}
	for _, e := range p.Items {
		if _, ok := apps[e.TenantDomain]; ok {
			continue
		}
		appID, err := s.store.ResolveAppByDomain(ctx, e.TenantDomain)
		if err != nil {
			return counts, rejectf(5, ItemError{EventID: e.EventID, Step: 5, Reason: err.Error()}), nil
		}
		apps[e.TenantDomain] = appID
	}

	tx, err := s.store.DB().Begin(ctx)
	if err != nil {
		return counts, nil, fmt.Errorf("begin batch apply tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	wm, err := s.store.GetWatermarkForUpdate(ctx, tx, source.ID)
	if err != nil {
		return counts, nil, fmt.Errorf("lock watermark: %w", err)
	}

	// snapshot 陈旧防线：批次最大 sequence 必须大于水位（整体推进）
	var batchMaxSeq uint64
	for _, e := range p.Items {
		if e.Sequence > batchMaxSeq {
			batchMaxSeq = e.Sequence
		}
	}
	if p.Mode == ModeSnapshot && batchMaxSeq <= wm.LastSequence {
		return counts, rejectf(3, ItemError{Step: 3, Reason: fmt.Sprintf(
			"snapshot 批次最大 sequence=%d 不大于已应用水位 %d（陈旧快照拒收）", batchMaxSeq, wm.LastSequence)}), nil
	}

	now := s.now()
	touched := map[objKey]bool{}    // 需事后冲突评估的对象
	conflicted := map[objKey]bool{} // 本批冲突标记的对象（跳过自动解除）
	var maxAppliedSeq uint64
	var lastEventBySeq string
	var maxRevokeSeq uint64

	for i, e := range p.Items {
		// 第 3 步：重放幂等（事务内）
		dup, err := s.store.AppliedEventExists(ctx, tx, source.ID, e.EventID)
		if err != nil {
			return counts, nil, fmt.Errorf("replay check: %w", err)
		}
		if dup {
			counts.SkippedDuplicate++
			continue
		}
		if p.Mode == ModeDelta {
			// 序号冲突拒收（同序号不同事件——重放攻击面；缺口补齐事件
			// （序号落在缺口内、event_id 未消费）属合法新事实照常应用——
			// AUTHZ_SOURCE_GAP 补齐语义，见设计附录「实现状态」决策 D3）
			seqDup, err := s.store.SequenceExists(ctx, tx, source.ID, e.Sequence)
			if err != nil {
				return counts, nil, fmt.Errorf("sequence check: %w", err)
			}
			if seqDup {
				return counts, rejectf(3, ItemError{Index: i, EventID: e.EventID, Step: 3, Reason: fmt.Sprintf(
					"sequence=%d 已被其他事件消费（同序号重放拒收）", e.Sequence)}), nil
			}
		}

		appID := apps[e.TenantDomain]
		key := objKey{appID: appID, objType: e.ObjectType, objRef: e.ObjectRef, tenant: e.TenantDomain}
		vf, _ := time.Parse(time.RFC3339, e.ValidFrom)
		var vu *time.Time
		if e.ValidUntil != "" {
			if t, perr := time.Parse(time.RFC3339, e.ValidUntil); perr == nil {
				vu = &t
			}
		}

		switch e.ChangeType {
		case ChangeGrant:
			owners, err := s.store.ListActiveOwnerPrincipals(ctx, tx, appID, e.ObjectType, e.ObjectRef, tenantPtr(e.TenantDomain), now)
			if err != nil {
				return counts, nil, fmt.Errorf("conflict pre-check: %w", err)
			}
			competing := false
			adopt := false
			for _, pr := range owners {
				if pr == e.PrincipalRef {
					adopt = true // 同键认领（同一事实刷新溯源/有效期，不算覆盖）
				} else {
					competing = true
				}
			}
			if competing && !adopt {
				// 冲突：不落关系行，只记冲突（不按最后到达者覆盖）
				prs := append(append([]string(nil), owners...), e.PrincipalRef)
				if err := s.store.UpsertConflict(ctx, tx, appID, e.ObjectType, e.TenantDomain, e.ObjectRef, prs); err != nil {
					return counts, nil, fmt.Errorf("upsert conflict: %w", err)
				}
				conflicted[key] = true
				touched[key] = true
				counts.Conflicts++
			} else {
				evidenceRef := fmt.Sprintf("authority://%s/%s", source.ID, e.EventID)
				if _, err := s.store.GrantRelation(ctx, tx, GrantInput{
					ApplicationID: appID,
					ObjectType:    e.ObjectType,
					ObjectRef:     e.ObjectRef,
					PrincipalRef:  e.PrincipalRef,
					TenantDomain:  tenantPtr(e.TenantDomain),
					ValidFrom:     vf,
					ValidUntil:    vu,
					EvidenceRef:   &evidenceRef,
					ConfirmedBy:   "authority:" + source.Name,
					Reason:        "权威同步批次 " + batchID.String(),
					SourceID:      source.ID,
					EventID:       e.EventID,
					BatchID:       batchID,
				}); err != nil {
					return counts, nil, fmt.Errorf("grant relation (event %s): %w", e.EventID, err)
				}
				counts.Grants++
				touched[key] = true
			}
		case ChangeRevoke:
			if _, err := s.store.RevokeRelation(ctx, tx, source.ID, appID, e.ObjectType, e.ObjectRef, e.PrincipalRef, tenantPtr(e.TenantDomain)); err != nil {
				return counts, nil, fmt.Errorf("revoke relation (event %s): %w", e.EventID, err)
			}
			counts.Revokes++
			touched[key] = true
			if e.Sequence > maxRevokeSeq {
				maxRevokeSeq = e.Sequence
			}
		}

		if err := s.store.InsertAppliedEvent(ctx, tx, source.ID, e.EventID, e.Sequence, batchID, e.ChangeType); err != nil {
			return counts, nil, fmt.Errorf("record applied event: %w", err)
		}
		counts.Applied++
		if e.Sequence >= maxAppliedSeq {
			maxAppliedSeq = e.Sequence
			lastEventBySeq = e.EventID
		}
	}

	// snapshot 原子切换：本来源本域有效权威行不在新全量键集内的标 REVOKED
	// （在全部 GRANT 落位后执行——保留集=新全量；任何失败整体回滚）。
	if p.Mode == ModeSnapshot {
		type domainScope struct {
			appID  uuid.UUID
			domain string
		}
		keep := map[domainScope][]string{}
		for _, e := range p.Items {
			ds := domainScope{appID: apps[e.TenantDomain], domain: e.TenantDomain}
			keep[ds] = append(keep[ds], e.ObjectType+" "+e.ObjectRef+" "+e.PrincipalRef)
		}
		for ds, keys := range keep {
			if _, err := s.store.RevokeAuthorityRelationsNotIn(ctx, tx, source.ID, ds.appID, tenantPtr(ds.domain), keys); err != nil {
				return counts, nil, fmt.Errorf("snapshot switch revoke-not-in: %w", err)
			}
			for _, e := range p.Items {
				if e.TenantDomain == ds.domain {
					touched[objKey{appID: ds.appID, objType: e.ObjectType, objRef: e.ObjectRef, tenant: ds.domain}] = true
				}
			}
		}
	}

	// 水位推进（单调不下降）
	newWM := wm
	if maxAppliedSeq > newWM.LastSequence {
		newWM.LastSequence = maxAppliedSeq
		newWM.LastEventID = lastEventBySeq
	}
	if p.Mode == ModeSnapshot && batchMaxSeq > newWM.LastSequence {
		newWM.LastSequence = batchMaxSeq
		newWM.LastEventID = lastEventBySeq
	}
	if maxRevokeSeq > newWM.RevocationWatermark {
		newWM.RevocationWatermark = maxRevokeSeq
	}
	// NG-AZ-02 D1 对齐：snapshot 原子切换的「不在集合即撤销」同样推进撤销水位至批次
	// 最大序号（切换即权威撤销语义——否则 PreviousValid 资格过滤无法拦截切换前旧快照
	// 复活被切换撤销的关系；单调 max 语义不变）
	if p.Mode == ModeSnapshot && batchMaxSeq > newWM.RevocationWatermark {
		newWM.RevocationWatermark = batchMaxSeq
	}
	gap, err := s.store.RecomputeGap(ctx, tx, source.ID)
	if err != nil {
		return counts, nil, fmt.Errorf("recompute gap: %w", err)
	}
	newWM.GapFrom = gap
	if err := s.store.UpsertWatermark(ctx, tx, source.ID, newWM); err != nil {
		return counts, nil, fmt.Errorf("upsert watermark: %w", err)
	}

	// 事后冲突评估（REVOKE/切换收敛自动解除；本批冲突标记对象跳过自动解除）
	for key := range touched {
		prs, err := s.store.ListActiveOwnerPrincipals(ctx, tx, key.appID, key.objType, key.objRef, tenantPtr(key.tenant), now)
		if err != nil {
			return counts, nil, fmt.Errorf("conflict re-eval: %w", err)
		}
		switch {
		case len(prs) > 1:
			if err := s.store.UpsertConflict(ctx, tx, key.appID, key.objType, key.tenant, key.objRef, prs); err != nil {
				return counts, nil, fmt.Errorf("upsert conflict re-eval: %w", err)
			}
		default:
			if !conflicted[key] {
				if err := s.store.ResolveConflictIfSingleOwner(ctx, tx, key.appID, key.objType, key.tenant, key.objRef); err != nil {
					return counts, nil, fmt.Errorf("resolve conflict: %w", err)
				}
			}
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return counts, nil, fmt.Errorf("commit batch apply: %w", err)
	}
	committed = true
	return counts, nil, nil
}

// tenantPtr 租户域指针形态（关系表 tenant_id 可空列）。
func tenantPtr(domain string) *string {
	if domain == "" {
		return nil
	}
	return &domain
}
