package exceptions

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jiuzhang-waf/server/internal/gatewayconfig"
	"github.com/jiuzhang-waf/server/internal/validation"
)

// MaxPublishExceptions 单次发布例外容量上限（规则 ID 8000001-8004000 段，
// 每条例外占 marker/effect 两个连续 ID；超限发布明确失败——契约 §5）。
const MaxPublishExceptions = 2000

// publishMarkerBase 例外规则 ID 段起点（与自定义规则 7100000+ 区分）。
const publishMarkerBase = 8000001

// ListForPublish 返回发布快照（gatewayconfig.ExceptionProvider 实现）：
// ENABLED + VALID + WAF 引擎 + 未删除，按 exception_id 字典序（uuid 列 ASC 与字符串
// 字典序一致）稳定排序；每条分配 marker=8000001+2i / effect=marker+1 两个连续规则 ID
// （ExceptionRule.RuleID 取 effect——映射注释锚定 effect 行，反查锚点为 exc:/excv: tag）。
// 已到期（effective_until <= now）跳过；未来生效照常下发（TIME_EPOCH 时间链运行时门控）。
// 编译失败或超容量上限返回错误——发布 fail-hard。
func (s *Store) ListForPublish(ctx context.Context) ([]gatewayconfig.ExceptionRule, error) {
	rows, err := s.db.Query(ctx, `SELECT `+exceptionColumns+`
FROM exception_policies
WHERE deleted_at IS NULL AND status = 'ENABLED' AND validation_status = 'VALID' AND target_engine = 'WAF'
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list exceptions for publish: %w", err)
	}
	defer rows.Close()
	var list []*Exception
	for rows.Next() {
		e, err := scanExceptionRows(rows)
		if err != nil {
			return nil, fmt.Errorf("list exceptions for publish: %w", err)
		}
		list = append(list, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list exceptions for publish: %w", err)
	}

	now := time.Now()
	out := make([]gatewayconfig.ExceptionRule, 0, len(list))
	for _, e := range list {
		if e.EffectiveUntil != nil && !e.EffectiveUntil.After(now) {
			continue // 已到期：不下发（到期无需再发布）
		}
		if len(out) >= MaxPublishExceptions {
			return nil, fmt.Errorf("启用例外超过发布容量上限 %d 条（规则 ID 段 %d-%d）",
				MaxPublishExceptions, publishMarkerBase, publishMarkerBase+2*MaxPublishExceptions)
		}
		marker := publishMarkerBase + 2*len(out)
		secLang, err := GenerateSecLang(e, marker)
		if err != nil {
			return nil, fmt.Errorf("compile exception %s: %w", e.ID, err)
		}
		rule := gatewayconfig.ExceptionRule{
			RuleID:           marker + 1, // effect 行
			SecLang:          secLang,
			ScopeType:        e.ScopeType,
			ExceptionID:      e.ID.String(),
			ExceptionVersion: e.Version,
		}
		if e.ApplicationID != nil {
			rule.ApplicationID = e.ApplicationID.String()
		}
		if e.PolicyID != nil {
			rule.PolicyID = e.PolicyID.String()
		}
		out = append(out, rule)
	}
	return out, nil
}

// ListAPIExceptionsForGuard 返回 API 引擎受限例外的 guard 下发快照（api_exceptions 段，
// 契约 §6）：ENABLED + VALID + target_engine='API'，key=应用编码（经 applications JOIN）。
// 已到期跳过；未来生效照常下发（网关按 effective_from/until 半开区间运行时判断）。
// 启用行应用绑定悬空（应用缺失/已删除）返回错误——读取失败 fail-hard 中止发布。
// 无 API 例外时返回 nil（guard 配置不下发该段，网关零行为变化）。
func (s *Store) ListAPIExceptionsForGuard(ctx context.Context) (map[string][]gatewayconfig.GuardAPIException, error) {
	rows, err := s.db.Query(ctx, `SELECT `+exceptionColumns+`
FROM exception_policies
WHERE deleted_at IS NULL AND status = 'ENABLED' AND validation_status = 'VALID' AND target_engine = 'API'
ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list api exceptions for guard: %w", err)
	}
	defer rows.Close()
	var list []*Exception
	for rows.Next() {
		e, err := scanExceptionRows(rows)
		if err != nil {
			return nil, fmt.Errorf("list api exceptions for guard: %w", err)
		}
		list = append(list, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list api exceptions for guard: %w", err)
	}
	if len(list) == 0 {
		return nil, nil
	}

	// 应用编码（api_exceptions 段 key）
	seen := map[uuid.UUID]bool{}
	var appIDs []uuid.UUID
	for _, e := range list {
		if e.ApplicationID != nil && !seen[*e.ApplicationID] {
			seen[*e.ApplicationID] = true
			appIDs = append(appIDs, *e.ApplicationID)
		}
	}
	codes := map[uuid.UUID]string{}
	if len(appIDs) > 0 {
		r2, err := s.db.Query(ctx, `SELECT id, code FROM applications WHERE id = ANY($1) AND deleted_at IS NULL`, appIDs)
		if err != nil {
			return nil, fmt.Errorf("list api exceptions for guard: query application codes: %w", err)
		}
		defer r2.Close()
		for r2.Next() {
			var id uuid.UUID
			var code string
			if err := r2.Scan(&id, &code); err != nil {
				return nil, fmt.Errorf("list api exceptions for guard: scan application code: %w", err)
			}
			codes[id] = code
		}
		if err := r2.Err(); err != nil {
			return nil, fmt.Errorf("list api exceptions for guard: query application codes: %w", err)
		}
	}

	now := time.Now()
	out := map[string][]gatewayconfig.GuardAPIException{}
	for _, e := range list {
		if e.EffectiveUntil != nil && !e.EffectiveUntil.After(now) {
			continue
		}
		if e.ApplicationID == nil {
			return nil, fmt.Errorf("api exception %s 为 ENABLED+VALID 但缺少应用绑定（启用门禁被破坏）", e.ID)
		}
		code, ok := codes[*e.ApplicationID]
		if !ok {
			return nil, fmt.Errorf("api exception %s 绑定应用 %s 不存在或已删除", e.ID, *e.ApplicationID)
		}
		item := gatewayconfig.GuardAPIException{
			SchemaVersion: 1,
			ExceptionID:   e.ID.String(),
			Version:       e.Version,
			Domain:        validation.NormalizeHostname(e.Domain),
			URIExact:      e.URIExact,
			URIPrefix:     e.URIPrefix,
			Methods:       normalizedMethods(e.Methods),
			SourceIPs:     e.SourceIPs,
		}
		if e.EffectiveFrom != nil {
			v := e.EffectiveFrom.UTC().Unix()
			item.EffectiveFrom = &v
		}
		if e.EffectiveUntil != nil {
			v := e.EffectiveUntil.UTC().Unix()
			item.EffectiveUntil = &v
		}
		for _, ref := range sortedAPIRuleRefs(e.APIRuleRefs) {
			item.RuleRefs = append(item.RuleRefs, gatewayconfig.GuardAPIRuleRef{
				DetectorID:   ref.DetectorID,
				RuleID:       ref.RuleID,
				ModelVersion: ref.ModelVersion,
			})
		}
		out[code] = append(out[code], item)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
