// Package guardjanitor 阶段5到期自动失效调度：
// 定期将到期的临时访问控制规则、临时封禁与临时例外标记为 EXPIRED，并记录系统审计。
// 临时封禁到期时补写 CC_TEMP_BLOCK_EXPIRED 访问控制事件（M-24）。
// 网关在时间窗到期后即停止执行，本任务负责管理状态回写与历史保留。
package guardjanitor

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jiuzhang-waf/server/internal/accesscontrolevents"
	"github.com/jiuzhang-waf/server/internal/accessrules"
	"github.com/jiuzhang-waf/server/internal/audits"
	"github.com/jiuzhang-waf/server/internal/exceptions"
	"github.com/jiuzhang-waf/server/internal/temporaryblocks"
	"github.com/jiuzhang-waf/server/internal/urlwhitelists"
)

// DefaultInterval 默认调度间隔。
const DefaultInterval = time.Minute

// SweepOnce 执行一次到期标记（可由调度与测试直接调用）。
func SweepOnce(ctx context.Context, rules *accessrules.Store, blocks *temporaryblocks.Store, auditSvc *audits.Service) (rulesExpired, blocksExpired int, err error) {
	return SweepOnceFull(ctx, rules, blocks, nil, auditSvc, nil)
}

// SweepOnceFull 到期标记（含临时例外；可选写入访问控制事件）。
func SweepOnceFull(ctx context.Context, rules *accessrules.Store, blocks *temporaryblocks.Store, exceptionStore *exceptions.Store, auditSvc *audits.Service, acEvents *accesscontrolevents.Store) (rulesExpired, blocksExpired int, err error) {
	return SweepOnceWithURLWhitelists(ctx, rules, nil, blocks, exceptionStore, auditSvc, acEvents)
}

// SweepOnceWithURLWhitelists 到期标记（含 IP 黑白名单、URL 白名单、临时封禁与临时例外）。
func SweepOnceWithURLWhitelists(ctx context.Context, rules *accessrules.Store, urlRules *urlwhitelists.Store, blocks *temporaryblocks.Store, exceptionStore *exceptions.Store, auditSvc *audits.Service, acEvents *accesscontrolevents.Store) (rulesExpired, blocksExpired int, err error) {
	now := time.Now().UTC()
	if rules != nil {
		rulesExpired, err = rules.MarkExpired(ctx, now)
		if err != nil {
			return rulesExpired, blocksExpired, fmt.Errorf("expire access rules: %w", err)
		}
	}
	urlRulesExpired := 0
	if urlRules != nil {
		urlRulesExpired, err = urlRules.MarkExpired(ctx, now)
		if err != nil {
			return rulesExpired, blocksExpired, fmt.Errorf("expire url whitelists: %w", err)
		}
		rulesExpired += urlRulesExpired
	}
	if blocks != nil {
		expiredBlocks, berr := blocks.MarkExpiredReturning(ctx, now)
		if berr != nil {
			return rulesExpired, blocksExpired, fmt.Errorf("expire temporary blocks: %w", berr)
		}
		blocksExpired = len(expiredBlocks)
		// M-24：到期补写 CC_TEMP_BLOCK_EXPIRED 事件
		if acEvents != nil && len(expiredBlocks) > 0 {
			batch := make([]accesscontrolevents.Event, 0, len(expiredBlocks))
			for _, b := range expiredBlocks {
				ev := accesscontrolevents.Event{
					OccurredAt:     now,
					ApplicationID:  b.ApplicationID,
					ClientIP:       b.ClientIP,
					EventType:      accesscontrolevents.EventTypeCCTempBlockExpired,
					Action:         accesscontrolevents.ActionTempBlock,
					AccessRuleID:   b.ID.String(),
					BlockExpiresAt: &b.BlockExpiresAt,
					Message:        "临时封禁到期自动失效",
					GatewayNodeID:  "management-api",
				}
				batch = append(batch, ev)
			}
			if _, ierr := acEvents.Insert(ctx, batch); ierr != nil {
				slog.Warn("write CC_TEMP_BLOCK_EXPIRED events failed", "error", ierr, "count", len(batch))
			}
		}
	}
	exceptionsExpired := 0
	if exceptionStore != nil {
		exceptionsExpired, err = exceptionStore.ExpireTemporary(ctx)
		if err != nil {
			return rulesExpired, blocksExpired, fmt.Errorf("expire exceptions: %w", err)
		}
	}
	// 系统审计（有实际到期才记录）
	if auditSvc != nil && (rulesExpired > 0 || blocksExpired > 0 || exceptionsExpired > 0) {
		if err := auditSvc.Record(ctx, audits.RecordInput{
			Username:     "system",
			Module:       "access_control",
			Action:       "auto_expire",
			ObjectType:   "temporary_rules",
			ObjectName:   "到期自动失效",
			AfterSummary: fmt.Sprintf("临时规则到期 %d 条，临时封禁到期 %d 条，临时例外到期 %d 条", rulesExpired, blocksExpired, exceptionsExpired),
			Result:       audits.ResultSuccess,
			RiskLevel:    audits.RiskLow,
		}); err != nil {
			slog.Warn("guard janitor audit record failed", "error", err)
		}
	}
	return rulesExpired, blocksExpired, nil
}

// Run 周期调度（直到 ctx 取消）。
func Run(ctx context.Context, interval time.Duration, rules *accessrules.Store, blocks *temporaryblocks.Store, auditSvc *audits.Service) {
	RunFull(ctx, interval, rules, blocks, nil, auditSvc, nil)
}

// RunFull 周期调度（含临时例外到期与 CC 到期事件）。
func RunFull(ctx context.Context, interval time.Duration, rules *accessrules.Store, blocks *temporaryblocks.Store, exceptionStore *exceptions.Store, auditSvc *audits.Service, acEvents *accesscontrolevents.Store) {
	RunWithURLWhitelists(ctx, interval, rules, nil, blocks, exceptionStore, auditSvc, acEvents)
}

// RunWithURLWhitelists 周期调度（含 URL 白名单临时到期标记）。
func RunWithURLWhitelists(ctx context.Context, interval time.Duration, rules *accessrules.Store, urlRules *urlwhitelists.Store, blocks *temporaryblocks.Store, exceptionStore *exceptions.Store, auditSvc *audits.Service, acEvents *accesscontrolevents.Store) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	slog.Info("guard janitor started", "interval", interval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			re, be, err := SweepOnceWithURLWhitelists(ctx, rules, urlRules, blocks, exceptionStore, auditSvc, acEvents)
			if err != nil {
				slog.Error("guard janitor sweep failed", "error", err)
				continue
			}
			if re > 0 || be > 0 {
				slog.Info("guard janitor expired", "access_rules", re, "temporary_blocks", be)
			}
		}
	}
}
