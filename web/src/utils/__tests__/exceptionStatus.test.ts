import { describe, expect, it } from 'vitest'
import {
  computeExceptionDerivedStatus,
  deriveExceptionStatus,
  getExceptionEnableBlockers,
  isActionSupportedForNewEnable,
} from '../exceptionStatus'

const NOW = Date.parse('2026-09-07T12:00:00Z')

describe('computeExceptionDerivedStatus', () => {
  it('启用中且 now >= effective_until（半开区间上界）→ EXPIRED', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        effective_until: '2026-09-07T12:00:00Z',
        now: NOW,
      }),
    ).toBe('EXPIRED')
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        effective_until: '2026-09-07T11:59:59Z',
        now: NOW,
      }),
    ).toBe('EXPIRED')
  })

  it('启用中且未到失效时间：按发布数据继续推导（不判 EXPIRED）', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        effective_until: '2026-09-07T12:00:01Z',
        now: NOW,
      }),
    ).toBe('ENABLED_NOT_PUBLISHED')
  })

  it('后端原始状态 EXPIRED → EXPIRED（与有效期无关）', () => {
    expect(computeExceptionDerivedStatus({ status: 'EXPIRED', now: NOW })).toBe('EXPIRED')
  })

  it('DISABLED 优先于时间：停用记录即使已过有效期仍显示 DISABLED', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'DISABLED',
        effective_until: '2026-09-01T00:00:00Z',
        now: NOW,
      }),
    ).toBe('DISABLED')
  })

  it('NEEDS_REVIEW 优先于 DISABLED/DRAFT：待审查醒目标记不被停用态掩盖', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'DISABLED',
        validation_status: 'NEEDS_REVIEW',
        now: NOW,
      }),
    ).toBe('NEEDS_REVIEW')
    expect(
      computeExceptionDerivedStatus({
        status: 'DRAFT',
        validation_status: 'NEEDS_REVIEW',
        now: NOW,
      }),
    ).toBe('NEEDS_REVIEW')
  })

  it('NEEDS_REVIEW 优先于发布推导（历史危险配置只标记）', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        validation_status: 'NEEDS_REVIEW',
        publish: { state: 'PUBLISHED', nodes_total: 2, nodes_acknowledged: 2 },
        now: NOW,
      }),
    ).toBe('NEEDS_REVIEW')
  })

  it('EXPIRED 优先于 NEEDS_REVIEW（到期是事实）', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        validation_status: 'NEEDS_REVIEW',
        effective_until: '2026-09-01T00:00:00Z',
        now: NOW,
      }),
    ).toBe('EXPIRED')
  })

  it('非 ENABLED 且非 DISABLED/EXPIRED → DRAFT', () => {
    expect(computeExceptionDerivedStatus({ status: 'DRAFT', now: NOW })).toBe('DRAFT')
    expect(computeExceptionDerivedStatus({ status: undefined, now: NOW })).toBe('DRAFT')
  })

  it('ENABLED 无发布数据 → ENABLED_NOT_PUBLISHED（未发布/未知，不假装全节点一致）', () => {
    expect(computeExceptionDerivedStatus({ status: 'ENABLED', now: NOW })).toBe(
      'ENABLED_NOT_PUBLISHED',
    )
    expect(computeExceptionDerivedStatus({ status: 'ENABLED', publish: null, now: NOW })).toBe(
      'ENABLED_NOT_PUBLISHED',
    )
    expect(
      computeExceptionDerivedStatus({ status: 'ENABLED', publish: {}, now: NOW }),
    ).toBe('ENABLED_NOT_PUBLISHED')
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'NOT_PUBLISHED' },
        now: NOW,
      }),
    ).toBe('ENABLED_NOT_PUBLISHED')
  })

  it('ENABLED + PUBLISHING → PUBLISHING', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'PUBLISHING' },
        now: NOW,
      }),
    ).toBe('PUBLISHING')
  })

  it('ENABLED + 节点回执全部到位 → EFFECTIVE；部分到位 → PARTIALLY_EFFECTIVE', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'PUBLISHED', nodes_total: 3, nodes_acknowledged: 3 },
        now: NOW,
      }),
    ).toBe('EFFECTIVE')
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'PUBLISHED', nodes_total: 3, nodes_acknowledged: 1 },
        now: NOW,
      }),
    ).toBe('PARTIALLY_EFFECTIVE')
  })

  it('ENABLED + PARTIAL 无节点计数 → PARTIALLY_EFFECTIVE', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'PARTIAL' },
        now: NOW,
      }),
    ).toBe('PARTIALLY_EFFECTIVE')
  })

  it('ENABLED + PUBLISHED 但无节点回执明细 → ENABLED_NOT_PUBLISHED（不凭发布动作假装生效）', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        publish: { state: 'PUBLISHED' },
        now: NOW,
      }),
    ).toBe('ENABLED_NOT_PUBLISHED')
  })

  it('effective_until 非法字符串按无结束时间处理（不误判过期）', () => {
    expect(
      computeExceptionDerivedStatus({
        status: 'ENABLED',
        effective_until: 'not-a-date',
        now: NOW,
      }),
    ).toBe('ENABLED_NOT_PUBLISHED')
  })

  it('effective_until 为空（永久例外）不判 EXPIRED', () => {
    expect(
      computeExceptionDerivedStatus({ status: 'ENABLED', effective_until: null, now: NOW }),
    ).toBe('ENABLED_NOT_PUBLISHED')
  })
})

describe('deriveExceptionStatus', () => {
  it('从记录字段透传计算', () => {
    expect(
      deriveExceptionStatus(
        { status: 'ENABLED', validation_status: 'VALID', effective_until: null },
        { state: 'PUBLISHED', nodes_total: 1, nodes_acknowledged: 1 },
        NOW,
      ),
    ).toBe('EFFECTIVE')
    expect(
      deriveExceptionStatus(
        { status: 'ENABLED', validation_status: 'NEEDS_REVIEW', effective_until: null },
        undefined,
        NOW,
      ),
    ).toBe('NEEDS_REVIEW')
  })
})

describe('isActionSupportedForNewEnable', () => {
  it('WAF：REMOVE_RULE/REMOVE_RULE_TAG/REMOVE_VAR_DETECTION 支持，LOG_ONLY/ADJUST_SCORE 拒绝', () => {
    expect(isActionSupportedForNewEnable('WAF', 'REMOVE_RULE')).toBe(true)
    expect(isActionSupportedForNewEnable('WAF', 'REMOVE_RULE_TAG')).toBe(true)
    expect(isActionSupportedForNewEnable('WAF', 'REMOVE_VAR_DETECTION')).toBe(true)
    expect(isActionSupportedForNewEnable('WAF', 'LOG_ONLY')).toBe(false)
    expect(isActionSupportedForNewEnable('WAF', 'ADJUST_SCORE')).toBe(false)
  })

  it('target_engine 缺省按 WAF 处理（兼容旧记录无该字段）', () => {
    expect(isActionSupportedForNewEnable(undefined, 'LOG_ONLY')).toBe(false)
    expect(isActionSupportedForNewEnable(undefined, 'REMOVE_RULE')).toBe(true)
  })

  it('API：仅 OBSERVE_RULE 支持', () => {
    expect(isActionSupportedForNewEnable('API', 'OBSERVE_RULE')).toBe(true)
    expect(isActionSupportedForNewEnable('API', 'REMOVE_RULE')).toBe(false)
    expect(isActionSupportedForNewEnable('API', 'LOG_ONLY')).toBe(false)
  })
})

describe('getExceptionEnableBlockers', () => {
  it('VALID + 受支持动作 → 无阻断', () => {
    expect(
      getExceptionEnableBlockers({
        validation_status: 'VALID',
        unsupported_reasons: null,
        target_engine: 'WAF',
        exception_action: 'REMOVE_RULE',
      }),
    ).toEqual([])
  })

  it('NEEDS_REVIEW + unsupported_reasons → 阻断并逐条说明缺什么', () => {
    const blockers = getExceptionEnableBlockers({
      validation_status: 'NEEDS_REVIEW',
      unsupported_reasons: ['缺少目标应用绑定', '规则标签无法解析为冻结规则集'],
      target_engine: 'WAF',
      exception_action: 'REMOVE_RULE',
    })
    expect(blockers).toHaveLength(1)
    expect(blockers[0]).toContain('缺少目标应用绑定')
    expect(blockers[0]).toContain('规则标签无法解析为冻结规则集')
  })

  it('NEEDS_REVIEW 无原因明细时给出通用说明', () => {
    const blockers = getExceptionEnableBlockers({
      validation_status: 'NEEDS_REVIEW',
      unsupported_reasons: [],
      target_engine: 'WAF',
      exception_action: 'REMOVE_RULE',
    })
    expect(blockers).toHaveLength(1)
    expect(blockers[0]).toContain('待审查')
  })

  it('历史不支持动作（WAF LOG_ONLY）→ 阻断并提示改精确目标排除', () => {
    const blockers = getExceptionEnableBlockers({
      validation_status: 'VALID',
      unsupported_reasons: null,
      target_engine: 'WAF',
      exception_action: 'LOG_ONLY',
    })
    expect(blockers).toHaveLength(1)
    expect(blockers[0]).toContain('仅记录不阻断')
    expect(blockers[0]).toContain('移除变量检测')
    expect(blockers[0]).not.toContain('LOG_ONLY')
    expect(blockers[0]).not.toContain('REMOVE_VAR_DETECTION')
  })

  it('NEEDS_REVIEW + 不支持动作 → 两条阻断叠加', () => {
    const blockers = getExceptionEnableBlockers({
      validation_status: 'NEEDS_REVIEW',
      unsupported_reasons: ['历史 LOG_ONLY 配置需迁移'],
      target_engine: 'WAF',
      exception_action: 'ADJUST_SCORE',
    })
    expect(blockers).toHaveLength(2)
  })
})
