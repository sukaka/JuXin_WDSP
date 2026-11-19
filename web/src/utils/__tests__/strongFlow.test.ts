import { describe, expect, it } from 'vitest'
import type { StrongFlowStep } from '../../api/strongFlow'
import {
  STEP_EVENT_RESULT_META,
  STRONG_FLOW_MODE_META,
  canResolveInstance,
  classifyResolveConflict,
  isTerminalInstance,
  shortInstanceKey,
  successRuleText,
  validInstanceKeyParam,
  validateStrongFlowSteps,
  validateStrongFlowSuccessRule,
} from '../strongFlow'

function step(partial: Partial<StrongFlowStep> = {}): StrongFlowStep {
  return {
    step_key: 'register',
    endpoint_key: 'POST /api/v1/register',
    sequence: 1,
    success_rule: { status_codes: [200] },
    timeout_seconds: 60,
    retry_semantics: 'IDEMPOTENT',
    parallel_group: '',
    lease_seconds: 60,
    allows_202: false,
    ...partial,
  }
}

describe('validateStrongFlowSteps（镜像 server validateSteps 结构规则）', () => {
  it('空步骤集与超上限', () => {
    expect(validateStrongFlowSteps([])).toBe('定义至少包含一个步骤')
    expect(validateStrongFlowSteps(Array.from({ length: 65 }, (_, i) => step({ step_key: `s${i}`, sequence: i + 1 })))).toBe('步骤数超上限 64')
  })

  it('step_key 重复 / sequence 重复', () => {
    expect(validateStrongFlowSteps([step(), step({ endpoint_key: 'POST /api/v1/pay', sequence: 2 })])).toBe(
      '步骤标识 "register" 重复（定义内唯一）',
    )
    expect(validateStrongFlowSteps([step(), step({ step_key: 'pay', endpoint_key: 'POST /api/v1/pay' })])).toBe(
      '顺序号 1 重复（定义内唯一——严格递增即首步唯一最小的承载）',
    )
  })

  it('parallel_group 单步与不相邻', () => {
    expect(
      validateStrongFlowSteps([step({ parallel_group: 'g1' })]),
    ).toBe('并行组 "g1" 仅一步（并行组至少两步；单步请置空串行）')
    expect(
      validateStrongFlowSteps([
        step({ parallel_group: 'g1' }),
        step({ step_key: 'a', sequence: 2, parallel_group: 'g1' }),
        step({ step_key: 'b', sequence: 4, parallel_group: 'g1' }),
      ]),
    ).toBe('并行组 "g1" 步骤顺序号不相邻（同组须连续区间）')
    // 相邻连续合法
    expect(
      validateStrongFlowSteps([
        step({ parallel_group: 'g1' }),
        step({ step_key: 'a', sequence: 2, parallel_group: 'g1' }),
      ]),
    ).toBe('')
  })

  it('timeout/lease 词表外拒收不夹紧', () => {
    expect(validateStrongFlowSteps([step({ timeout_seconds: 14 })])).toContain('超时时间超出范围（15~600')
    expect(validateStrongFlowSteps([step({ timeout_seconds: 601 })])).toContain('超时时间超出范围（15~600')
    expect(validateStrongFlowSteps([step({ lease_seconds: 301 })])).toContain('租约时长超出范围（15~300')
  })

  it('success_rule 必填与至少一形态', () => {
    expect(validateStrongFlowSteps([step({ success_rule: null })])).toContain('成功判定规则：必填（无成功判定规则的步骤恒为未知')
    expect(validateStrongFlowSteps([step({ success_rule: {} })])).toContain('至少配置一种成功判定条件')
  })

  it('合法定义返回空串', () => {
    expect(validateStrongFlowSteps([step(), step({ step_key: 'pay', endpoint_key: 'POST /api/v1/pay', sequence: 2 })])).toBe('')
  })
})

describe('validateStrongFlowSuccessRule（§1.4 三形态）', () => {
  it('状态码值域 / JSONPath 子集形态 / value 必填', () => {
    expect(validateStrongFlowSuccessRule({ status_codes: [99] })).toBe('状态码列表元素须为合法 HTTP 状态码（100~599）')
    expect(validateStrongFlowSuccessRule({ body_jsonpath_equals: { path: 'status', value: 'PAID' } })).toContain('形态非法（仅支持点路径子集，如 $.a.b')
    expect(validateStrongFlowSuccessRule({ body_jsonpath_equals: { path: '$.status', value: '' } })).toBe('响应体字段目标值必填')
    expect(validateStrongFlowSuccessRule({ body_jsonpath_equals: { path: '$.status', value: 'PAID' } })).toBe('')
    expect(validateStrongFlowSuccessRule({ graphql_errors_empty: true })).toBe('')
  })
})

describe('successRuleText & 中文词表（成功条件与结果标签）', () => {
  it('三形态组合与连接，无配置如实显示恒为未知', () => {
    expect(
      successRuleText({
        status_codes: [200, 201],
        body_jsonpath_equals: { path: '$.status', value: 'PAID' },
        graphql_errors_empty: true,
      }),
    ).toBe('状态码 ∈ [200, 201] 且 $.status == "PAID" 且 GraphQL 错误列表为空')
    expect(successRuleText(null)).toBe('未配置（该步骤恒为未知）')
    expect(successRuleText({})).toBe('未配置（该步骤恒为未知）')
  })

  it('步骤结果与模式词表均为纯中文标签', () => {
    expect(STEP_EVENT_RESULT_META.OK.label).toBe('成功')
    expect(STEP_EVENT_RESULT_META.UNKNOWN.label).toBe('未知')
    expect(STRONG_FLOW_MODE_META.OBSERVE.label).toBe('观察')
    expect(STRONG_FLOW_MODE_META.PROTECT.label).toBe('实断')
  })
})

describe('实例引用提取器形态 / 恢复可用性 / 409 归类', () => {
  it('validInstanceKeyParam：query:<名> / path:<段序>', () => {
    expect(validInstanceKeyParam('query:order_id')).toBe(true)
    expect(validInstanceKeyParam('path:3')).toBe(true)
    expect(validInstanceKeyParam('path:')).toBe(false)
    expect(validInstanceKeyParam('path:abc')).toBe(false)
    expect(validInstanceKeyParam('query:')).toBe(false)
    expect(validInstanceKeyParam('query:a b')).toBe(false)
    expect(validInstanceKeyParam('header:x')).toBe(false)
  })

  it('canResolveInstance/isTerminalInstance：仅 ACTIVE/INDETERMINATE 可恢复', () => {
    expect(canResolveInstance('ACTIVE')).toBe(true)
    expect(canResolveInstance('INDETERMINATE')).toBe(true)
    expect(canResolveInstance('CONFIRMED')).toBe(false)
    expect(isTerminalInstance('CONFIRMED')).toBe(true)
    expect(isTerminalInstance('CANCELLED')).toBe(true)
    expect(isTerminalInstance('FAILED')).toBe(true)
    expect(isTerminalInstance('ACTIVE')).toBe(false)
  })

  it('classifyResolveConflict：版本冲突 / 实例已终态 / 其他', () => {
    expect(classifyResolveConflict('strong flow instance version conflict（乐观锁不匹配：实例已被变更，请刷新后重试）')).toBe('version')
    expect(classifyResolveConflict('instance already terminal（CONFIRMED/CANCELLED/FAILED 终态拒绝重复恢复）')).toBe('terminal')
    expect(classifyResolveConflict('invalid status transition（RETIRED 单向终态）')).toBe('terminal')
    expect(classifyResolveConflict('something else')).toBe('other')
  })

  it('shortInstanceKey 截断', () => {
    expect(shortInstanceKey('sfref:0123456789abcdef0123456789abcdef')).toBe('sfref:01234567…89abcdef')
    expect(shortInstanceKey('sfref:short')).toBe('sfref:short')
    expect(shortInstanceKey('')).toBe('-')
  })
})
