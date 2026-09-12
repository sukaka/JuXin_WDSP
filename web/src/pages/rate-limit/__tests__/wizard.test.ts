import { describe, expect, it } from 'vitest'
import dayjs from 'dayjs'
import { WIZARD_STEPS, buildPolicyBody, buildSummaryItems, policyToFormValues } from '../wizard'
import type { PolicyFormValues } from '../wizard'
import type { RateLimitPolicyItem } from '../../../types'

const baseValues: PolicyFormValues = {
  name: '登录防爆破',
  scope_type: 'GLOBAL',
  uri_match_type: 'ALL',
  dimension: 'CLIENT_IP',
  algorithm: 'TOKEN_BUCKET',
  requests_limit: 100,
  window_seconds: 60,
  action: 'REJECT',
  priority: 100,
}

function makeRecord(overrides: Partial<RateLimitPolicyItem> = {}): RateLimitPolicyItem {
  return {
    id: 'p1',
    name: '登录防爆破',
    description: '登录接口保护',
    scope_type: 'URI',
    application_id: 'app-1',
    uri_match_type: 'PREFIX',
    uri_pattern: '/api/login',
    dimension: 'CLIENT_IP_AND_URI',
    algorithm: 'SLIDING_WINDOW',
    requests_limit: 30,
    window_seconds: 120,
    burst_capacity: 50,
    action: 'TEMP_BLOCK',
    block_duration_seconds: 600,
    status: 'ACTIVE',
    observe_only: true,
    priority: 10,
    effective_from: '2026-09-01T00:00:00.000Z',
    effective_until: '2026-10-01T00:00:00.000Z',
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 3,
    ...overrides,
  }
}

describe('WIZARD_STEPS 分步定义', () => {
  it('共四步，末步为确认摘要且不校验字段', () => {
    expect(WIZARD_STEPS).toHaveLength(4)
    expect(WIZARD_STEPS[3].title).toBe('确认摘要')
    expect(WIZARD_STEPS[3].fields).toHaveLength(0)
  })

  it('前三步各自声明需校验字段，且覆盖全部必填校验字段', () => {
    expect(WIZARD_STEPS[0].fields).toEqual(
      expect.arrayContaining(['name', 'scope_type', 'application_id', 'uri_match_type', 'uri_pattern']),
    )
    expect(WIZARD_STEPS[1].fields).toEqual(
      expect.arrayContaining(['requests_limit', 'window_seconds']),
    )
    expect(WIZARD_STEPS[2].fields).toEqual(
      expect.arrayContaining(['action', 'block_duration_seconds']),
    )
  })
})

describe('buildPolicyBody 请求体组装', () => {
  it('GLOBAL 范围裁剪 application_id，ALL 匹配裁剪 uri_pattern', () => {
    const body = buildPolicyBody({
      ...baseValues,
      application_id: 'app-should-drop',
      uri_pattern: '/should-drop',
    })
    expect(body.application_id).toBeNull()
    expect(body.uri_pattern).toBe('')
  })

  it('非 TEMP_BLOCK 动作封禁时长归零，TEMP_BLOCK 保留时长', () => {
    expect(buildPolicyBody({ ...baseValues, action: 'REJECT', block_duration_seconds: 600 }).block_duration_seconds).toBe(0)
    expect(
      buildPolicyBody({ ...baseValues, action: 'TEMP_BLOCK', block_duration_seconds: 600 })
        .block_duration_seconds,
    ).toBe(600)
  })

  it('缺省可选字段取默认值，生效时间转 ISO', () => {
    const body = buildPolicyBody({
      ...baseValues,
      effective_range: [dayjs('2026-09-01T08:00:00+08:00'), null],
    })
    expect(body.burst_capacity).toBe(0)
    expect(body.observe_only).toBe(false)
    expect(body.effective_from).toBe('2026-09-01T00:00:00.000Z')
    expect(body.effective_until).toBeNull()
  })
})

describe('policyToFormValues 编辑回填', () => {
  it('完整回填记录字段（含生效区间 dayjs 转换）', () => {
    const values = policyToFormValues(makeRecord())
    expect(values.name).toBe('登录防爆破')
    expect(values.scope_type).toBe('URI')
    expect(values.application_id).toBe('app-1')
    expect(values.uri_pattern).toBe('/api/login')
    expect(values.block_duration_seconds).toBe(600)
    expect(values.observe_only).toBe(true)
    expect(values.effective_range?.[0]?.toISOString()).toBe('2026-09-01T00:00:00.000Z')
    expect(values.effective_range?.[1]?.toISOString()).toBe('2026-10-01T00:00:00.000Z')
  })

  it('空值字段回填为 undefined/null，回填后可无损还原请求体', () => {
    const record = makeRecord({
      description: '',
      uri_pattern: '',
      block_duration_seconds: 0,
      effective_from: null,
      effective_until: null,
    })
    const values = policyToFormValues(record)
    expect(values.description).toBeUndefined()
    expect(values.block_duration_seconds).toBeUndefined()
    expect(values.effective_range).toEqual([null, null])

    const body = buildPolicyBody(values)
    expect(body).toMatchObject({
      name: record.name,
      scope_type: 'URI',
      application_id: 'app-1',
      uri_match_type: 'PREFIX',
      uri_pattern: '',
      action: 'TEMP_BLOCK',
      block_duration_seconds: 0,
      effective_from: null,
      effective_until: null,
    })
  })
})

describe('buildSummaryItems 摘要数据组装', () => {
  it('GLOBAL + ALL 输出精简范围/匹配文案，突发缺省取阈值', () => {
    const items = buildSummaryItems(baseValues)
    const get = (label: string) => items.find((i) => i.label === label)?.value
    expect(get('策略名称')).toBe('登录防爆破')
    expect(get('作用范围')).toBe('全局')
    expect(get('路径匹配')).toBe('全部路径')
    expect(get('限速参数')).toBe('100 次 / 60 秒，突发容量 100')
    expect(get('超阈值动作')).toBe('拒绝(429)')
    expect(get('生效时间')).toBe('长期生效')
    expect(get('仅观察')).toBe('否')
  })

  it('应用范围经 appLabel 解析，TEMP_BLOCK 摘要含封禁时长', () => {
    const values = policyToFormValues(makeRecord())
    const items = buildSummaryItems(values, (id) => (id === 'app-1' ? '商城（mall）' : undefined))
    const get = (label: string) => items.find((i) => i.label === label)?.value
    expect(get('作用范围')).toBe('应用+路径：商城（mall）')
    expect(get('路径匹配')).toBe('前缀匹配：/api/login')
    expect(get('超阈值动作')).toBe('临时封禁（600 秒）')
    expect(get('仅观察')).toBe('是（命中只记录不阻断）')
    expect(get('限速参数')).toBe('30 次 / 120 秒，突发容量 50')
  })

  it('appLabel 缺失时回退为应用 ID，未知枚举回退为原始值', () => {
    const items = buildSummaryItems({
      ...baseValues,
      scope_type: 'APPLICATION',
      application_id: 'app-x',
      action: 'FUTURE_ACTION',
    })
    const get = (label: string) => items.find((i) => i.label === label)?.value
    expect(get('作用范围')).toBe('指定应用：app-x')
    expect(get('超阈值动作')).toBe('FUTURE_ACTION')
  })
})
