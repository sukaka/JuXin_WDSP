import { describe, expect, it } from 'vitest'
import {
  WHAT_IF_SCENARIO_OPTIONS,
  buildWhatIfBody,
  whatIfSupportsTimeRange,
} from '../whatIf'

describe('What-If 场景与参数提交载荷（§19 八场景契约）', () => {
  it('场景选项覆盖契约八种场景', () => {
    expect(WHAT_IF_SCENARIO_OPTIONS.map((o) => o.value)).toEqual([
      'disable_rule',
      'enable_rule',
      'anomaly_threshold',
      'pl_switch',
      'add_exception',
      'remove_exception',
      'cc_threshold',
      'block_duration',
    ])
  })

  it('disable_rule：rule_id，不带 time_range', () => {
    expect(buildWhatIfBody({ scenario: 'disable_rule', rule_id: 942100, time_range: '7d' })).toEqual(
      { scenario: 'disable_rule', rule_id: 942100 },
    )
  })

  it('enable_rule：rule_id + time_range', () => {
    expect(buildWhatIfBody({ scenario: 'enable_rule', rule_id: 920100, time_range: '30d' })).toEqual({
      scenario: 'enable_rule',
      rule_id: 920100,
      time_range: '30d',
    })
  })

  it('anomaly_threshold：anomaly_threshold + time_range', () => {
    expect(
      buildWhatIfBody({ scenario: 'anomaly_threshold', anomaly_threshold: 5, time_range: '24h' }),
    ).toEqual({ scenario: 'anomaly_threshold', anomaly_threshold: 5, time_range: '24h' })
  })

  it('pl_switch：paranoia_level + time_range', () => {
    expect(
      buildWhatIfBody({ scenario: 'pl_switch', paranoia_level: 2, time_range: '30d' }),
    ).toEqual({ scenario: 'pl_switch', paranoia_level: 2, time_range: '30d' })
  })

  it('add_exception：rule_id + time_range（契约：rule_id 必填，可选 scope 未暴露）', () => {
    expect(
      buildWhatIfBody({ scenario: 'add_exception', rule_id: 941160, time_range: '7d' }),
    ).toEqual({ scenario: 'add_exception', rule_id: 941160, time_range: '7d' })
  })

  it('remove_exception：exception_id + time_range，空白 ID 去首尾空格', () => {
    expect(
      buildWhatIfBody({
        scenario: 'remove_exception',
        exception_id: '  exc-1  ',
        time_range: '30d',
      }),
    ).toEqual({ scenario: 'remove_exception', exception_id: 'exc-1', time_range: '30d' })
  })

  it('cc_threshold / block_duration：沿用旧口径', () => {
    expect(buildWhatIfBody({ scenario: 'cc_threshold', cc_threshold: 200, time_range: '7d' })).toEqual(
      { scenario: 'cc_threshold', cc_threshold: 200, time_range: '7d' },
    )
    expect(
      buildWhatIfBody({ scenario: 'block_duration', block_duration_seconds: 3600, time_range: '7d' }),
    ).toEqual({ scenario: 'block_duration', block_duration_seconds: 3600, time_range: '7d' })
  })

  it('time_range 为空时不携带', () => {
    expect(buildWhatIfBody({ scenario: 'enable_rule', rule_id: 1 })).toEqual({
      scenario: 'enable_rule',
      rule_id: 1,
    })
  })
})

describe('What-If 参数校验（与后端边界一致）', () => {
  it('enable_rule / add_exception：rule_id 缺失或非正整数拒绝', () => {
    for (const scenario of ['enable_rule', 'add_exception'] as const) {
      expect(() => buildWhatIfBody({ scenario })).toThrow('请输入有效的规则 ID')
      expect(() => buildWhatIfBody({ scenario, rule_id: 0 })).toThrow('请输入有效的规则 ID')
      expect(() => buildWhatIfBody({ scenario, rule_id: 1.5 })).toThrow('请输入有效的规则 ID')
    }
  })

  it('anomaly_threshold：缺省/越界（1-10000）拒绝', () => {
    expect(() => buildWhatIfBody({ scenario: 'anomaly_threshold' })).toThrow(
      '请输入有效的异常阈值',
    )
    expect(() => buildWhatIfBody({ scenario: 'anomaly_threshold', anomaly_threshold: 0 })).toThrow(
      '请输入有效的异常阈值',
    )
    expect(() =>
      buildWhatIfBody({ scenario: 'anomaly_threshold', anomaly_threshold: 10001 }),
    ).toThrow('请输入有效的异常阈值')
    expect(() =>
      buildWhatIfBody({ scenario: 'anomaly_threshold', anomaly_threshold: 2.5 }),
    ).toThrow('请输入有效的异常阈值')
    expect(buildWhatIfBody({ scenario: 'anomaly_threshold', anomaly_threshold: 10000 })
      .anomaly_threshold).toBe(10000)
  })

  it('pl_switch：缺省/越界（1-4）拒绝', () => {
    expect(() => buildWhatIfBody({ scenario: 'pl_switch' })).toThrow('请选择 CRS 执行等级')
    expect(() => buildWhatIfBody({ scenario: 'pl_switch', paranoia_level: 0 })).toThrow(
      '请选择 CRS 执行等级',
    )
    expect(() => buildWhatIfBody({ scenario: 'pl_switch', paranoia_level: 5 })).toThrow(
      '请选择 CRS 执行等级',
    )
    expect(buildWhatIfBody({ scenario: 'pl_switch', paranoia_level: 4 }).paranoia_level).toBe(4)
  })

  it('remove_exception：exception_id 缺失或空白拒绝', () => {
    expect(() => buildWhatIfBody({ scenario: 'remove_exception' })).toThrow(
      '请选择要模拟删除的例外',
    )
    expect(() => buildWhatIfBody({ scenario: 'remove_exception', exception_id: '   ' })).toThrow(
      '请选择要模拟删除的例外',
    )
  })

  it('cc_threshold / block_duration：边界校验保持既有口径', () => {
    expect(() => buildWhatIfBody({ scenario: 'cc_threshold', cc_threshold: 1000001 })).toThrow(
      '请输入有效的 CC 阈值',
    )
    expect(() =>
      buildWhatIfBody({ scenario: 'block_duration', block_duration_seconds: 59 }),
    ).toThrow('请输入有效的封禁时长')
    expect(() =>
      buildWhatIfBody({ scenario: 'block_duration', block_duration_seconds: 2592001 }),
    ).toThrow('请输入有效的封禁时长')
  })

  it('whatIfSupportsTimeRange：仅 disable_rule 不支持', () => {
    expect(whatIfSupportsTimeRange('disable_rule')).toBe(false)
    for (const s of [
      'enable_rule',
      'anomaly_threshold',
      'pl_switch',
      'add_exception',
      'remove_exception',
      'cc_threshold',
      'block_duration',
    ] as const) {
      expect(whatIfSupportsTimeRange(s)).toBe(true)
    }
  })
})
