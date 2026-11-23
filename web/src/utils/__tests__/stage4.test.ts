import { describe, expect, it } from 'vitest'
import {
  EXCEPTION_STATUS_META,
  RULE_SOURCE_META,
  isBroadExceptionDraft,
  parseWafRuleTags,
} from '../stage4'

describe('parseWafRuleTags', () => {
  it('解析后端 base64 编码的 JSON 数组（[]byte 序列化行为）', () => {
    // '["OWASP_CRS","attack-sqli"]' 的 base64
    expect(parseWafRuleTags('WyJPV0FTUF9DUlMiLCJhdHRhY2stc3FsaSJd')).toEqual([
      'OWASP_CRS',
      'attack-sqli',
    ])
  })

  it('兼容已修复后端的数组返回', () => {
    expect(parseWafRuleTags(['a', 'b'])).toEqual(['a', 'b'])
  })

  it('兼容直接返回 JSON 字符串', () => {
    expect(parseWafRuleTags('["x","y"]')).toEqual(['x', 'y'])
  })

  it('空值返回空数组', () => {
    expect(parseWafRuleTags(null)).toEqual([])
    expect(parseWafRuleTags(undefined)).toEqual([])
    expect(parseWafRuleTags('')).toEqual([])
  })

  it('无法解析的普通字符串按单标签处理', () => {
    expect(parseWafRuleTags('plain-tag')).toEqual(['plain-tag'])
  })

  it('过滤数组中的非字符串元素', () => {
    expect(parseWafRuleTags(['a', 1, null, 'b'])).toEqual(['a', 'b'])
  })
})

describe('isBroadExceptionDraft（镜像后端 exceptions.IsBroad）', () => {
  it('有具体限定条件（URI前缀）时不算宽泛', () => {
    expect(
      isBroadExceptionDraft({
        scope_type: 'GLOBAL',
        uri_prefix: '/api/',
        attack_types: ['SQL_INJECTION'],
      }),
    ).toBe(false)
  })

  it('针对 SQLi 且无任何限定条件 → 宽泛', () => {
    expect(isBroadExceptionDraft({ scope_type: 'APPLICATION', attack_types: ['SQL_INJECTION'] })).toBe(
      true,
    )
    expect(isBroadExceptionDraft({ scope_type: 'APPLICATION', attack_types: ['XSS'] })).toBe(true)
    expect(
      isBroadExceptionDraft({ scope_type: 'APPLICATION', attack_types: ['COMMAND_INJECTION'] }),
    ).toBe(true)
  })

  it('非高风险攻击类型且非全局 → 不宽泛', () => {
    expect(
      isBroadExceptionDraft({ scope_type: 'APPLICATION', attack_types: ['PROTOCOL_VIOLATION'] }),
    ).toBe(false)
  })

  it('全局范围且无具体限定条件 → 宽泛', () => {
    expect(isBroadExceptionDraft({ scope_type: 'GLOBAL' })).toBe(true)
  })

  it('无应用限定且规则标签含 SQLI/XSS → 宽泛', () => {
    expect(isBroadExceptionDraft({ scope_type: 'APPLICATION', rule_tags: ['attack-sqli'] })).toBe(true)
    // 有应用限定则不宽泛
    expect(
      isBroadExceptionDraft({
        scope_type: 'APPLICATION',
        rule_tags: ['attack-sqli'],
        application_id: 'app-1',
      }),
    ).toBe(false)
  })

  it('有规则ID限定 → 精确例外', () => {
    expect(
      isBroadExceptionDraft({ scope_type: 'GLOBAL', rule_ids: [942100], attack_types: ['SQL_INJECTION'] }),
    ).toBe(false)
  })
})

describe('EXCEPTION_STATUS_META / RULE_SOURCE_META（B4-05 / B8-04）', () => {
  it('EXCEPTION_STATUS_META 包含 DRAFT 草稿状态', () => {
    expect(EXCEPTION_STATUS_META.DRAFT).toEqual({ color: 'default', label: '草稿' })
    expect(Object.keys(EXCEPTION_STATUS_META)).toEqual(['DRAFT', 'ENABLED', 'DISABLED', 'EXPIRED'])
  })

  it('RULE_SOURCE_META 不含无效的 CUSTOM，保留后端 6 个合法来源', () => {
    expect(RULE_SOURCE_META.CUSTOM).toBeUndefined()
    expect(Object.keys(RULE_SOURCE_META).sort()).toEqual([
      'CRS_PLUGIN',
      'CUSTOM_PACK',
      'JIUZHANG_BUILTIN',
      'OWASP_CRS',
      'THIRD_PARTY',
      'USER_CUSTOM',
    ])
    expect(RULE_SOURCE_META.USER_CUSTOM).toEqual({ color: 'purple', label: '用户自定义' })
  })
})
