import { describe, expect, it } from 'vitest'
import {
  formatRulePhaseZh,
  resolveWafRuleDetail,
  ruleTagTooltipZh,
  WAF_RULE_DETAIL_SOURCE_META,
  WAF_RULE_TYPE_META,
} from '../wafRuleDetails'
import type { WafRuleItem } from '../../types'

describe('wafRuleDetails 中文详述与展示工具', () => {
  it('将执行阶段编号格式化为中文阶段名', () => {
    expect(formatRulePhaseZh(1)).toBe('阶段 1（请求头检查）')
    expect(formatRulePhaseZh(2)).toBe('阶段 2（请求体与参数检查）')
    expect(formatRulePhaseZh(4)).toBe('阶段 4（响应体检查）')
    expect(formatRulePhaseZh(5)).toBe('阶段 5（日志与关联分析）')
    expect(formatRulePhaseZh(undefined)).toBe('-')
  })

  it('为常见规则标签提供中文悬停提示', () => {
    expect(ruleTagTooltipZh('paranoia-level/1')).toContain('PL1')
    expect(ruleTagTooltipZh('attack-sqli')).toContain('SQL 注入')
    expect(ruleTagTooltipZh('cve/CVE-2021-44228')).toContain('CVE-2021-44228')
    expect(ruleTagTooltipZh('capec/1000/152/248/66')).toContain('CAPEC-66')
    expect(ruleTagTooltipZh('ai-crawler')).toContain('AI')
  })

  it('优先返回后端下发的结构化中文 detail', () => {
    const rule: WafRuleItem = {
      id: 'rule-911100',
      rule_id: 911100,
      rule_source: 'OWASP_CRS',
      file_name: 'REQUEST-911-METHOD-ENFORCEMENT.conf',
      name: '请求方法不被策略允许',
      message: '请求方法不被策略允许',
      description: '校验 HTTP 请求方法是否在白名单内。',
      detail: {
        rule_type: 'DETECTION',
        rule_type_label: '安全检测规则',
        summary: '校验客户端使用的 HTTP 请求方法是否在当前策略允许的方法白名单内。',
        detection_logic: '在阶段 1 检查 HTTP 请求方法（REQUEST_METHOD）。',
        risk_impact: '防止 TRACE/PUT/DELETE 等危险方法扩大攻击面。',
        tuning_advice: 'RESTful API 如需 PUT/DELETE 请在策略中按需放行。',
        phase_description: '阶段 1（请求头检查）：收到完整请求头后执行',
        paranoia_level: 'PL1（默认启用，低误报基线防护）',
        action_behavior: '异常评分（入站，严重级别 +5 分）',
        targets: ['HTTP 请求方法（REQUEST_METHOD）'],
        references: ['CAPEC-274：HTTP 方法篡改'],
      },
      severity: 'CRITICAL',
      phase: 1,
      tags: ['paranoia-level/1'],
      attack_type: 'OTHER',
      default_state: 'ENABLED',
      crs_version: '4.28.0',
    }
    const resolved = resolveWafRuleDetail(rule)
    expect(resolved.summary).toContain('HTTP 请求方法')
    expect(resolved.targets).toEqual(['HTTP 请求方法（REQUEST_METHOD）'])
    expect(WAF_RULE_TYPE_META[resolved.rule_type]?.label).toBe('安全检测规则')
  })

  it('后端未返回 detail 时自动合成完整中文兜底说明（含内部规则识别）', () => {
    const internalRule: WafRuleItem = {
      id: 'rule-913011',
      rule_id: 913011,
      rule_source: 'OWASP_CRS',
      file_name: 'REQUEST-913-SCANNER-DETECTION.conf',
      name: '扫描器检测内部规则',
      message: '扫描器检测内部规则',
      severity: 'NOTICE',
      phase: 1,
      tags: ['OWASP_CRS'],
      attack_type: 'OTHER',
      default_state: 'ENABLED',
      crs_version: '4.28.0',
    }
    const resolved = resolveWafRuleDetail(internalRule)
    expect(resolved.rule_type).toBe('INTERNAL')
    expect(resolved.rule_type_label).toBe('引擎内部控制规则')
    expect(resolved.summary).toContain('内部流程控制')
    expect(resolved.tuning_advice).toContain('不应手动停用')
    expect(resolved.source).toBe('AUTO')
    expect(WAF_RULE_DETAIL_SOURCE_META.PARSED.label).toBe('规则文件自动解析')
    expect(WAF_RULE_DETAIL_SOURCE_META.CUSTOM.label).toBe('人工维护说明')
  })
})
