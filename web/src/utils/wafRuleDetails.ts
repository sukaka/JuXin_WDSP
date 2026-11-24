/* ==================== WAF 规则详情中文说明与展示辅助工具 ==================== */

import type { WafRuleDetailInfo, WafRuleItem } from '../types'
import { CRS_FAMILY_NAMES_ZH, ruleNameZh } from './crsRuleNames'
import { ATTACK_TYPE_META, parseWafRuleTags, RULE_SEVERITY_META, RULE_SOURCE_META } from './stage4'

/** 规则功能类别展示元数据 */
export const WAF_RULE_TYPE_META: Record<string, { color: string; label: string }> = {
  DETECTION: { color: 'blue', label: '安全检测规则' },
  OBSERVE: { color: 'cyan', label: '观测告警规则' },
  BLOCKING_EVALUATION: { color: 'red', label: '阻断评估规则' },
  EXCLUSION: { color: 'green', label: '误报排除规则' },
  PREPROCESSING: { color: 'purple', label: '预处理规则' },
  INTERNAL: { color: 'default', label: '引擎内部控制规则' },
}

/** 规则中文详细说明来源元数据 */
export const WAF_RULE_DETAIL_SOURCE_META: Record<string, { color: string; label: string }> = {
  CUSTOM: { color: 'green', label: '人工维护说明' },
  BUILTIN: { color: 'blue', label: '内置中文规则库' },
  PARSED: { color: 'cyan', label: '规则文件自动解析' },
  AUTO: { color: 'default', label: '元数据自动生成' },
}

const PHASE_SHORT_ZH: Record<number, string> = {
  1: '阶段 1（请求头检查）',
  2: '阶段 2（请求体与参数检查）',
  3: '阶段 3（响应头检查）',
  4: '阶段 4（响应体检查）',
  5: '阶段 5（日志与关联分析）',
}

const PHASE_DETAIL_ZH: Record<number, string> = {
  1: '阶段 1（请求头检查）：在接收完整 HTTP 请求头后执行，可在读取请求体前及早判定',
  2: '阶段 2（请求体与参数检查）：在解析查询参数、表单、JSON/XML 及上传文件后执行',
  3: '阶段 3（响应头检查）：在接收源站返回响应头后执行',
  4: '阶段 4（响应体检查）：在接收源站响应正文后执行，用于识别敏感报错、源码泄露与 WebShell 回显',
  5: '阶段 5（日志与关联分析）：在响应完成后执行异常评分汇总与审计关联，不阻断流量',
}

const SEVERITY_SCORE_MAP: Record<string, number> = {
  CRITICAL: 5,
  ERROR: 4,
  WARNING: 3,
  NOTICE: 2,
}

const TAG_TOOLTIPS_ZH: Record<string, string> = {
  OWASP_CRS: '属于 OWASP 核心规则集（CRS）',
  CUSTOM_PACK: '属于九章扩展安全规则包',
  'jiuzhang-custom': '属于九章内置规则',
  'application-multi': '适用于多种 Web 应用',
  'language-multi': '适用于多种后端开发语言',
  'platform-multi': '适用于多种操作系统与运行平台',
  'attack-sqli': '攻击分类：SQL 注入',
  'attack-xss': '攻击分类：跨站脚本（XSS）',
  'attack-rce': '攻击分类：远程命令/代码执行（RCE）',
  'attack-lfi': '攻击分类：本地文件包含（LFI）',
  'attack-rfi': '攻击分类：远程文件包含（RFI）',
  'attack-php': '攻击分类：PHP 注入攻击',
  'attack-java': '攻击分类：Java 攻击与反序列化',
  'attack-protocol': '攻击分类：HTTP 协议违规与走私',
  'attack-fixation': '攻击分类：会话固定攻击',
  'attack-scanner': '攻击分类：扫描器与爬虫探测',
  'attack-reputation-scanner': '攻击分类：已知安全扫描器特征',
  'attack-disclosure': '攻击分类：敏感信息与报错泄露',
  'attack-injection-generic': '攻击分类：通用代码注入攻击',
  'attack-generic': '攻击分类：通用 Web 安全防护',
  'attack-ssrf': '攻击分类：服务端请求伪造（SSRF）',
  'attack-xxe': '攻击分类：XML 外部实体注入（XXE）',
  'attack-dos': '攻击分类：应用层拒绝服务（DoS）',
  'attack-mass-assignment': '攻击分类：批量赋值与越权提权',
  'attack-deserialization': '攻击分类：不安全反序列化',
  'attack-ssti': '攻击分类：服务端模板注入（SSTI）',
  'attack-upload': '攻击分类：恶意文件上传',
  'attack-multipart-header': '攻击分类：Multipart 请求头异常',
  'crawler-ua': '观测标记：常见爬虫 User-Agent 指纹',
  'ai-crawler': '观测标记：AI 大模型抓取爬虫',
  'anomaly-evaluation': '异常评分汇总与阻断评估规则',
  'paranoia-level/1': '偏执级别 PL1（默认启用，低误报基线）',
  'paranoia-level/2': '偏执级别 PL2（增强防护，偏执级别 ≥ 2 生效）',
  'paranoia-level/3': '偏执级别 PL3（严格防护，偏执级别 ≥ 3 生效）',
  'paranoia-level/4': '偏执级别 PL4（极严防护，偏执级别 = 4 生效）',
}

/** 格式化规则执行阶段为简洁中文标签 */
export function formatRulePhaseZh(phase?: number): string {
  if (!phase) return '-'
  return PHASE_SHORT_ZH[phase] ?? `阶段 ${phase}`
}

/** 返回规则标签的中文悬停提示 */
export function ruleTagTooltipZh(tag: string): string {
  const exact = TAG_TOOLTIPS_ZH[tag]
  if (exact) return exact
  const low = tag.toLowerCase()
  if (low.startsWith('cve/')) return `关联公开漏洞编号：${tag.slice(4).toUpperCase()}`
  if (low.startsWith('cnnvd/')) return `关联 CNNVD 编号：${tag.slice(6).toUpperCase()}`
  if (low.startsWith('capec/')) {
    const code = tag.split('/').pop() ?? ''
    return `CAPEC-${code} 常见攻击模式分类编号`
  }
  if (low.startsWith('webshell/')) return '攻击分类：WebShell 后门木马检测'
  if (low.startsWith('bot-claim/')) return `观测标记：声明为 ${tag.slice(10)} 搜索引擎爬虫`
  if (tag.startsWith('OWASP_CRS/')) return `OWASP CRS 子分类：${tag.slice('OWASP_CRS/'.length)}`
  if (low.startsWith('language-')) return `适用开发语言：${tag.slice('language-'.length)}`
  if (low.startsWith('platform-')) return `适用运行平台：${tag.slice('platform-'.length)}`
  if (low.startsWith('application-')) return `适用应用类型：${tag.slice('application-'.length)}`
  return `规则分类标签：${tag}`
}

/**
 * 解析规则的结构化中文详细说明：
 * 优先使用后端返回的 detail 对象；若接口未返回（如旧版响应或精简测试桩），
 * 在前端根据规则元数据生成完整中文兜底说明，确保详情抽屉始终有清晰中文解释。
 */
export function resolveWafRuleDetail(rule: WafRuleItem): WafRuleDetailInfo {
  if (rule.detail && rule.detail.summary) {
    return {
      ...rule.detail,
      source: rule.detail.source ?? (rule.detail.customized ? 'CUSTOM' : 'BUILTIN'),
      source_label:
        rule.detail.source_label ??
        WAF_RULE_DETAIL_SOURCE_META[rule.detail.source ?? 'BUILTIN']?.label ??
        '内置中文规则库',
      customized: Boolean(rule.detail.customized),
      targets: rule.detail.targets ?? [],
      references: rule.detail.references ?? [],
    }
  }

  const zhName = ruleNameZh(rule) || `规则 ${rule.rule_id}`
  const tags = parseWafRuleTags(rule.tags)
  const srcLabel = RULE_SOURCE_META[rule.rule_source]?.label ?? 'WAF 防护规则库'
  const attackLabel = ATTACK_TYPE_META[rule.attack_type]?.label ?? '通用安全防护'
  const sevLabel = RULE_SEVERITY_META[rule.severity]?.label ?? '低'
  const sevScore = SEVERITY_SCORE_MAP[rule.severity] ?? 2
  const familyKey = (rule.file_name ?? '').replace(/\.conf$/i, '')
  const familyName = CRS_FAMILY_NAMES_ZH[familyKey]

  const isInternal = zhName.includes('内部规则')
  const isExclusion = rule.rule_source === 'THIRD_PARTY' || rule.attack_type === 'EXCLUSION'
  const isBlockingEval = [949110, 949111, 959100, 959101, 9000102, 9000104].includes(rule.rule_id)

  const ruleType = isInternal
    ? 'INTERNAL'
    : isExclusion
      ? 'EXCLUSION'
      : isBlockingEval
        ? 'BLOCKING_EVALUATION'
        : 'DETECTION'
  const ruleTypeLabel = WAF_RULE_TYPE_META[ruleType]?.label ?? '安全检测规则'

  const plTag = tags.find((t) => t.startsWith('paranoia-level/'))
  const plNum = plTag ? Number(plTag.split('/')[1]) : 0
  const paranoiaLevel =
    plNum === 1
      ? 'PL1（默认启用，低误报基线防护）'
      : plNum === 2
        ? 'PL2（增强防护，策略偏执级别 ≥ 2 时生效）'
        : plNum === 3
          ? 'PL3（严格防护，策略偏执级别 ≥ 3 时生效）'
          : plNum === 4
            ? 'PL4（极严防护，策略偏执级别 = 4 时生效，误报风险较高）'
            : isInternal
              ? '无条件执行（引擎内部流程控制）'
              : '默认基线生效'

  const summary =
    rule.description ||
    (isInternal
      ? `属于${srcLabel}${familyName ? `「${familyName}」规则族` : ''}的引擎内部流程控制规则，用于按策略偏执级别控制后续检测规则是否执行，不直接检测攻击载荷也不阻断正常流量。`
      : isExclusion
        ? `属于${srcLabel}的误报排除规则（${zhName}），用于在对应应用正常业务路径与字段上移除易误报检测规则。`
        : `属于${srcLabel}${familyName ? `「${familyName}」规则族` : ''}的「${attackLabel}」检测规则，专门识别并防范「${zhName}」相关的攻击载荷与异常请求特征。`)

  const detectionLogic = isInternal
    ? `在${formatRulePhaseZh(rule.phase)}校验引擎内部策略变量，按配置决定是否跳过后续规则段，不记录业务告警日志。`
    : `在${formatRulePhaseZh(rule.phase)}围绕「${attackLabel}」特征检查请求或响应数据；命中后按${sevLabel}风险级别参与异常评分或拦截判定。`

  const riskImpact = isInternal
    ? '属于 WAF 引擎内部流程控制规则，不直接识别恶意载荷也不拦截流量，用于确保策略偏执级别分级与评分机制准确执行。'
    : isExclusion
      ? '该规则仅在特定应用场景下放行已知误报，不直接阻断业务请求，同时保留对其余参数与路径的正常防护。'
      : `防范「${attackLabel}」类安全威胁导致的数据泄露、权限绕过或服务异常，降低应用暴露面与被利用风险。`

  const tuningAdvice = isInternal
    ? '此类内部控制规则不会产生业务误报，通常不应手动停用；如需调整检测严格度，请直接修改防护策略的偏执级别或异常评分阈值。'
    : '如正常业务请求触发误拦截，请先在安全事件详情中核实命中参数与上下文，优先通过精细化例外策略按路径或参数放行，避免整站关闭检测规则。'

  const actionBehavior = isInternal
    ? '内部流程控制（不阻断、不记录日志）'
    : isExclusion
      ? '动态规则放行（降低误报，不阻断请求）'
      : `异常评分（${sevLabel}级别 +${sevScore} 分；累计达到策略阈值后在防护模式阻断，观察模式仅记录）`

  const references: string[] = []
  for (const t of tags) {
    if (t.toLowerCase().startsWith('cve/')) {
      references.push(`漏洞编号：${t.slice(4).toUpperCase()}`)
    } else if (t.toLowerCase().startsWith('capec/')) {
      references.push(`CAPEC-${t.split('/').pop() ?? ''} 攻击模式`)
    }
  }
  if (familyName) {
    references.push(`${srcLabel}${rule.crs_version ? ` ${rule.crs_version}` : ''} · ${familyName}规则族`)
  }

  return {
    rule_type: ruleType,
    rule_type_label: ruleTypeLabel,
    source: 'AUTO',
    source_label: '元数据自动生成',
    customized: false,
    summary,
    detection_logic: detectionLogic,
    risk_impact: riskImpact,
    tuning_advice: tuningAdvice,
    phase_description: PHASE_DETAIL_ZH[rule.phase] ?? formatRulePhaseZh(rule.phase),
    paranoia_level: paranoiaLevel,
    action_behavior: actionBehavior,
    targets: [],
    references,
  }
}
