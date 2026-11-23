import { describe, expect, it } from 'vitest'
import { CRS_FAMILY_NAMES_ZH, CRS_RULE_NAMES_ZH, ruleMessageZh, ruleNameZh } from '../crsRuleNames'

describe('CRS_RULE_NAMES_ZH 逐条映射', () => {
  it('覆盖内置 CRS 4.28.0 全部 622 条规则', () => {
    expect(Object.keys(CRS_RULE_NAMES_ZH)).toHaveLength(622)
  })

  it('代表性规则中文名与英文 msg 语义一致', () => {
    // SQL Injection Attack Detected via libinjection
    expect(CRS_RULE_NAMES_ZH[942100]).toBe('通过 libinjection 检测到 SQL 注入攻击')
    // XSS Attack Detected via libinjection
    expect(CRS_RULE_NAMES_ZH[941100]).toBe('通过 libinjection 检测到 XSS 攻击')
    // Remote Command Execution: Unix Shell Expression Found
    expect(CRS_RULE_NAMES_ZH[932130]).toBe('远程命令执行：Unix Shell 表达式')
    // Path Traversal Attack (/../) or (/.../)
    expect(CRS_RULE_NAMES_ZH[930100]).toBe('路径遍历攻击（/../ 或 /.../）')
    // POST without Content-Length and Transfer-Encoding headers
    expect(CRS_RULE_NAMES_ZH[920180]).toBe('POST 请求缺少 Content-Length 与 Transfer-Encoding')
    // Found User-Agent associated with security scanner
    expect(CRS_RULE_NAMES_ZH[913100]).toBe('发现安全扫描器关联的 User-Agent')
    // Inbound Anomaly Score Exceeded
    expect(CRS_RULE_NAMES_ZH[949110]).toBe('入站异常评分超限')
    // Method is not allowed by policy
    expect(CRS_RULE_NAMES_ZH[911100]).toBe('请求方法不被策略允许')
    // HTTP Request Smuggling Attack
    expect(CRS_RULE_NAMES_ZH[921110]).toBe('HTTP 请求走私攻击')
    // Invalid HTTP Request Line
    expect(CRS_RULE_NAMES_ZH[920100]).toBe('非法的 HTTP 请求行')
    // Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address
    expect(CRS_RULE_NAMES_ZH[931100]).toBe('疑似 RFI 攻击：URL 参数使用 IP 地址')
    // PHP Injection Attack: PHP Open Tag Found
    expect(CRS_RULE_NAMES_ZH[933100]).toBe('PHP 注入攻击：发现 PHP 开始标签')
    // Possible Session Fixation Attack: Setting Cookie Values in HTML
    expect(CRS_RULE_NAMES_ZH[943100]).toBe('疑似会话固定攻击：在 HTML 中设置 Cookie')
    // Potential Remote Command Execution: Log4j / Log4shell
    expect(CRS_RULE_NAMES_ZH[944150]).toBe('潜在远程命令执行：Log4j / Log4shell')
    // XSS Filter - Category 1: Script Tag Vector
    expect(CRS_RULE_NAMES_ZH[941110]).toBe('XSS 过滤 - 类别 1：Script 标签向量')
    // mysql SQL Information Leakage
    expect(CRS_RULE_NAMES_ZH[951230]).toBe('MySQL SQL 信息泄露')
    // Outbound Anomaly Score Exceeded
    expect(CRS_RULE_NAMES_ZH[959100]).toBe('出站异常评分超限')
    // PHP Web shell detected
    expect(CRS_RULE_NAMES_ZH[955100]).toBe('检测到 PHP Web Shell')
  })

  it('msg 为空的内部规则使用「族名 + 内部规则」命名', () => {
    expect(CRS_RULE_NAMES_ZH[920011]).toBe('协议合规校验内部规则')
    expect(CRS_RULE_NAMES_ZH[980050]).toBe('关联评分内部规则')
  })
})

describe('CRS_FAMILY_NAMES_ZH 规则族映射', () => {
  it('覆盖 tsv 中出现的全部 26 个规则族', () => {
    expect(Object.keys(CRS_FAMILY_NAMES_ZH)).toHaveLength(26)
    expect(CRS_FAMILY_NAMES_ZH['REQUEST-942-APPLICATION-ATTACK-SQLI']).toBe('SQL 注入')
    expect(CRS_FAMILY_NAMES_ZH['RESPONSE-955-WEB-SHELLS']).toBe('Web Shell 检测')
  })
})

describe('ruleNameZh 解析优先级', () => {
  it('优先返回逐条映射的中文名', () => {
    expect(
      ruleNameZh({
        rule_id: 942100,
        file_name: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
        name: 'SQL Injection Attack Detected via libinjection',
      }),
    ).toBe('通过 libinjection 检测到 SQL 注入攻击')
  })

  it('不在逐条映射时回退为「族名 + 检测规则」', () => {
    expect(
      ruleNameZh({
        rule_id: 942999,
        file_name: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
        name: 'some english message',
      }),
    ).toBe('SQL 注入检测规则')
  })

  it('族名未知时回退为英文 name', () => {
    expect(ruleNameZh({ rule_id: 999999, file_name: 'CUSTOM-RULES.conf', name: 'My custom rule' })).toBe(
      'My custom rule',
    )
  })

  it('无任何可用信息时返回空串', () => {
    expect(ruleNameZh({ rule_id: 999999 })).toBe('')
    expect(ruleNameZh({ rule_id: 999999, file_name: '', name: '' })).toBe('')
  })

  it('支持模板型扩展规则中文化（爬虫/AI爬虫/搜索引擎声明）', () => {
    expect(ruleNameZh({ rule_id: 1002999, name: 'Scanner fingerprint: crawler UA (zgrab)' })).toBe(
      '扫描器指纹：爬虫 UA（zgrab）',
    )
    expect(ruleNameZh({ rule_id: 1010062, name: 'AI crawler UA: GPTBot' })).toBe('AI 爬虫 UA：GPTBot')
    expect(ruleNameZh({ rule_id: 1010201, name: 'Search engine bot UA claim: Googlebot' })).toBe(
      '搜索引擎爬虫 UA 声明：Googlebot',
    )
  })
})

describe('ruleMessageZh 事件匹配消息中文化', () => {
  it('将英文 CRS 命中消息与动态异常评分转为中文', () => {
    expect(
      ruleMessageZh({
        rule_id: 943120,
        message: 'Possible Session Fixation Attack: SessionID Parameter Name with No Referer',
      }),
    ).toBe('疑似会话固定攻击：SessionID 参数无 Referer')

    expect(
      ruleMessageZh({
        rule_id: 949110,
        message: 'Inbound Anomaly Score Exceeded (Total Score: 5)',
      }),
    ).toBe('入站异常评分超限（总分：5）')

    expect(
      ruleMessageZh({
        rule_id: 949111,
        message: 'Inbound Anomaly Score Exceeded in phase 1 (Total Score: 8)',
      }),
    ).toBe('入站异常评分超限（阶段 1，总分：8）')
  })

  it('已有中文的自定义规则消息保持原样', () => {
    expect(
      ruleMessageZh({
        rule_id: 7100001,
        rule_name: 'Struts2 RCE 虚拟补丁',
        message: '命中虚拟补丁',
      }),
    ).toBe('命中虚拟补丁')
  })
})
