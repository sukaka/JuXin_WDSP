import { describe, expect, it } from 'vitest'
import type { ApiSpecAudit, ApiSpecAuditItem } from '../../../api/apiSecurity'
import { specAuditCSV } from '../specAuditExport'

const header =
  '"规范 ID","规范格式","操作数","问题数","高危问题","中危问题","是否截断","规则","严重级别","接口键","参数位置","参数名称","说明"\r\n'

function makeItem(overrides: Partial<ApiSpecAuditItem> = {}): ApiSpecAuditItem {
  return {
    rule_id: 'PATH_PARAMETER_MISSING',
    severity: 'HIGH',
    endpoint_key: 'GET /v1/users/{user_id}',
    param_in: 'path',
    param_name: 'user_id',
    message: '路径参数 user_id 缺少定义',
    ...overrides,
  }
}

function makeAudit(overrides: Partial<ApiSpecAudit> = {}): ApiSpecAudit {
  return {
    spec_id: 'spec-001',
    format: 'openapi3',
    operation_count: 8,
    issue_count: 1,
    high_count: 1,
    medium_count: 0,
    items: [makeItem()],
    truncated: false,
    ...overrides,
  }
}

describe('specAuditCSV', () => {
  it('输出 UTF-8 BOM、中文表头与中文化枚举/布尔明细', () => {
    const csv = specAuditCSV(makeAudit())

    expect(csv).toBe(
      `\uFEFF${header}` +
        '"spec-001","OpenAPI 3.x","8","1","1","0","否","路径参数缺失","高","GET /v1/users/{user_id}","路径参数","user_id","路径参数 user_id 缺少定义"\r\n',
    )
    expect(csv.charCodeAt(0)).toBe(0xfeff)
  })

  it('将所有已收录规则、严重级别、参数位置与规范格式映射为官方中文，未知值原样兜底', () => {
    const csv = specAuditCSV(
      makeAudit({
        format: 'graphql',
        operation_count: 10,
        issue_count: 9,
        high_count: 5,
        medium_count: 4,
        items: [
          makeItem({
            rule_id: 'PATH_PARAMETER_MISSING',
            severity: 'HIGH',
            param_in: 'path',
          }),
          makeItem({
            rule_id: 'PATH_PARAMETER_NOT_REQUIRED',
            severity: 'MEDIUM',
            param_in: 'query',
          }),
          makeItem({
            rule_id: 'PATH_PARAMETER_UNDECLARED',
            severity: 'HIGH',
            param_in: 'header',
          }),
          makeItem({
            rule_id: 'SENSITIVE_QUERY_PARAMETER',
            severity: 'MEDIUM',
            param_in: 'cookie',
          }),
          makeItem({
            rule_id: 'SUCCESS_RESPONSE_MISSING',
            severity: 'HIGH',
            param_in: '',
            param_name: '',
          }),
          makeItem({
            rule_id: 'ERROR_RESPONSE_MISSING',
            severity: 'MEDIUM',
            param_in: 'body',
          }),
          makeItem({
            rule_id: 'SECURITY_SCHEME_UNDEFINED',
            severity: 'HIGH',
            param_in: 'SECURITY',
            param_name: 'bearerAuth',
          }),
          makeItem({
            rule_id: 'API_KEY_IN_QUERY',
            severity: 'HIGH',
            param_in: 'security',
            param_name: 'api_key',
          }),
          makeItem({
            rule_id: 'CUSTOM_FUTURE_RULE' as ApiSpecAuditItem['rule_id'],
            severity: 'LOW' as ApiSpecAuditItem['severity'],
            param_in: 'custom_loc',
            param_name: 'extra',
          }),
        ],
      }),
    )

    expect(csv).toContain('"GraphQL SDL","10","9","5","4","否","路径参数缺失","高","GET /v1/users/{user_id}","路径参数"')
    expect(csv).toContain('"路径参数未标记必填","中","GET /v1/users/{user_id}","查询参数"')
    expect(csv).toContain('"路径参数未声明","高","GET /v1/users/{user_id}","请求头"')
    expect(csv).toContain('"敏感查询参数","中","GET /v1/users/{user_id}","Cookie"')
    expect(csv).toContain('"成功响应未声明","高","GET /v1/users/{user_id}","",""')
    expect(csv).toContain('"错误响应未声明","中","GET /v1/users/{user_id}","请求体"')
    expect(csv).toContain('"认证方案未定义","高","GET /v1/users/{user_id}","认证方案","bearerAuth"')
    expect(csv).toContain('"查询参数传递 API Key","高","GET /v1/users/{user_id}","认证方案","api_key"')
    // 未收录枚举值原样兜底，不丢失数据
    expect(csv).toContain('"CUSTOM_FUTURE_RULE","LOW","GET /v1/users/{user_id}","custom_loc","extra"')
  })

  it('按标准 CSV 规则保留并转义逗号、双引号和 CRLF', () => {
    const csv = specAuditCSV(
      makeAudit({
        spec_id: 'spec,"一"\r\n源',
        format: 'openapi,3.0',
        items: [
          makeItem({
            endpoint_key: 'GET /v1/orders,{id}',
            param_in: 'query',
            param_name: 'order"id',
            message: '中文第一行,"原始说明"\r\n第二行',
          }),
        ],
      }),
    )

    expect(csv).toBe(
      `\uFEFF${header}` +
        '"spec,""一""\r\n源","openapi,3.0","8","1","1","0","否","路径参数缺失","高","GET /v1/orders,{id}","查询参数","order""id","中文第一行,""原始说明""\r\n第二行"\r\n',
    )
  })

  it.each([
    '=1+1',
    '+SUM(1,1)',
    '-2+3',
    '@SUM(1,1)',
    '\t1+1',
    '\r1+1',
    '\n1+1',
  ])('为以危险字符开头的单元格前置单引号且保留原文：%j', (value) => {
    const csv = specAuditCSV(
      makeAudit({ items: [makeItem({ message: value })] }),
    )

    expect(csv.endsWith(`,"'${value}"\r\n`)).toBe(true)
  })

  it('对汇总与明细的所有文本列采用相同防公式注入策略', () => {
    const csv = specAuditCSV(
      makeAudit({
        spec_id: '=spec-001',
        format: '+openapi3',
        items: [
          makeItem({
            rule_id: '=UNKNOWN_RULE' as ApiSpecAuditItem['rule_id'],
            severity: '+UNKNOWN_SEV' as ApiSpecAuditItem['severity'],
            endpoint_key: '-GET /v1/users',
            param_in: '@path',
            param_name: '\tuser_id',
            message: '\r原始说明',
          }),
        ],
      }),
    )

    expect(csv).toContain(
      '"\'=spec-001","\'+openapi3","8","1","1","0","否","\'=UNKNOWN_RULE","\'+UNKNOWN_SEV","\'-GET /v1/users","\'@path","\'\tuser_id","\'\r原始说明"',
    )
  })

  it('空明细仍保留中文表头和汇总，不生成伪造问题项', () => {
    const csv = specAuditCSV(
      makeAudit({
        spec_id: 'empty-spec',
        operation_count: 3,
        issue_count: 0,
        high_count: 0,
        medium_count: 0,
        items: [],
      }),
    )

    expect(csv).toBe(
      `\uFEFF${header}` +
        '"empty-spec","OpenAPI 3.x","3","0","0","0","否"' +
        ',""'.repeat(6) +
        '\r\n',
    )
    expect(csv).not.toContain('路径参数缺失')
  })

  it('保留截断标记（是）和汇总总数，只导出实际返回的明细', () => {
    const csv = specAuditCSV(
      makeAudit({
        operation_count: 700,
        issue_count: 650,
        high_count: 400,
        medium_count: 250,
        truncated: true,
      }),
    )

    expect(csv).toBe(
      `\uFEFF${header}` +
        '"spec-001","OpenAPI 3.x","700","650","400","250","是","路径参数缺失","高","GET /v1/users/{user_id}","路径参数","user_id","路径参数 user_id 缺少定义"\r\n',
    )
    expect(csv.match(/路径参数缺失/g)).toHaveLength(1)
  })
})
