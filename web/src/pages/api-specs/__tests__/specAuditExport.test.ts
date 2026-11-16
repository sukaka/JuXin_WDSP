import { describe, expect, it } from 'vitest'
import type { ApiSpecAudit, ApiSpecAuditItem } from '../../../api/apiSecurity'
import { specAuditCSV } from '../specAuditExport'

const header =
  '"spec_id","format","operation_count","issue_count","high_count","medium_count","truncated","rule_id","severity","endpoint_key","param_in","param_name","message"\r\n'

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
  it('输出 UTF-8 BOM、完整汇总和中文真实明细', () => {
    const csv = specAuditCSV(makeAudit())

    expect(csv).toBe(
      `\uFEFF${header}` +
        '"spec-001","openapi3","8","1","1","0","false","PATH_PARAMETER_MISSING","HIGH","GET /v1/users/{user_id}","path","user_id","路径参数 user_id 缺少定义"\r\n',
    )
    expect(csv.charCodeAt(0)).toBe(0xfeff)
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
        '"spec,""一""\r\n源","openapi,3.0","8","1","1","0","false","PATH_PARAMETER_MISSING","HIGH","GET /v1/orders,{id}","query","order""id","中文第一行,""原始说明""\r\n第二行"\r\n',
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
            endpoint_key: '-GET /v1/users',
            param_in: '@path',
            param_name: '\tuser_id',
            message: '\r原始说明',
          }),
        ],
      }),
    )

    expect(csv).toContain(
      '"\'=spec-001","\'+openapi3","8","1","1","0","false","PATH_PARAMETER_MISSING","HIGH","\'-GET /v1/users","\'@path","\'\tuser_id","\'\r原始说明"',
    )
  })

  it('空明细仍保留表头和汇总，不生成伪造问题项', () => {
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
        '"empty-spec","openapi3","3","0","0","0","false"' +
        ',""'.repeat(6) +
        '\r\n',
    )
    expect(csv).not.toContain('PATH_PARAMETER_MISSING')
  })

  it('保留截断标记和汇总总数，只导出实际返回的明细', () => {
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
        '"spec-001","openapi3","700","650","400","250","true","PATH_PARAMETER_MISSING","HIGH","GET /v1/users/{user_id}","path","user_id","路径参数 user_id 缺少定义"\r\n',
    )
    expect(csv.match(/PATH_PARAMETER_MISSING/g)).toHaveLength(1)
  })
})
