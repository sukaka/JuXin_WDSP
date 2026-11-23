import { describe, expect, it } from 'vitest'
import {
  L7_DEFAULT_CONTENT_TYPE,
  L7_MAX_BODY_BYTES,
  actionConfigToFormValues,
  buildActionConfig,
  conditionToRow,
  previewL7RedirectUrl,
  rowToCondition,
  summarizeConditions,
  utf8ByteLength,
  validateConditionRow,
  validateL7HostValue,
  validateL7RedirectUrl,
  validateL7Regex,
  type L7ConditionFormRow,
} from '../l7rules'
import type { L7RuleCondition } from '../../types'

describe('rowToCondition（表单行 → 契约 JSON）', () => {
  it('uri 条件：仅 type+op+value，无 name', () => {
    const row: L7ConditionFormRow = { type: 'uri', op: 'prefix', value: '/admin' }
    expect(rowToCondition(row)).toEqual({ type: 'uri', op: 'prefix', value: '/admin' })
  })

  it('host 条件：非正则去空白并小写归一（含尾点），无 name', () => {
    expect(rowToCondition({ type: 'host', op: 'eq', value: ' JXDR.CN. ' })).toEqual({
      type: 'host',
      op: 'eq',
      value: 'jxdr.cn',
    })
    expect(rowToCondition({ type: 'host', op: 'regex', value: '^(www\\.)?JXDR\\.CN$' })).toEqual({
      type: 'host',
      op: 'regex',
      value: '^(www\\.)?JXDR\\.CN$',
    })
  })

  it('method/client_ip 条件：仅 type+values，不带 op', () => {
    expect(rowToCondition({ type: 'method', values: ['GET', 'POST'] })).toEqual({
      type: 'method',
      values: ['GET', 'POST'],
    })
    expect(rowToCondition({ type: 'client_ip', values: ['10.0.0.0/8', '192.168.1.5'] })).toEqual({
      type: 'client_ip',
      values: ['10.0.0.0/8', '192.168.1.5'],
    })
  })

  it('header/cookie/query 条件：携带 name', () => {
    expect(rowToCondition({ type: 'header', name: 'X-Env', op: 'eq', value: 'prod' })).toEqual({
      type: 'header',
      name: 'X-Env',
      op: 'eq',
      value: 'prod',
    })
    expect(rowToCondition({ type: 'query', name: 'debug', op: 'ne', value: '1' })).toEqual({
      type: 'query',
      name: 'debug',
      op: 'ne',
      value: '1',
    })
  })

  it('exists/not_exists 不带 value', () => {
    expect(rowToCondition({ type: 'cookie', name: 'session', op: 'exists' })).toEqual({
      type: 'cookie',
      name: 'session',
      op: 'exists',
    })
    expect(
      rowToCondition({ type: 'header', name: 'X-Debug', op: 'not_exists', value: '残留值' }),
    ).toEqual({ type: 'header', name: 'X-Debug', op: 'not_exists' })
  })

  it('op 缺省按 eq 序列化', () => {
    expect(rowToCondition({ type: 'uri', value: '/a' })).toEqual({ type: 'uri', op: 'eq', value: '/a' })
  })
})

describe('conditionToRow（契约 JSON → 表单行，编辑回显）', () => {
  it('与 rowToCondition 往返一致', () => {
    const cases: L7RuleCondition[] = [
      { type: 'uri', op: 'prefix', value: '/admin' },
      { type: 'host', op: 'eq', value: 'jxdr.cn' },
      { type: 'method', values: ['GET', 'POST'] },
      { type: 'header', name: 'X-Env', op: 'eq', value: 'prod' },
      { type: 'cookie', name: 'session', op: 'exists' },
      { type: 'query', name: 'debug', op: 'ne', value: '1' },
      { type: 'client_ip', values: ['10.0.0.0/8', '192.168.1.5'] },
      { type: 'request_body', op: 'contains', value: 'request-secret' },
      { type: 'response_header', name: 'X-Result', op: 'eq', value: 'ready' },
      { type: 'response_body', op: 'contains', value: 'response-secret' },
    ]
    for (const cond of cases) {
      expect(rowToCondition(conditionToRow(cond))).toEqual(cond)
    }
  })

  it('values 数组回显为副本（不共享引用）', () => {
    const cond: L7RuleCondition = { type: 'method', values: ['GET'] }
    const row = conditionToRow(cond)
    row.values?.push('POST')
    expect(cond.values).toEqual(['GET'])
  })
})

describe('buildActionConfig（动作配置序列化，全键输出）', () => {
  it('block：取 status+message', () => {
    expect(buildActionConfig({ action: 'block', block_status: 451, block_message: '禁止访问' })).toEqual({
      status: 451,
      message: '禁止访问',
      redirect_url: '',
      redirect_status: 302,
      content_type: L7_DEFAULT_CONTENT_TYPE,
      body: '',
    })
  })

  it('block 状态码缺省 403', () => {
    expect(buildActionConfig({ action: 'block' }).status).toBe(403)
  })

  it('allow：全部默认值', () => {
    expect(buildActionConfig({ action: 'allow' })).toEqual({
      status: 403,
      message: '',
      redirect_url: '',
      redirect_status: 302,
      content_type: L7_DEFAULT_CONTENT_TYPE,
      body: '',
    })
  })

  it('redirect：取 redirect_url+redirect_status，开启保留路径和查询参数时输出 preserve_path_query', () => {
    const cfg = buildActionConfig({
      action: 'redirect',
      redirect_url: ' https://www.jxdr.cn ',
      redirect_status: 301,
      redirect_preserve_path_query: true,
    })
    expect(cfg.redirect_url).toBe('https://www.jxdr.cn')
    expect(cfg.redirect_status).toBe(301)
    expect(cfg.preserve_path_query).toBe(true)
    expect(cfg.status).toBe(403)

    const back = actionConfigToFormValues('redirect', cfg)
    expect(back.redirect_preserve_path_query).toBe(true)
    expect(buildActionConfig(back)).toEqual(cfg)

    // 未勾选时保持六键零漂移
    const plain = buildActionConfig({
      action: 'redirect',
      redirect_url: 'https://www.jxdr.cn',
      redirect_status: 301,
      redirect_preserve_path_query: false,
    })
    expect('preserve_path_query' in plain).toBe(false)
  })

  it('custom_page：取 status+content_type+body', () => {
    const cfg = buildActionConfig({
      action: 'custom_page',
      custom_status: 200,
      custom_content_type: 'text/plain',
      custom_body: 'hello',
    })
    expect(cfg.status).toBe(200)
    expect(cfg.content_type).toBe('text/plain')
    expect(cfg.body).toBe('hello')
  })

  it('与 actionConfigToFormValues 往返一致', () => {
    const cfg = buildActionConfig({
      action: 'custom_page',
      custom_status: 403,
      custom_content_type: 'text/html; charset=utf-8',
      custom_body: '<h1>deny</h1>',
    })
    const formValues = actionConfigToFormValues('custom_page', cfg)
    expect(buildActionConfig(formValues)).toEqual(cfg)
  })
})

describe('validateConditionRow（提交前逐行校验）', () => {
  it('method 取值须为大写字母方法', () => {
    expect(validateConditionRow({ type: 'method', values: ['GET'] })).toBeNull()
    expect(validateConditionRow({ type: 'method', values: ['get'] })).not.toBeNull()
    expect(validateConditionRow({ type: 'method', values: [] })).not.toBeNull()
  })

  it('client_ip 取值复用严格 IP/CIDR 校验', () => {
    expect(validateConditionRow({ type: 'client_ip', values: ['10.0.0.0/8', '::1'] })).toBeNull()
    expect(validateConditionRow({ type: 'client_ip', values: ['example.com'] })).not.toBeNull()
    expect(validateConditionRow({ type: 'client_ip', values: ['10.0.0.0/33'] })).not.toBeNull()
  })

  it('命名类型必须填名称', () => {
    expect(validateConditionRow({ type: 'header', name: '', op: 'eq', value: 'a' })).not.toBeNull()
    expect(validateConditionRow({ type: 'header', name: 'X-A', op: 'eq', value: 'a' })).toBeNull()
    expect(validateConditionRow({ type: 'response_header', name: 'X-Result', op: 'contains', value: 'secret' })).toBeNull()
    expect(validateConditionRow({ type: 'response_header', name: '', op: 'contains', value: 'secret' })).not.toBeNull()
  })

  it('请求体和返回体默认支持关键字包含，不支持存在性运算', () => {
    expect(validateConditionRow({ type: 'request_body', op: 'contains', value: 'secret' })).toBeNull()
    expect(validateConditionRow({ type: 'response_body', op: 'contains', value: 'secret' })).toBeNull()
    expect(validateConditionRow({ type: 'request_body', op: 'exists' })).not.toBeNull()
    expect(validateConditionRow({ type: 'response_body', op: 'contains', value: '' })).not.toBeNull()
  })

  it('exists/not_exists 不需要匹配值', () => {
    expect(validateConditionRow({ type: 'cookie', name: 's', op: 'exists' })).toBeNull()
    expect(validateConditionRow({ type: 'cookie', name: 's', op: 'not_exists' })).toBeNull()
  })

  it('uri 非正则（含 eq/ne/prefix/contains）须以 / 开头，regex 不强制', () => {
    expect(validateConditionRow({ type: 'uri', op: 'prefix', value: 'admin' })).not.toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'prefix', value: '/admin' })).toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'eq', value: 'admin' })).not.toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'ne', value: 'admin' })).not.toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'contains', value: 'admin' })).not.toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'contains', value: '/admin' })).toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'regex', value: 'admin$' })).toBeNull()
  })

  it('host 条件校验：允许域名/IPv6/正则，拒绝协议/路径/空白/显式端口', () => {
    expect(validateConditionRow({ type: 'host', op: 'eq', value: 'jxdr.cn' })).toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'eq', value: 'JXDR.CN' })).toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'eq', value: '[::1]' })).toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'regex', value: '^(www\\.)?jxdr\\.cn$' })).toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'eq', value: 'jxdr.cn:443' })).not.toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'eq', value: 'https://jxdr.cn' })).not.toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'eq', value: 'jxdr.cn/news' })).not.toBeNull()
    expect(validateConditionRow({ type: 'host', op: 'exists' })).not.toBeNull()
    expect(validateL7HostValue('eq', 'jxdr.cn evil')).not.toBeNull()
  })

  it('regex 须可编译', () => {
    expect(validateConditionRow({ type: 'uri', op: 'regex', value: '^/a+$' })).toBeNull()
    expect(validateConditionRow({ type: 'uri', op: 'regex', value: '([' })).not.toBeNull()
  })

  it('运算符不适用于类型时拒绝', () => {
    expect(validateConditionRow({ type: 'uri', op: 'exists' })).not.toBeNull()
  })
})

describe('validateL7Regex / validateL7RedirectUrl / utf8ByteLength', () => {
  it('正则长度上限 512', () => {
    expect(validateL7Regex('a'.repeat(512))).toBeNull()
    expect(validateL7Regex('a'.repeat(513))).not.toBeNull()
  })

  it('重定向 URL 仅允许 http/https', () => {
    expect(validateL7RedirectUrl('https://example.com/x')).toBeNull()
    expect(validateL7RedirectUrl('http://example.com')).toBeNull()
    expect(validateL7RedirectUrl('ftp://example.com')).not.toBeNull()
    expect(validateL7RedirectUrl('javascript:alert(1)')).not.toBeNull()
    expect(validateL7RedirectUrl('//example.com')).not.toBeNull()
    expect(validateL7RedirectUrl('not-a-url')).not.toBeNull()
    expect(validateL7RedirectUrl('')).not.toBeNull()
  })

  it('字节数按 UTF-8 计', () => {
    expect(utf8ByteLength('abc')).toBe(3)
    expect(utf8ByteLength('中文')).toBe(6)
    expect(utf8ByteLength('x'.repeat(L7_MAX_BODY_BYTES))).toBe(L7_MAX_BODY_BYTES)
  })

  it('previewL7RedirectUrl 预览保留路径和查询参数拼接结果', () => {
    expect(previewL7RedirectUrl('https://www.jxdr.cn', true, '/news?id=1')).toBe('https://www.jxdr.cn/news?id=1')
    expect(previewL7RedirectUrl('https://www.jxdr.cn/', true, '/news?id=1')).toBe('https://www.jxdr.cn/news?id=1')
    expect(previewL7RedirectUrl('https://www.jxdr.cn/v2', true, '/news?id=1')).toBe('https://www.jxdr.cn/v2/news?id=1')
    expect(previewL7RedirectUrl('https://www.jxdr.cn?from=apex', true, '/news?id=1')).toBe(
      'https://www.jxdr.cn/news?from=apex&id=1',
    )
    expect(previewL7RedirectUrl('https://www.jxdr.cn', false, '/news?id=1')).toBe('https://www.jxdr.cn')
    expect(previewL7RedirectUrl('not-a-url', true, '/news?id=1')).toBeNull()
  })
})

describe('summarizeConditions（条件摘要）', () => {
  it('host 条件摘要展示 请求域名（Host）', () => {
    expect(summarizeConditions([{ type: 'host', op: 'eq', value: 'jxdr.cn' }])).toBe('请求域名（Host） 等于 jxdr.cn')
  })
  it('空条件', () => {
    expect(summarizeConditions([])).toBe('无条件（匹配全部请求）')
  })

  it('多条件 AND 连接，超出折叠', () => {
    const conds: L7RuleCondition[] = [
      { type: 'uri', op: 'prefix', value: '/admin' },
      { type: 'method', values: ['GET', 'POST'] },
      { type: 'client_ip', values: ['10.0.0.0/8'] },
    ]
    expect(summarizeConditions(conds)).toBe(
      '访问URI 前缀匹配 /admin 且 请求方法 ∈ [GET, POST] 等 3 个条件',
    )
    expect(summarizeConditions(conds, 10)).toBe(
      '访问URI 前缀匹配 /admin 且 请求方法 ∈ [GET, POST] 且 来源IP ∈ [10.0.0.0/8]',
    )
  })

  it('未收录的 type/op 回退原值', () => {
    const conds = [{ type: 'future_type', op: 'future_op', value: 'x' } as unknown as L7RuleCondition]
    expect(summarizeConditions(conds)).toBe('future_type future_op x')
  })
})
