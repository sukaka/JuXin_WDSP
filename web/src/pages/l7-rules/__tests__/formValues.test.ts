import { describe, expect, it } from 'vitest'
import { formValuesToBody, ruleToFormValues, type L7RuleFormValues } from '../formValues'
import type { L7RuleItem } from '../../../types'

/** 契约一示例规则（冻结契约中的完整字段形态） */
const CONTRACT_RULE: L7RuleItem = {
  id: 'uuid',
  name: '规则名',
  priority: 100,
  enabled: true,
  conditions: [
    { type: 'uri', op: 'prefix', value: '/admin' },
    { type: 'method', values: ['GET', 'POST'] },
    { type: 'header', name: 'X-Env', op: 'eq', value: 'prod' },
    { type: 'cookie', name: 'session', op: 'exists' },
    { type: 'query', name: 'debug', op: 'ne', value: '1' },
    { type: 'client_ip', values: ['10.0.0.0/8', '192.168.1.5'] },
  ],
  action: 'block',
  action_config: {
    status: 403,
    message: '访问被拦截',
    redirect_url: '',
    redirect_status: 302,
    content_type: 'text/html; charset=utf-8',
    body: '',
  },
  hit_count_24h: 0,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

describe('formValuesToBody / ruleToFormValues', () => {
  it('契约示例规则 编辑回显 → 提交 往返一致（逐字段比对）', () => {
    const body = formValuesToBody(ruleToFormValues(CONTRACT_RULE))
    expect(body).toEqual({
      name: '规则名',
      priority: 100,
      enabled: true,
      conditions: CONTRACT_RULE.conditions,
      action: 'block',
      action_config: CONTRACT_RULE.action_config,
    })
  })

  it('非法条件在提交时被拦截并指出行号', () => {
    const values: L7RuleFormValues = {
      ...ruleToFormValues(CONTRACT_RULE),
      conditions: [
        { type: 'uri', op: 'prefix', value: '/ok' },
        { type: 'client_ip', values: ['not-an-ip'] },
      ],
    }
    expect(() => formValuesToBody(values)).toThrowError(/第 2 个条件/)
  })

  it('条件超过 10 个时拒绝提交', () => {
    const values: L7RuleFormValues = {
      ...ruleToFormValues(CONTRACT_RULE),
      conditions: Array.from({ length: 11 }, () => ({ type: 'uri', op: 'prefix', value: '/a' }) as const),
    }
    expect(() => formValuesToBody(values)).toThrowError(/最多 10 个条件/)
  })

  it('redirect 动作提交前序列化 redirect_url/redirect_status/preserve_path_query 与 host 条件', () => {
    const values: L7RuleFormValues = {
      ...ruleToFormValues(CONTRACT_RULE),
      conditions: [{ type: 'host', op: 'eq', value: 'JXDR.CN' }],
      action: 'redirect',
      redirect_url: 'https://www.jxdr.cn',
      redirect_status: 301,
      redirect_preserve_path_query: true,
    }
    const body = formValuesToBody(values)
    expect(body.conditions).toEqual([{ type: 'host', op: 'eq', value: 'jxdr.cn' }])
    expect(body.action).toBe('redirect')
    expect(body.action_config.redirect_url).toBe('https://www.jxdr.cn')
    expect(body.action_config.redirect_status).toBe(301)
    expect(body.action_config.preserve_path_query).toBe(true)

    const back = ruleToFormValues({
      ...CONTRACT_RULE,
      conditions: body.conditions,
      action: 'redirect',
      action_config: body.action_config,
    })
    expect(back.redirect_preserve_path_query).toBe(true)
    expect(formValuesToBody(back)).toEqual(body)
  })

  it('conditions 为空时拒绝提交（minItems=1）', () => {
    const values: L7RuleFormValues = {
      ...ruleToFormValues(CONTRACT_RULE),
      conditions: [],
    }
    expect(() => formValuesToBody(values)).toThrowError(/至少需要 1 条匹配条件/)
  })

  it('uri contains 不以 / 开头时拒绝提交', () => {
    const values: L7RuleFormValues = {
      ...ruleToFormValues(CONTRACT_RULE),
      conditions: [{ type: 'uri', op: 'contains', value: 'admin' }],
    }
    expect(() => formValuesToBody(values)).toThrowError(/第 1 个条件：URI 须以 \/ 开头/)
  })

  it('block 状态码必须在 400~599 之间', () => {
    expect(() =>
      formValuesToBody({ ...ruleToFormValues(CONTRACT_RULE), action: 'block', block_status: 302 }),
    ).toThrowError(/400~599/)
    expect(() =>
      formValuesToBody({ ...ruleToFormValues(CONTRACT_RULE), action: 'block', block_status: 600 }),
    ).toThrowError(/400~599/)
    expect(
      formValuesToBody({ ...ruleToFormValues(CONTRACT_RULE), action: 'block', block_status: 400 }).action_config.status,
    ).toBe(400)
    expect(
      formValuesToBody({ ...ruleToFormValues(CONTRACT_RULE), action: 'block', block_status: 599 }).action_config.status,
    ).toBe(599)
  })

  it('custom_page 状态码必须在 200~599 之间且 body 非空', () => {
    expect(() =>
      formValuesToBody({
        ...ruleToFormValues(CONTRACT_RULE),
        action: 'custom_page',
        custom_status: 199,
        custom_body: 'ok',
      }),
    ).toThrowError(/200~599/)
    expect(() =>
      formValuesToBody({
        ...ruleToFormValues(CONTRACT_RULE),
        action: 'custom_page',
        custom_status: 200,
        custom_body: '',
      }),
    ).toThrowError(/自定义页面内容不能为空/)
    expect(
      formValuesToBody({
        ...ruleToFormValues(CONTRACT_RULE),
        action: 'custom_page',
        custom_status: 200,
        custom_body: '<h1>Maintenance</h1>',
      }).action_config.body,
    ).toBe('<h1>Maintenance</h1>')
  })
})
