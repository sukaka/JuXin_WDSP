import { test, expect } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段4 E2E：策略绑定发布 → 攻击事件 → 误报例外闭环
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s3'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S3!2026'
const GATEWAY_URL = process.env.E2E_GATEWAY_URL || 'http://127.0.0.1:18080'
const HOST = process.env.E2E_HOST || 'waf-test.local'

test.describe('阶段4：策略与事件闭环', () => {
  test('内置策略存在且可查询', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const resp = await page.request.get(`${API_URL}/protection-policies`)
    expect(resp.status()).toBe(200)
    const data = (await resp.json())?.data
    const codes = data.items.map((p: { code: string }) => p.code)
    expect(codes).toContain('relaxed')
    expect(codes).toContain('standard')
    expect(codes).toContain('strict')
  })

  test('WAF规则同步与查询', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token
    // 触发同步
    const sync = await page.request.post(`${API_URL}/waf-rules/sync`, {
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(sync.status()).toBe(200)
    const report = (await sync.json())?.data
    expect(report.total_in_db).toBeGreaterThan(100)
    // 查询规则
    const rules = await page.request.get(`${API_URL}/waf-rules?attack_type=SQL_INJECTION&page_size=5`)
    expect(rules.status()).toBe(200)
    const rulesData = (await rules.json())?.data
    expect(rulesData.total).toBeGreaterThan(0)
  })

  test('攻击产生安全事件且可查询处置', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    // 发攻击
    await page.request.get(`${GATEWAY_URL}/echo?q=1'%20OR%20'1'='1`, { headers: { Host: HOST } })
    await page.waitForTimeout(4000)
    // 查询事件
    const events = await page.request.get(`${API_URL}/security-events?attack_type=SQL_INJECTION&page_size=5`)
    expect(events.status()).toBe(200)
    const data = (await events.json())?.data
    expect(data.total).toBeGreaterThan(0)
    const evt = data.items[0]
    expect(evt.attack_type).toBe('SQL_INJECTION')
    // 事件详情
    const detail = await page.request.get(`${API_URL}/security-events/${evt.id}`)
    expect(detail.status()).toBe(200)
    const detailData = (await detail.json())?.data
    expect(detailData.matches.length).toBeGreaterThan(0)
    // 处置（确认攻击）
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token
    const disp = await page.request.post(`${API_URL}/security-events/${evt.id}/confirm-attack`, {
      data: { result: 'CONFIRMED_ATTACK', note: 'E2E确认' },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(disp.status()).toBe(200)
  })

  test('自定义规则创建与校验', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token
    // 校验合法规则
    const validate = await page.request.post(`${API_URL}/custom-rules/00000000-0000-0000-0000-000000000000/validate`, {
      data: {
        rule_id: 7100999, name: 'E2E测试规则', operator: 'rx', operator_value: '(?i)test',
        target_variables: ['ARGS'], action: 'BLOCK', phase: 2, attack_type: 'OTHER', severity: 'WARNING',
      },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(validate.status()).toBe(200)
    const vdata = (await validate.json())?.data
    expect(vdata.valid).toBe(true)
    // 危险规则被拒
    const bad = await page.request.post(`${API_URL}/custom-rules`, {
      data: {
        rule_id: 942100, name: '危险', operator: 'rx', operator_value: 'x',
        target_variables: ['ARGS'], action: 'BLOCK', phase: 2,
      },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(bad.status()).toBe(400)
  })

  test('宽泛例外需风险确认', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const me = await page.request.get(`${API_URL}/auth/me`)
    const csrf = (await me.json())?.data?.csrf_token
    const resp = await page.request.post(`${API_URL}/exceptions`, {
      data: {
        name: '全部SQLi例外', scope_type: 'GLOBAL', attack_types: ['SQL_INJECTION'],
        exception_action: 'REMOVE_RULE_TAG', rule_tags: ['attack-sqli'],
      },
      headers: { 'X-CSRF-Token': csrf },
    })
    expect(resp.status()).toBe(400)
  })
})
