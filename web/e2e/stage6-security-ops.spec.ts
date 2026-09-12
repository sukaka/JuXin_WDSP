import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段6 E2E：态势首页/统计分析/系统告警/报告/备份/交付检查
 */

const SEC_USER = process.env.E2E_SEC_USER || 'sec_admin_s5'
const SEC_PWD = process.env.E2E_SEC_PWD || 'SecAdmin@S5!2026'
const SYS_USER = process.env.E2E_SYS_USER || 'jiuzhang_admin'
const SYS_PWD = process.env.E2E_SYSADMIN_PWD || 'SysAdmin@S5!2026'

async function csrf(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return (await me.json())?.data?.csrf_token
}

test.describe('阶段6：安全运营与交付', () => {
  test('安全总览与统计分析渲染真实数据', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/security-overview')
    // 总览卡片渲染（今日请求总数为数字）
    await expect(page.getByText('今日请求').first()).toBeVisible({ timeout: 15000 })
    // 图表 canvas 出现
    await expect(page.locator('canvas').first()).toBeVisible({ timeout: 15000 })
    // 排行 Tab 可切换
    await page.goto('/analytics')
    await expect(page.locator('canvas').first()).toBeVisible({ timeout: 15000 })
  })

  test('系统告警列表与确认流转', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/system-alerts')
    await expect(page.getByText('系统告警').first()).toBeVisible({ timeout: 15000 })
    // 找 OPEN 告警并经 API 确认（UI 渲染验证 + API 流转）
    const list = await page.request.get(`${API_URL}/system-alerts?status=OPEN&page_size=1`)
    const data = (await list.json())?.data
    if (data?.items?.length > 0) {
      const alertId = data.items[0].id
      const token = await csrf(page)
      const ack = await page.request.post(`${API_URL}/system-alerts/${alertId}/acknowledge`, {
        headers: { 'X-CSRF-Token': token },
      })
      expect([200, 409]).toContain(ack.status())
    }
    // 审计管理员只读：创建审计用户验证列表可见、操作接口 403
    const audName = 's6e2e_audit_' + Math.random().toString(36).slice(2, 8)
    const sysPage = page
    await loginViaAPI(sysPage, SYS_USER, SYS_PWD)
    const token = await csrf(sysPage)
    const create = await sysPage.request.post(`${API_URL}/users`, {
      data: { username: audName, display_name: audName, role_code: 'AUDIT_ADMIN' },
      headers: { 'X-CSRF-Token': token },
    })
    expect(create.ok()).toBeTruthy()
    const tmpPwd = (await create.json())?.data?.temporary_password
    // 改密
    await loginViaAPI(sysPage, audName, tmpPwd)
    const t2 = await csrf(sysPage)
    await sysPage.request.post(`${API_URL}/auth/change-password`, {
      data: { old_password: tmpPwd, new_password: 'AuditS6@Test2026!' },
      headers: { 'X-CSRF-Token': t2 },
    })
    await loginViaAPI(sysPage, audName, 'AuditS6@Test2026!')
    const audList = await sysPage.request.get(`${API_URL}/system-alerts?page_size=1`)
    expect(audList.status()).toBe(200)
    if (data?.items?.length > 0) {
      const t3 = await csrf(sysPage)
      const ack = await sysPage.request.post(`${API_URL}/system-alerts/${data.items[0].id}/acknowledge`, {
        headers: { 'X-CSRF-Token': t3 },
      })
      expect(ack.status()).toBe(403)
    }
  })

  test('报告全流程：创建→生成→预览→下载', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/reports')
    await expect(page.getByText('报告').first()).toBeVisible({ timeout: 15000 })
    const token = await csrf(page)
    const start = new Date(Date.now() - 7 * 86400000).toISOString()
    const end = new Date().toISOString()
    const create = await page.request.post(`${API_URL}/reports`, {
      data: { report_type: 'CUSTOM', start_time: start, end_time: end, format: 'html' },
      headers: { 'X-CSRF-Token': token },
    })
    expect(create.ok()).toBeTruthy()
    const job = (await create.json())?.data?.report
    expect(job?.id).toBeTruthy()
    // 轮询至 SUCCESS
    let status = ''
    for (let i = 0; i < 60; i++) {
      const r = await page.request.get(`${API_URL}/reports/${job.id}`)
      status = (await r.json())?.data?.report?.status
      if (status === 'SUCCESS' || status === 'FAILED') break
      await page.waitForTimeout(2000)
    }
    expect(status).toBe('SUCCESS')
    // 预览含九章
    const preview = await page.request.get(`${API_URL}/reports/${job.id}/preview`)
    expect((await preview.text()).includes('九章')).toBeTruthy()
    // 下载
    const dl = await page.request.get(`${API_URL}/reports/${job.id}/download`)
    expect(dl.ok()).toBeTruthy()
  })

  test('备份创建与验证（UI + API）', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/backup-restore')
    await expect(page.getByText('备份').first()).toBeVisible({ timeout: 15000 })
    const token = await csrf(page)
    const create = await page.request.post(`${API_URL}/backups`, {
      data: { backup_type: 'CONFIG_ONLY' },
      headers: { 'X-CSRF-Token': token },
    })
    expect(create.ok()).toBeTruthy()
    const job = (await create.json())?.data?.job
    let status = ''
    for (let i = 0; i < 90; i++) {
      const r = await page.request.get(`${API_URL}/backups/${job.id}`)
      status = (await r.json())?.data?.job?.status
      if (status === 'SUCCESS' || status === 'FAILED') break
      await page.waitForTimeout(2000)
    }
    expect(status).toBe('SUCCESS')
    const verify = await page.request.post(`${API_URL}/backups/${job.id}/verify`, {
      headers: { 'X-CSRF-Token': token },
    })
    expect(verify.ok()).toBeTruthy()
  })

  test('交付检查执行与结果展示', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/delivery-check')
    await expect(page.getByText('交付检查').first()).toBeVisible({ timeout: 15000 })
    const token = await csrf(page)
    const run = await page.request.post(`${API_URL}/delivery-checks/run`, {
      headers: { 'X-CSRF-Token': token },
    })
    expect(run.ok()).toBeTruthy()
    const check = (await run.json())?.data?.check
    expect(check?.id).toBeTruthy()
    await page.waitForTimeout(5000)
    const detail = await page.request.get(`${API_URL}/delivery-checks/${check.id}`)
    const d = (await detail.json())?.data
    const checkObj = d?.check ?? d
    expect(checkObj.total).toBeGreaterThanOrEqual(20)
    expect(['PASS', 'WARNING', 'FAIL']).toContain(checkObj.overall_result)
  })

  test('三权隔离：安全管理员访问备份恢复被拒', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    const resp = await page.request.get(`${API_URL}/backups`)
    expect(resp.status()).toBe(403)
    // 菜单不含系统运维项
    await page.goto('/security-overview')
    await expect(page.getByText('今日请求').first()).toBeVisible({ timeout: 15000 })
    await expect(page.getByRole('link', { name: '备份恢复' })).toHaveCount(0)
    await expect(page.getByRole('link', { name: '系统升级' })).toHaveCount(0)
  })
})
