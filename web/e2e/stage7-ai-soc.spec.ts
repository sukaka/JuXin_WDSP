import { test, expect } from '@playwright/test'
import type { Page } from '@playwright/test'
import { loginViaAPI, API_URL } from './helpers'

/**
 * 阶段7 E2E：AI 安全运营中心
 * - 菜单权限显隐（安全/审计管理员）
 * - AI安全助手多轮对话全流程（真实 Ollama 推理，单轮约 30-90 秒）
 * - AI 任务记录、事件分析、AI 管理只读浏览、Prompt 流程、审计哈希链
 *
 * 依赖：stage5 栈（API 18081 + Ollama qwen2.5:3b）+ vite dev server（/api 代理）。
 * 串行执行（workers=1）：「任务记录」用例依赖「AI安全助手」用例产生的任务。
 */

const SEC_USER = process.env.E2E_SEC_USER || 's6_sec'
const SEC_PWD = process.env.E2E_SEC_PWD || 'S6Sec@Test2026!'
const SYS_USER = process.env.E2E_SYS_USER || 's6_sys'
const SYS_PWD = process.env.E2E_SYS_PWD || 'S6Sys@Test2026!'
const AUD_USER = process.env.E2E_AUD_USER || 's6_aud'
const AUD_PWD = process.env.E2E_AUD_PWD || 'S6Aud@Test2026!'

/** AI 推理等待（CPU 上 qwen2.5:3b 单轮 30-90s，留足余量） */
const AI_WAIT = 300_000

/** 真实安全事件 ID（取自 security_events 表；列表接口当前 500，见交付说明） */
const SAMPLE_EVENT_ID = '61bfdb71-d6b2-4da9-bc7a-b994f2265e40'

async function csrf(page: Page): Promise<string> {
  const me = await page.request.get(`${API_URL}/auth/me`)
  return (await me.json())?.data?.csrf_token
}

/** 展开侧边栏分组（antd SubMenu 关闭时子项不渲染） */
async function openMenuGroup(page: Page, label: string) {
  await page.locator('.ant-menu-submenu-title', { hasText: label }).click()
}

test.describe('阶段7：AI安全运营中心', () => {
  test.describe.configure({ mode: 'serial' })

  /* ==================== 1. 菜单权限显隐 ==================== */

  test('菜单权限：安全管理员可见 AI安全运营 全部7项与 AI管理 全部7项', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/dashboard')

    // 种子权限（000014）：安全管理员含 ai.models.read / ai.agents.read / ai.tools.read /
    // ai.prompts.read / ai.audits.read / ai.usage.read，菜单按角色显隐（menu.ts），两组均全量可见
    await openMenuGroup(page, 'AI安全运营')
    for (const label of [
      'AI安全助手',
      'AI事件分析',
      'AI攻击画像',
      'AI攻击链',
      'AI策略建议',
      'AI报告总结',
      'AI任务记录',
    ]) {
      await expect(page.getByRole('menuitem', { name: label })).toBeVisible()
    }

    await openMenuGroup(page, 'AI管理')
    for (const label of [
      '模型管理',
      'Agent管理',
      'Tool管理',
      'Prompt管理',
      'Memory管理',
      '配额与成本',
      'AI审计',
    ]) {
      await expect(page.getByRole('menuitem', { name: label })).toBeVisible()
    }
  })

  test('菜单权限：审计管理员仅见 AI管理 下只读项', async ({ page }) => {
    await loginViaAPI(page, AUD_USER, AUD_PWD)
    await page.goto('/dashboard')

    // 审计管理员无任何 ai.*.use 权限 → 「AI安全运营」分组不出现
    await expect(
      page.locator('.ant-menu-submenu-title', { hasText: 'AI安全运营' }),
    ).toHaveCount(0)

    // 仅 ai.usage.read + ai.audits.read → 只见 配额与成本、AI审计
    await openMenuGroup(page, 'AI管理')
    await expect(page.getByRole('menuitem', { name: '配额与成本' })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: 'AI审计' })).toBeVisible()
    for (const label of ['模型管理', 'Agent管理', 'Tool管理', 'Prompt管理', 'Memory管理']) {
      await expect(page.getByRole('menuitem', { name: label })).toHaveCount(0)
    }
  })

  /* ==================== 2. AI安全助手完整对话 ==================== */

  test('AI安全助手：多轮对话→重命名→刷新留存→清理', async ({ page }) => {
    test.setTimeout(600_000)
    const sessionTitle = `E2E会话${Date.now()}`

    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/ai/assistant')
    await page.getByRole('button', { name: '新建会话' }).click()

    // 第一轮：统计数据类问题
    const input = page.getByPlaceholder(/输入问题/)
    await input.fill('统计最近24小时攻击类型分布')
    await page.getByRole('button', { name: '发送' }).click()

    // 执行过程区出现 plan/agent 步骤
    await expect(page.getByText(/任务计划|Agent 开始/).first()).toBeVisible({ timeout: 240_000 })

    // 最终回答出现（持久化消息后渲染反馈按钮）
    await expect(page.locator('button:has(.anticon-like)').first()).toBeVisible({
      timeout: AI_WAIT,
    })
    // 回答内容与问题相关（攻击/事件/CC 分布），且包含证据引用标记或证据说明
    await expect(
      page.locator('p.ant-typography', { hasText: /攻击|事件|CC/ }).first(),
    ).toBeVisible()
    await expect(
      page.getByText(/证据|\[E\d+\]|统计如下|分布/).last(),
    ).toBeVisible()

    // 第二轮：短消息验证多轮上下文
    await input.fill('其中CC攻击多少次？')
    await page.getByRole('button', { name: '发送' }).click()
    await expect(page.locator('button:has(.anticon-like)')).toHaveCount(2, { timeout: AI_WAIT })

    // 会话重命名（列表按 updated_at DESC，当前会话在第一项）
    const firstItem = page.locator('.ant-list-item').first()
    await firstItem.locator('button:has(.anticon-more)').click()
    await page.getByRole('menuitem', { name: /重命名/ }).click()
    const renameDialog = page.getByRole('dialog')
    await renameDialog.locator('input').fill(sessionTitle)
    await renameDialog.getByRole('button', { name: '保存' }).click()
    await expect(page.getByText(sessionTitle)).toBeVisible({ timeout: 15_000 })

    // 刷新页面会话仍在，历史消息可回看
    await page.reload()
    await expect(page.getByText(sessionTitle).first()).toBeVisible({ timeout: 15_000 })
    await page.locator('.ant-list-item', { hasText: sessionTitle }).first().click()
    await expect(page.getByText('统计最近24小时攻击类型分布')).toBeVisible({ timeout: 15_000 })

    // 清理：API 删除会话
    const list = await page.request.get(`${API_URL}/ai/sessions?page=1&page_size=50`)
    const items = (await list.json())?.data?.items ?? []
    const target = items.find((s: { id: string; title: string }) => s.title === sessionTitle)
    expect(target, '会话列表中应找到重命名后的会话').toBeTruthy()
    const token = await csrf(page)
    const del = await page.request.delete(`${API_URL}/ai/sessions/${target.id}`, {
      headers: { 'X-CSRF-Token': token },
    })
    expect(del.ok()).toBeTruthy()
  })

  /* ==================== 3. 任务记录 ==================== */

  test('AI任务记录：列表含成功记录并可打开详情抽屉', async ({ page }) => {
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/ai/tasks')
    await expect(page.getByText('AI 任务记录')).toBeVisible({ timeout: 15_000 })

    // 依赖上一个用例产生的任务；按状态过滤「成功」
    await page.locator('.ant-select', { hasText: '状态' }).first().click()
    await page
      .locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', {
        hasText: '成功',
      })
      .first()
      .click()
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText('成功', { exact: true }).first()).toBeVisible()

    // 详情抽屉
    await page.getByRole('button', { name: '详情' }).first().click()
    const drawer = page.locator('.ant-drawer-content')
    await expect(drawer.getByText('任务详情')).toBeVisible({ timeout: 15_000 })
    await expect(drawer.getByText('任务 ID')).toBeVisible()
    await expect(drawer.getByText('计划摘要')).toBeVisible()
  })

  /* ==================== 4. 事件分析 ==================== */

  test('AI事件分析：输入真实事件ID输出回答与证据', async ({ page }) => {
    test.setTimeout(420_000)
    await loginViaAPI(page, SEC_USER, SEC_PWD)
    await page.goto('/ai/event-analysis')

    await page.getByPlaceholder('安全事件 UUID').fill(SAMPLE_EVENT_ID)
    await page.getByRole('button', { name: '开始分析' }).click()
    await expect(page.getByText(/AI 正在分析/)).toBeVisible({ timeout: 15_000 })

    // 分析结果卡：计划信息 + 回答
    await expect(page.getByText('分析结果')).toBeVisible({ timeout: AI_WAIT })
    await expect(page.getByText('任务类型')).toBeVisible()
    await expect(page.getByText('任务 ID')).toBeVisible()
    // 证据引用列表
    await expect(page.getByText('证据引用')).toBeVisible({ timeout: 20_000 })
  })

  /* ==================== 5. AI管理只读浏览（s6_sys） ==================== */

  test('AI管理：模型页可见 ollama-local/qwen2.5:3b 与路由档位', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/ai/admin/models')

    await expect(page.getByText('模型路由档位')).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText('标准分析')).toBeVisible()
    await expect(page.getByText('模型供应商')).toBeVisible()
    await expect(page.getByText('ollama-local').first()).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText('qwen2.5:3b').first()).toBeVisible()
    // 路由档位已指向 qwen2.5:3b（Select 选中值，选项标签含显示名与编码）
    await expect(
      page.locator('.ant-select-selection-item', { hasText: 'qwen2.5:3b' }).first(),
    ).toBeVisible()
  })

  test('AI管理：Agent 页列出 8 个内置 Agent', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/ai/admin/agents')

    await expect(page.getByText('Agent 管理')).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('tbody tr')).toHaveCount(8, { timeout: 15_000 })
    await expect(page.getByText('dispatcher')).toBeVisible()
    await expect(page.getByText('security_event')).toBeVisible()
  })

  test('AI管理：Tool 页展示 Tool 表格', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/ai/admin/tools')

    await expect(page.getByText('Tool 管理')).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 15_000 })
    await expect(page.getByText('application.search')).toBeVisible()
  })

  test('AI管理：AI审计页展示审计记录表格', async ({ page }) => {
    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/ai/admin/audits')

    await expect(page.getByText('AI 审计')).toBeVisible({ timeout: 15_000 })
    await expect(page.locator('tbody tr').first()).toBeVisible({ timeout: 15_000 })
  })

  /* ==================== 6. Prompt 管理流程（s6_sys） ==================== */

  test('Prompt管理：新建→版本→未测试禁发→静态测试→发布', async ({ page }) => {
    test.setTimeout(180_000)
    const ts = Date.now()
    const code = `e2e.prompt.${ts}`
    const name = `E2E测试Prompt${ts}`

    await loginViaAPI(page, SYS_USER, SYS_PWD)
    await page.goto('/ai/admin/prompts')

    // 新建 Prompt
    await page.getByRole('button', { name: '新建 Prompt' }).click()
    let dialog = page.getByRole('dialog')
    await dialog.locator('#code').fill(code)
    await dialog.locator('#name').fill(name)
    await dialog
      .locator('.ant-form-item')
      .filter({ has: page.locator('label[for="prompt_type"]') })
      .locator('.ant-select')
      .click()
    await page
      .locator('.ant-select-dropdown:not(.ant-select-dropdown-hidden) .ant-select-item-option', {
        hasText: '任务',
      })
      .click()
    await dialog.locator('#content').fill('你是安全运营助手，仅基于给定数据输出简短摘要。')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('Prompt 已创建')).toBeVisible({ timeout: 15_000 })
    const row = page.locator('tbody tr', { hasText: code })
    await expect(row).toBeVisible({ timeout: 15_000 })

    // 打开版本管理抽屉，新建 v2
    await row.getByRole('button', { name: '版本' }).click()
    const drawer = page.locator('.ant-drawer-content')
    await expect(drawer.getByText(`版本管理 - ${name}`)).toBeVisible({ timeout: 15_000 })
    await drawer.getByRole('button', { name: '新建版本' }).click()
    dialog = page.getByRole('dialog')
    await dialog.locator('#content').fill('你是安全运营助手，基于证据给出结论，输出不超过三段。')
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    const v2row = drawer.locator('tbody tr', { hasText: 'v2' })
    await expect(v2row).toBeVisible({ timeout: 15_000 })

    // 未测试：UI 发布按钮禁用
    await expect(v2row.getByRole('button', { name: '发布' })).toBeDisabled()
    // 未测试：API 直接发布应报错（400 仅静态测试通过可发布）
    const promptsResp = await page.request.get(`${API_URL}/ai/prompts`)
    const prompt = ((await promptsResp.json())?.data?.items ?? []).find(
      (p: { id: string; code: string }) => p.code === code,
    )
    expect(prompt, 'Prompt 列表中应找到新建项').toBeTruthy()
    const versionsResp = await page.request.get(`${API_URL}/ai/prompts/${prompt.id}/versions`)
    const versions = (await versionsResp.json())?.data?.items ?? []
    const v2 = versions.find((v: { id: string; version_number: number }) => v.version_number === 2)
    expect(v2, '版本列表中应存在 v2').toBeTruthy()
    let token = await csrf(page)
    const badPublish = await page.request.post(`${API_URL}/ai/prompts/${prompt.id}/publish`, {
      data: { version_id: v2.id },
      headers: { 'X-CSRF-Token': token },
    })
    expect(badPublish.status()).toBe(400)
    expect(((await badPublish.json())?.message ?? '') as string).toContain('仅静态测试通过')

    // 静态测试通过
    await v2row.getByRole('button', { name: '测试' }).click()
    await expect(page.getByText('静态测试通过')).toBeVisible({ timeout: 30_000 })
    await page.getByRole('button', { name: /知道了/ }).click()
    await expect(v2row.getByText('测试通过')).toBeVisible({ timeout: 15_000 })

    // 发布成功
    await v2row.getByRole('button', { name: '发布' }).click()
    dialog = page.getByRole('dialog')
    await expect(dialog.getByText('发布确认')).toBeVisible()
    await dialog.getByRole('button', { name: /确 ?定/ }).click()
    await expect(page.getByText('版本已发布')).toBeVisible({ timeout: 15_000 })
    await expect(v2row.getByText('当前')).toBeVisible({ timeout: 15_000 })
    // 说明：Prompt 无删除接口，遗留数据以 e2e.prompt.<时间戳> 编码可识别
  })

  /* ==================== 7. 审计哈希链（s6_aud） ==================== */

  test('AI审计：审计管理员校验哈希链通过', async ({ page }) => {
    test.setTimeout(180_000)
    await loginViaAPI(page, AUD_USER, AUD_PWD)
    await page.goto('/ai/admin/audits')

    await page.getByRole('button', { name: '校验哈希链' }).click()
    await expect(page.getByText('哈希链校验通过')).toBeVisible({ timeout: 120_000 })
    await expect(page.getByText(/共校验 \d+ 条记录/)).toBeVisible()
  })
})
