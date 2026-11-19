import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import CustomRulesPage from '../CustomRulesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

const RULE = {
  id: 'cr-1',
  rule_id: 7100001,
  name: 'Struts2 RCE 虚拟补丁',
  description: '',
  attack_type: 'REMOTE_CODE_EXECUTION',
  severity: 'ERROR',
  phase: 2,
  operator: 'rx',
  operator_value: '(?i)ognl',
  target_variables: ['ARGS'],
  action: 'BLOCK',
  tags: [],
  cnnvd_ids: ['CNNVD-202401-2345', 'CNNVD-202402-0001'],
  cve_ids: ['CVE-2024-0001'],
  status: 'ENABLED',
  scope_type: 'GLOBAL',
  scope_ids: [],
  generated_rule: 'SecRule ARGS "@rx (?i)ognl" "id:7100001,phase:2,block"',
  version: 1,
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function mockFetch() {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (init?.method === 'POST' && url.endsWith('/custom-rules')) return ok(RULE)
    if (/\/custom-rules\/[^/?]+$/.test(url)) return ok(RULE)
    if (url.includes('/custom-rules')) {
      return ok({ items: [RULE], total: 1, page: 1, page_size: 20 })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter>
          <CustomRulesPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** Select tags 模式录入一个值并回车 */
function addTag(scope: HTMLElement, fieldId: string, value: string) {
  const input = scope.querySelector<HTMLInputElement>(`#${fieldId}`)
  expect(input).toBeTruthy()
  fireEvent.change(input!, { target: { value } })
  fireEvent.keyDown(input!, { key: 'Enter', code: 'Enter' })
}

describe('CustomRulesPage CNNVD/CVE 编号（CNNVD 兼容性 P1）', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['custom_rules.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表「漏洞编号」列：CNNVD 红 Tag / CVE 蓝 Tag，超出折叠 +N', async () => {
    renderPage()

    await screen.findByText('Struts2 RCE 虚拟补丁')
    expect(screen.getByText('CNNVD-202401-2345')).toBeInTheDocument()
    expect(screen.getByText('CNNVD-202402-0001')).toBeInTheDocument()
    // 共 3 个编号，折叠第 3 个（CVE-2024-0001）
    expect(screen.getByText('+1')).toBeInTheDocument()
    expect(screen.queryByText('CVE-2024-0001')).not.toBeInTheDocument()
  })

  it('按编号搜索：粘贴完整 CNNVD 编号走 cnnvd_id 参数，CVE 编号走 cve_id 参数', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    const input = screen.getByPlaceholderText('搜索规则ID/名称/CNNVD/CVE 编号')
    fireEvent.change(input, { target: { value: 'cnnvd-202401-2345' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
    // @rc-component/input 的 Enter 锁需 keyUp 复位，否则第二次回车被吞
    fireEvent.keyUp(input, { key: 'Enter', code: 'Enter' })
    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('cnnvd_id='))
      expect(calls.length).toBe(1)
      expect(String(calls[0]![0])).toContain('cnnvd_id=CNNVD-202401-2345')
    })

    fireEvent.change(input, { target: { value: 'CVE-2024-0001' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
    fireEvent.keyUp(input, { key: 'Enter', code: 'Enter' })
    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) => String(c[0]).includes('cve_id='))
      expect(calls.length).toBe(1)
    })
  })

  it('表单编号校验：非法 CNNVD 编号即时标红提示，提交拦截不发起 POST', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    addTag(dialog, 'cnnvd_ids', 'CNNVD-2024-01')
    // 即时校验：非法值标红提示，不拦截录入过程
    expect(await within(dialog).findByText(/CNNVD 编号格式非法：CNNVD-2024-01/)).toBeInTheDocument()

    // 提交前表单校验拦截
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      expect(within(dialog).getByText(/CNNVD 编号格式非法/)).toBeInTheDocument()
    })
    const posts = (fetch as Mock).mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(posts).toHaveLength(0)
  })

  it('表单编号校验：非法 CVE 编号即时提示', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    addTag(dialog, 'cve_ids', 'CVE-24-1')
    expect(await within(dialog).findByText(/CVE 编号格式非法：CVE-24-1/)).toBeInTheDocument()
  })

  it('新建提交：合法编号随表单 POST（cnnvd_ids/cve_ids）', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    const ruleIdInput = dialog.querySelector<HTMLInputElement>('#rule_id')
    fireEvent.change(ruleIdInput!, { target: { value: '7100002' } })
    fireEvent.change(within(dialog).getByPlaceholderText('如：拦截特定路径的SQL注入尝试'), {
      target: { value: '测试规则' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：(?i)(union.*select)'), {
      target: { value: '(?i)test' },
    })
    addTag(dialog, 'cnnvd_ids', 'CNNVD-202401-2345')
    addTag(dialog, 'cve_ids', 'CVE-2024-0001')

    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
      const body = JSON.parse(String((post![1] as RequestInit).body))
      expect(body.cnnvd_ids).toEqual(['CNNVD-202401-2345'])
      expect(body.cve_ids).toEqual(['CVE-2024-0001'])
    })
  })
})

describe('执行阶段与动作联动（phase=2 BLOCK 被 CRS 抢先问题修复）', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['custom_rules.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('动作切换为 BLOCK 且阶段为默认 2 时，阶段自动改为 1；阶段提示文案渲染', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    // 阶段提示文案
    expect(
      within(dialog).getByText(/阶段 2 的阻断规则可能被 CRS 阻断评估抢先/),
    ).toBeInTheDocument()

    // antd 6 Select：选中值渲染在 .ant-select-content（title 属性同为选中项文本）
    const phaseText = () =>
      dialog.querySelector('#phase')?.closest('.ant-select')?.querySelector('.ant-select-content')
        ?.textContent

    // 初始：动作=仅记录（LOG），阶段=2
    expect(phaseText()).toContain('阶段 2')

    // 切换动作为 阻断（BLOCK）
    const actionSelect = dialog.querySelector('#action')!.closest('.ant-select')!
    fireEvent.mouseDown(actionSelect)
    const blockOption = await screen.findByText('阻断', { selector: '.ant-select-item-option-content' })
    fireEvent.click(blockOption)

    // 阶段联动为 1
    await waitFor(() => {
      expect(phaseText()).toContain('阶段 1')
    })
  })

  it('用户显式改过阶段后切 BLOCK 不被联动覆盖', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    // antd 6 Select：选中值渲染在 .ant-select-content（title 属性同为选中项文本）
    const phaseText = () =>
      dialog.querySelector('#phase')?.closest('.ant-select')?.querySelector('.ant-select-content')
        ?.textContent

    // 用户先把阶段改为 3
    const phaseSelect = dialog.querySelector('#phase')!.closest('.ant-select')!
    fireEvent.mouseDown(phaseSelect)
    fireEvent.click(await screen.findByText('阶段 3（响应头）', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => {
      expect(phaseText()).toContain('阶段 3')
    })

    // 再切 BLOCK：保持 3 不变
    const actionSelect = dialog.querySelector('#action')!.closest('.ant-select')!
    fireEvent.mouseDown(actionSelect)
    fireEvent.click(await screen.findByText('阻断', { selector: '.ant-select-item-option-content' }))
    await waitFor(() => {
      const actionText = dialog
        .querySelector('#action')
        ?.closest('.ant-select')
        ?.querySelector('.ant-select-content')?.textContent
      expect(actionText).toBe('阻断')
    })
    expect(phaseText()).toContain('阶段 3')
  })

  it('检测变量、作用范围与操作符中文化展示（表单下拉与详情抽屉）', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    // 详情抽屉：检测变量 ARGS → 全部参数，作用范围 GLOBAL → 全局，操作符 rx → 正则匹配
    fireEvent.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('全部参数')).toBeInTheDocument()
    expect(screen.getByText('全局')).toBeInTheDocument()
    expect(screen.getByText('正则匹配')).toBeInTheDocument()
    expect(screen.queryByText('GLOBAL')).not.toBeInTheDocument()

    // 新建弹窗：默认选中的检测变量 ARGS 显示为中文「全部参数」
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    await waitFor(() => expect(document.querySelector('.ant-modal')).toBeTruthy())
    const modal = document.querySelector('.ant-modal') as HTMLElement
    expect(within(modal).getByText('全部参数')).toBeInTheDocument()
  })
})
