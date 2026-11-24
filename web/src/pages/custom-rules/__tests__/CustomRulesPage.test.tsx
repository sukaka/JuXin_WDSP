import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import CustomRulesPage from '../CustomRulesPage'
import { formatCustomRulePhase, inferCustomRulePhase } from '../phase'
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

function mockFetch(rules = [RULE]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (init?.method === 'POST' && /\/custom-rules\/[^/?]+\/validate$/.test(url)) {
      return ok({ valid: true, generated_rule: rules[0]?.generated_rule ?? RULE.generated_rule })
    }
    if (init?.method === 'POST' && url.endsWith('/custom-rules')) return ok(rules[0] ?? RULE)
    if (init?.method === 'PUT' && /\/custom-rules\/[^/?]+$/.test(url)) return ok(rules[0] ?? RULE)
    if (/\/custom-rules\/[^/?]+$/.test(url)) {
      const id = url.split('/').pop()
      return ok(rules.find((r) => r.id === id) ?? rules[0] ?? RULE)
    }
    if (url.includes('/custom-rules')) {
      return ok({ items: rules, total: rules.length, page: 1, page_size: 20 })
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

  it('B10-5：不完整 CNNVD-/CVE- 前缀走 keyword 查询而非触发服务端 400 的精确参数', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    const input = screen.getByPlaceholderText('搜索规则ID/名称/CNNVD/CVE 编号')
    for (const partial of ['CNNVD-2024', 'cnnvd-', 'CVE-2024', 'cve-']) {
      fireEvent.change(input, { target: { value: partial } })
      fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })
      fireEvent.keyUp(input, { key: 'Enter', code: 'Enter' })
      await waitFor(() => {
        const calls = (fetch as Mock).mock.calls.filter((c) =>
          String(c[0]).includes(`keyword=${encodeURIComponent(partial)}`),
        )
        expect(calls.length).toBe(1)
      })
    }
    expect((fetch as Mock).mock.calls.some((c) => String(c[0]).includes('cnnvd_id='))).toBe(false)
    expect((fetch as Mock).mock.calls.some((c) => String(c[0]).includes('cve_id='))).toBe(false)
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

/** 多选 Select 中按中文标签勾选一个检测变量（输入关键词规避虚拟列表裁切） */
async function selectTargetVariable(dialog: HTMLElement, optionLabel: string) {
  const input = dialog.querySelector<HTMLInputElement>('#target_variables')!
  const select = input.closest('.ant-select')!
  fireEvent.mouseDown(select)
  fireEvent.change(input, { target: { value: optionLabel } })
  const option = await screen.findByText(optionLabel, {
    selector: '.ant-select-item-option-content',
  })
  fireEvent.click(option)
}

/** 清除多选 Select 中所有已选检测变量标签 */
function clearSelectedTargetVariables(dialog: HTMLElement) {
  const select = dialog.querySelector('#target_variables')!.closest('.ant-select')!
  const removeButtons = select.querySelectorAll<HTMLElement>('.ant-select-selection-item-remove')
  removeButtons.forEach((btn) => fireEvent.click(btn))
}

describe('inferCustomRulePhase / formatCustomRulePhase（自动阶段推导与展示）', () => {
  it('请求体相关变量（含 :selector 形态及混合变量）推导为阶段 2', () => {
    expect(inferCustomRulePhase(['REQUEST_BODY'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS_POST'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS_NAMES'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS:id'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS_POST:payload'])).toBe(2)
    expect(inferCustomRulePhase(['ARGS_NAMES:foo'])).toBe(2)
    expect(inferCustomRulePhase(['REQUEST_BODY:raw'])).toBe(2)
    expect(inferCustomRulePhase(['REQUEST_URI', 'ARGS_POST'])).toBe(2)
    expect(inferCustomRulePhase(['HTTP_USER_AGENT', 'ARGS:token'])).toBe(2)
  })

  it('仅含请求头/URI/Cookie 等变量或空列表推导为阶段 1', () => {
    const headerVars = [
      'ARGS_GET',
      'QUERY_STRING',
      'REQUEST_URI',
      'REQUEST_METHOD',
      'REQUEST_HEADERS',
      'REQUEST_HEADERS_NAMES',
      'REQUEST_COOKIES',
      'REQUEST_FILENAME',
      'REQUEST_BASENAME',
      'REMOTE_ADDR',
      'HTTP_USER_AGENT',
      'CONTENT_TYPE',
      'REQUEST_PROTOCOL',
      'REQUEST_LINE',
    ]
    for (const v of headerVars) {
      expect(inferCustomRulePhase([v])).toBe(1)
    }
    expect(inferCustomRulePhase(['REQUEST_HEADERS:Host', 'REQUEST_COOKIES:sid'])).toBe(1)
    expect(inferCustomRulePhase([])).toBe(1)
    expect(inferCustomRulePhase(undefined)).toBe(1)
  })

  it('执行阶段中文标签兼容 1..5 历史数据与未知值', () => {
    expect(formatCustomRulePhase(1)).toBe('阶段 1（请求头）')
    expect(formatCustomRulePhase(2)).toBe('阶段 2（请求体）')
    expect(formatCustomRulePhase(3)).toBe('阶段 3（响应头）')
    expect(formatCustomRulePhase(4)).toBe('阶段 4（响应体）')
    expect(formatCustomRulePhase(5)).toBe('阶段 5（日志）')
    expect(formatCustomRulePhase(9)).toBe('阶段 9')
    expect(formatCustomRulePhase(undefined)).toBe('-')
  })
})

describe('执行阶段自动推导与表单交互（方案一：自定义规则优先于 CRS）', () => {
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

  it('新建与编辑弹窗不再渲染手动 1-5 执行阶段下拉和 CRS 抢先术语', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    // 新建弹窗
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const createDialog = await screen.findByRole('dialog')
    expect(createDialog.querySelector('#phase')).toBeNull()
    expect(within(createDialog).queryByLabelText('执行阶段')).not.toBeInTheDocument()
    expect(within(createDialog).queryByText(/CRS/)).not.toBeInTheDocument()
    expect(within(createDialog).queryByText(/抢先/)).not.toBeInTheDocument()
    expect(
      within(createDialog).getByText(
        '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
      ),
    ).toBeInTheDocument()
    fireEvent.click(within(createDialog).getByRole('button', { name: /取\s*消|Cancel/ }))

    // 编辑弹窗
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    const editTitle = await screen.findByText(/编辑规则：Struts2 RCE 虚拟补丁/)
    const editDialog = editTitle.closest('.ant-modal') as HTMLElement
    expect(editDialog).toBeTruthy()
    expect(editDialog.querySelector('#phase')).toBeNull()
    expect(within(editDialog).queryByLabelText('执行阶段')).not.toBeInTheDocument()
    expect(within(editDialog).queryByText(/CRS/)).not.toBeInTheDocument()
    expect(within(editDialog).queryByText(/抢先/)).not.toBeInTheDocument()
    expect(
      within(editDialog).getByText(
        '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
      ),
    ).toBeInTheDocument()
  })

  it('切换检测变量时实时展示请求头阶段 / 请求体阶段自动生效时机', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    // 默认 target_variables=['ARGS'] → 请求体阶段
    expect(
      within(dialog).getByText(
        '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
      ),
    ).toBeInTheDocument()

    // 移除 ARGS，仅选择 REQUEST_URI 与 HTTP_USER_AGENT → 请求头阶段
    clearSelectedTargetVariables(dialog)
    await selectTargetVariable(dialog, '请求 URI')
    await selectTargetVariable(dialog, 'User-Agent')
    await waitFor(() => {
      expect(
        within(dialog).getByText('自动生效时机：请求头阶段（优先于内置防护规则生效）'),
      ).toBeInTheDocument()
    })

    // 加入 REQUEST_BODY → 切回请求体阶段
    await selectTargetVariable(dialog, '请求体')
    await waitFor(() => {
      expect(
        within(dialog).getByText(
          '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
        ),
      ).toBeInTheDocument()
    })

    // 清除并仅选择 ARGS_POST → 仍为请求体阶段
    clearSelectedTargetVariables(dialog)
    await selectTargetVariable(dialog, '表单请求体参数')
    await waitFor(() => {
      expect(
        within(dialog).getByText(
          '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
        ),
      ).toBeInTheDocument()
    })
  })

  it('动作切换为 BLOCK 且变量为 ARGS/REQUEST_BODY 时保持请求体阶段，不再误降为请求头阶段', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const dialog = await screen.findByRole('dialog')

    // 默认 ARGS + LOG → 请求体阶段
    expect(
      within(dialog).getByText(
        '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
      ),
    ).toBeInTheDocument()

    // 切换动作为 阻断（BLOCK）
    const actionSelect = dialog.querySelector('#action')!.closest('.ant-select')!
    fireEvent.mouseDown(actionSelect)
    const blockOption = await screen.findByText('阻断', {
      selector: '.ant-select-item-option-content',
    })
    fireEvent.click(blockOption)

    await waitFor(() => {
      const actionText = dialog
        .querySelector('#action')
        ?.closest('.ant-select')
        ?.querySelector('.ant-select-content')?.textContent
      expect(actionText).toBe('阻断')
    })

    // 仍保持请求体阶段
    expect(
      within(dialog).getByText(
        '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
      ),
    ).toBeInTheDocument()

    // 改为 REQUEST_BODY 后同样保持请求体阶段
    clearSelectedTargetVariables(dialog)
    await selectTargetVariable(dialog, '请求体')
    await waitFor(() => {
      expect(
        within(dialog).getByText(
          '自动生效时机：请求体阶段（支持检测 POST/JSON 请求体，优先于内置防护规则生效）',
        ),
      ).toBeInTheDocument()
    })
  })

  it('新建、校验与编辑提交均省略 phase 字段，由后端权威自动推导', async () => {
    const legacyRule = {
      ...RULE,
      id: 'cr-legacy',
      rule_id: 7100009,
      name: '历史阶段规则',
      phase: 3,
      target_variables: ['REQUEST_URI'],
    }
    vi.stubGlobal('fetch', mockFetch([legacyRule]))

    renderPage()
    await screen.findByText('历史阶段规则')

    // 1. 新建 + 校验
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    const createDialog = await screen.findByRole('dialog')
    const ruleIdInput = createDialog.querySelector<HTMLInputElement>('#rule_id')!
    fireEvent.change(ruleIdInput, { target: { value: '7100010' } })
    fireEvent.change(within(createDialog).getByPlaceholderText('如：拦截特定路径的SQL注入尝试'), {
      target: { value: '新建自动阶段规则' },
    })
    fireEvent.change(within(createDialog).getByPlaceholderText('如：(?i)(union.*select)'), {
      target: { value: '(?i)union' },
    })

    fireEvent.click(within(createDialog).getByRole('button', { name: /校验规则并预览 SecLang/ }))
    await waitFor(() => {
      const validateCall = (fetch as Mock).mock.calls.find(
        (c) =>
          (c[1] as RequestInit | undefined)?.method === 'POST' &&
          String(c[0]).endsWith('/custom-rules/new/validate'),
      )
      expect(validateCall).toBeTruthy()
      const body = JSON.parse(String((validateCall![1] as RequestInit).body))
      expect('phase' in body).toBe(false)
      expect(body.target_variables).toEqual(['ARGS'])
    })

    fireEvent.click(within(createDialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      const createCall = (fetch as Mock).mock.calls.find(
        (c) =>
          (c[1] as RequestInit | undefined)?.method === 'POST' &&
          String(c[0]).endsWith('/custom-rules'),
      )
      expect(createCall).toBeTruthy()
      const body = JSON.parse(String((createCall![1] as RequestInit).body))
      expect('phase' in body).toBe(false)
      expect(body.rule_id).toBe(7100010)
    })

    // 2. 编辑历史规则（原 phase=3，变量为 REQUEST_URI）：显示请求头阶段，校验与 PUT 均不回传旧 phase
    fireEvent.click(screen.getByRole('button', { name: '编辑' }))
    const editTitle = await screen.findByText('编辑规则：历史阶段规则')
    const editDialog = editTitle.closest('.ant-modal') as HTMLElement
    expect(editDialog).toBeTruthy()
    expect(
      within(editDialog).getByText('自动生效时机：请求头阶段（优先于内置防护规则生效）'),
    ).toBeInTheDocument()

    fireEvent.click(within(editDialog).getByRole('button', { name: /校验规则并预览 SecLang/ }))
    await waitFor(() => {
      const validateEditCall = (fetch as Mock).mock.calls.find(
        (c) =>
          (c[1] as RequestInit | undefined)?.method === 'POST' &&
          String(c[0]).endsWith('/custom-rules/cr-legacy/validate'),
      )
      expect(validateEditCall).toBeTruthy()
      const body = JSON.parse(String((validateEditCall![1] as RequestInit).body))
      expect('phase' in body).toBe(false)
    })

    fireEvent.click(within(editDialog).getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => {
      const putCall = (fetch as Mock).mock.calls.find(
        (c) =>
          (c[1] as RequestInit | undefined)?.method === 'PUT' &&
          String(c[0]).endsWith('/custom-rules/cr-legacy'),
      )
      expect(putCall).toBeTruthy()
      const body = JSON.parse(String((putCall![1] as RequestInit).body))
      expect('phase' in body).toBe(false)
      expect(body.version).toBe(1)
    })
  })

  it('检测变量、作用范围、操作符与执行阶段中文化展示（表单下拉与详情抽屉）', async () => {
    renderPage()
    await screen.findByText('Struts2 RCE 虚拟补丁')

    // 详情抽屉：检测变量 ARGS → 全部参数，作用范围 GLOBAL → 全局，操作符 rx → 正则匹配，执行阶段 2 → 阶段 2（请求体）
    fireEvent.click(screen.getByRole('button', { name: '详情' }))
    expect(await screen.findByText('全部参数')).toBeInTheDocument()
    expect(screen.getByText('全局')).toBeInTheDocument()
    expect(screen.getByText('正则匹配')).toBeInTheDocument()
    expect(screen.getByText('阶段 2（请求体）')).toBeInTheDocument()
    expect(screen.queryByText('GLOBAL')).not.toBeInTheDocument()

    // 新建弹窗：默认选中的检测变量 ARGS 显示为中文「全部参数」
    fireEvent.click(screen.getByRole('button', { name: /新建规则/ }))
    await waitFor(() => expect(document.querySelector('.ant-modal')).toBeTruthy())
    const modal = document.querySelector('.ant-modal') as HTMLElement
    expect(within(modal).getByText('全部参数')).toBeInTheDocument()
  })
})
