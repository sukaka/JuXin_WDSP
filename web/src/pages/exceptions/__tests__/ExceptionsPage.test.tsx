import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ExceptionsPage from '../ExceptionsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser, ExceptionItem } from '../../../types'

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function makeException(overrides: Partial<ExceptionItem> = {}): ExceptionItem {
  return {
    id: 'exc-1',
    name: '订单导出误报豁免',
    description: '',
    scope_type: 'APPLICATION',
    application_id: 'app-1',
    policy_id: null,
    domain: 'shop.example.com',
    uri_exact: '/api/orders/export',
    uri_prefix: '',
    uri_regex: '',
    methods: ['POST'],
    source_ips: [],
    param_names: [],
    cookie_names: [],
    header_names: [],
    rule_ids: [942100],
    rule_tags: [],
    attack_types: [],
    content_types: [],
    exception_action: 'REMOVE_RULE',
    action_target: '',
    is_temporary: false,
    effective_from: null,
    effective_until: null,
    status: 'DISABLED',
    risk_acknowledged: false,
    reason: '误报评估通过',
    version: 2,
    target_engine: 'WAF',
    validation_status: 'VALID',
    ...overrides,
  }
}

/** S4 §8 契约形状的预览响应（estimated_match_count=null 表示无法估算） */
const PREVIEW_RESULT = {
  validation_status: 'VALID',
  field_errors: [],
  normalized_scope: {
    domain: 'shop.example.com',
    uri_exact: '/api/orders/export',
    methods: ['POST'],
    source_ips: [],
    content_types: [],
  },
  resolved_rule_refs: [{ engine: 'WAF', rule_id: 942100 }],
  effective_window: { from: null, until: null, half_open: true },
  unsupported: [],
  protected_modules_unchanged: ['JWT', 'ACCESS_CONTROL', 'CC'],
  compiled_fingerprint: 'a'.repeat(64),
  required_publish_targets: ['shop'],
  historical_sample_coverage: null,
  estimated_match_count: null,
}

function mockFetch({
  list = [makeException()],
  detail = makeException(),
  preview = PREVIEW_RESULT,
}: {
  list?: ExceptionItem[]
  detail?: ExceptionItem
  preview?: unknown
} = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/preview')) return ok(preview)
    if (url.includes('/enable') && init?.method === 'POST') {
      return ok({ exception: { ...detail, status: 'ENABLED' } })
    }
    if (url.includes('/gateway-config/publish') && init?.method === 'POST') {
      return ok({ id: 'task-pub-1', status: 'SUCCESS', result_summary: 'published' })
    }
    if (url.includes('/applications')) return ok({ items: [], total: 0, page: 1, page_size: 100 })
    if (url.includes('/protection-policies')) {
      return ok({ items: [], total: 0, page: 1, page_size: 100 })
    }
    const method = init?.method ?? 'GET'
    if (/\/exceptions\/[^/?]+/.test(url) && method === 'GET') {
      return ok({ exception: detail, is_broad: false })
    }
    if (url.includes('/exceptions') && method === 'POST') {
      return ok({ exception: detail, is_broad: false })
    }
    if (url.includes('/exceptions')) {
      return ok({ items: list, total: list.length, page: 1, page_size: 20 })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <ExceptionsPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 按表单 label 找到对应 Select 根元素（antd v6 结构：鼠标事件落在 .ant-select 根节点） */
function selectOfFormItem(label: string): HTMLElement {
  const items = Array.from(document.querySelectorAll('.ant-form-item'))
  const item = items.find((it) =>
    it.querySelector('.ant-form-item-label label')?.textContent?.includes(label),
  )
  const select = item?.querySelector('.ant-select')
  if (!select) throw new Error(`form item ${label} 缺少 select`)
  return select as HTMLElement
}

describe('ExceptionsPage（P0-04）', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['exceptions.read', 'exceptions.manage']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('WAF 引擎：动作下拉中 LOG_ONLY/ADJUST_SCORE 为「不支持新启用」禁用项，REMOVE_* 可选', async () => {
    renderPage()
    await screen.findByText('订单导出误报豁免')
    fireEvent.click(screen.getByRole('button', { name: /新建例外/ }))
    await screen.findByText('规则与字段')

    fireEvent.mouseDown(selectOfFormItem('例外动作'))
    const disabled = document.querySelectorAll('.ant-select-item-option-disabled')
    const disabledTexts = Array.from(disabled).map((o) => o.textContent ?? '')
    expect(disabledTexts.some((t) => t.includes('仅记录不阻断'))).toBe(true)
    expect(disabledTexts.some((t) => t.includes('调整异常评分'))).toBe(true)
    expect(disabledTexts.every((t) => t.includes('不支持新启用'))).toBe(true)
    const enabled = document.querySelectorAll(
      '.ant-select-item-option:not(.ant-select-item-option-disabled)',
    )
    const enabledTexts = Array.from(enabled).map((o) => o.textContent ?? '')
    expect(enabledTexts.some((t) => t.includes('移除指定规则'))).toBe(true)
    expect(enabledTexts.some((t) => t.includes('API 规则仅观察'))).toBe(false)
  })

  it('切换 target_engine=API：动作仅 OBSERVE_RULE，规则引用编辑为 detector_id + rule_id + model_version', async () => {
    renderPage()
    await screen.findByText('订单导出误报豁免')
    fireEvent.click(screen.getByRole('button', { name: /新建例外/ }))
    await screen.findByText('规则与字段')

    fireEvent.mouseDown(selectOfFormItem('目标引擎'))
    const apiOption = Array.from(
      document.querySelectorAll('.ant-select-item-option-content'),
    ).find((o) => o.textContent?.includes('API（动态防护）'))
    expect(apiOption).toBeTruthy()
    fireEvent.click(apiOption as HTMLElement)

    // 动作被重置为 OBSERVE_RULE，WAF 专属字段隐藏，API 规则引用编辑器出现
    await screen.findByText('API 规则引用')
    expect(screen.queryByText('规则ID')).not.toBeInTheDocument()

    // 添加一条规则引用：检测器下拉（中文）+ 规则标识 + 模型版本（可选）
    fireEvent.click(screen.getByRole('button', { name: /添加规则引用/ }))
    expect(await screen.findByPlaceholderText('规则标识')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('模型版本（可选）')).toBeInTheDocument()

    fireEvent.mouseDown(selectOfFormItem('例外动作'))
    const options = Array.from(
      document.querySelectorAll('.ant-select-item-option-content'),
    ).map((o) => o.textContent ?? '')
    expect(options.some((t) => t.includes('API 规则仅观察'))).toBe(true)
    expect(options.some((t) => t.includes('移除指定规则'))).toBe(false)
  })

  it('派生状态：ENABLED 且无发布/节点数据时显示「未发布/未知」，不假装全节点一致', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ list: [makeException({ status: 'ENABLED', validation_status: 'VALID' })] }),
    )
    renderPage()
    expect(await screen.findByText('未发布/未知')).toBeInTheDocument()
    expect(screen.queryByText('部分节点生效')).not.toBeInTheDocument()
  })

  it('NEEDS_REVIEW 记录：列表醒目标记 + 「启用」按钮禁用，详情列出 unsupported_reasons', async () => {
    const record = makeException({
      status: 'DISABLED',
      validation_status: 'NEEDS_REVIEW',
      unsupported_reasons: ['历史 LOG_ONLY 动作需迁移为精确目标排除', '缺少目标应用绑定'],
    })
    vi.stubGlobal('fetch', mockFetch({ list: [record], detail: record }))
    renderPage()

    expect(await screen.findByText('待审查')).toBeInTheDocument()
    const enableBtn = screen.getByRole('button', { name: '启用' })
    expect(enableBtn).toBeDisabled()

    fireEvent.click(screen.getByText('订单导出误报豁免'))
    expect(
      await screen.findByText('该例外待审查，达标前禁止启用'),
    ).toBeInTheDocument()
    expect(screen.getByText('历史 LOG_ONLY 动作需迁移为精确目标排除')).toBeInTheDocument()
    expect(screen.getByText('缺少目标应用绑定')).toBeInTheDocument()
  })

  it('影响预览：展示契约字段；estimated_match_count=null 显示「无法估算」而非 0', async () => {
    const record = makeException()
    vi.stubGlobal('fetch', mockFetch({ list: [record], detail: record }))
    renderPage()

    fireEvent.click(await screen.findByText('订单导出误报豁免'))
    fireEvent.click(await screen.findByRole('button', { name: '影响预览' }))

    expect(await screen.findByText('规范化范围')).toBeInTheDocument()
    expect(screen.getByText('WAF 942100')).toBeInTheDocument()
    expect(screen.getByText('预估影响请求数')).toBeInTheDocument()
    expect(screen.getByText('无法估算（历史样本不足）')).toBeInTheDocument()
    expect(screen.getByText('不受例外影响的防护模块')).toBeInTheDocument()
    expect(screen.getByText('JWT 信任链')).toBeInTheDocument()
    expect(screen.getByText('a'.repeat(64))).toBeInTheDocument()
    // null 估算禁止显示为 0：预估行只含「无法估算」文案，无任何数字
    const labelEl = screen.getByText('预估影响请求数') as HTMLElement
    let row: HTMLElement | null = labelEl
    while (row && !row.textContent?.includes('无法估算')) {
      row = row.parentElement
    }
    expect(row).toBeTruthy()
    expect(row!.textContent).toBe('预估影响请求数无法估算（历史样本不足）')
  })

  it('影响预览：unsupported 项展示迁移预览说明', async () => {
    const record = makeException()
    vi.stubGlobal(
      'fetch',
      mockFetch({
        list: [record],
        detail: record,
        preview: {
          ...PREVIEW_RESULT,
          validation_status: 'NEEDS_REVIEW',
          unsupported: [
            {
              field_or_action: 'LOG_ONLY',
              migration_preview: '改为 REMOVE_VAR_DETECTION 精确目标排除',
            },
          ],
        },
      }),
    )
    renderPage()

    fireEvent.click(await screen.findByText('订单导出误报豁免'))
    fireEvent.click(await screen.findByRole('button', { name: '影响预览' }))

    expect(await screen.findByText('不支持项（需迁移）')).toBeInTheDocument()
    expect(screen.getByText('仅记录不阻断')).toBeInTheDocument()
    expect(screen.getByText(/改为 REMOVE_VAR_DETECTION 精确目标排除/)).toBeInTheDocument()
    expect(
      screen.getByText('校验状态：待审查，达标前禁止启用'),
    ).toBeInTheDocument()
  })

  it('B4-03：仅填写 uri_regex（非宽泛）也渲染并要求勾选 risk_acknowledged', async () => {
    renderPage()
    await screen.findByText('订单导出误报豁免')
    fireEvent.click(screen.getByRole('button', { name: /新建例外/ }))
    const dialog = await screen.findByRole('dialog')

    fireEvent.change(within(dialog).getByPlaceholderText('如：管理后台导出 API 误报豁免'), {
      target: { value: '正则例外' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如 api.example.com（可选）'), {
      target: { value: 'shop.example.com' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('^/api/v\\d+/export$'), {
      target: { value: '^/api/v\\d+/export$' },
    })
    // 选择 HTTP 方法
    fireEvent.mouseDown(selectOfFormItem('HTTP 方法'))
    const getOpt = Array.from(document.querySelectorAll('.ant-select-item-option-content')).find(
      (o) => o.textContent === 'GET',
    )
    fireEvent.click(getOpt as HTMLElement)
    fireEvent.change(within(dialog).getByPlaceholderText('说明误报原因与评估结论'), {
      target: { value: '动态路径需要正则' },
    })

    // 非宽泛（已填 domain）仍应显示 risk_acknowledged 复选框
    const ackCheckbox = await within(dialog).findByRole('checkbox', {
      name: /我已知晓路径正则属于历史\/高级配置的风险/,
    })
    expect(ackCheckbox).not.toBeChecked()

    // 未勾选时点击保存草稿应被前端拦截
    fireEvent.click(within(dialog).getByRole('button', { name: /保存草稿/ }))
    expect(
      await within(dialog).findByText('路径正则属于高级配置，必须确认风险后才能保存'),
    ).toBeInTheDocument()
    const postsBefore = (fetch as Mock).mock.calls.filter(
      (c) => String(c[0]).endsWith('/exceptions') && (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(postsBefore).toHaveLength(0)

    // 勾选后提交成功并携带 risk_acknowledged: true
    fireEvent.click(ackCheckbox)
    fireEvent.click(within(dialog).getByRole('button', { name: /保存草稿/ }))
    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) => String(c[0]).endsWith('/exceptions') && (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
      const body = JSON.parse(String((post![1] as RequestInit).body))
      expect(body.uri_regex).toBe('^/api/v\\d+/export$')
      expect(body.risk_acknowledged).toBe(true)
    })
  })

  it('B4-05：状态筛选包含「草稿 (DRAFT)」且详情原始状态正确渲染草稿标签', async () => {
    const draftRecord = makeException({ status: 'DRAFT', validation_status: 'VALID' })
    vi.stubGlobal('fetch', mockFetch({ list: [draftRecord], detail: draftRecord }))
    renderPage()
    await screen.findByText('订单导出误报豁免')

    // 状态筛选下拉包含「草稿」
    const statusCombo = screen.getAllByRole('combobox').find((el) =>
      el.closest('.ant-select')?.textContent?.includes('状态'),
    )
    expect(statusCombo).toBeTruthy()
    fireEvent.mouseDown(statusCombo as HTMLElement)
    const draftOption = await screen.findByTitle('草稿')
    fireEvent.click(draftOption)
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((c) => String(c[0]).includes('status=DRAFT')),
      ).toBe(true)
    })

    // 详情中原始状态渲染「草稿」而非原始字符串 DRAFT
    fireEvent.click(await screen.findByText('订单导出误报豁免'))
    const drawer = await screen.findByRole('dialog')
    const statusLabel = await within(drawer).findByText('原始状态')
    expect(statusLabel.closest('th')?.nextElementSibling?.textContent).toBe('草稿')
    expect(within(drawer).queryByText('DRAFT')).not.toBeInTheDocument()
  })

  it('B4-06：影响预览展示 normalized_scope.uri_regex 并兼容可空数组字段', async () => {
    const record = makeException({ uri_exact: '', uri_regex: '^/api/v\\d+/export$' })
    vi.stubGlobal(
      'fetch',
      mockFetch({
        list: [record],
        detail: record,
        preview: {
          ...PREVIEW_RESULT,
          field_errors: null,
          resolved_rule_refs: null,
          unsupported: null,
          normalized_scope: {
            domain: 'shop.example.com',
            uri_regex: '^/api/v\\d+/export$',
            methods: ['POST'],
            source_ips: null,
            content_types: null,
          },
        },
      }),
    )
    renderPage()
    fireEvent.click(await screen.findByText('订单导出误报豁免'))
    fireEvent.click(await screen.findByRole('button', { name: '影响预览' }))

    expect(await screen.findByText('正则 ^/api/v\\d+/export$')).toBeInTheDocument()
  })

  it('B4-09：启用例外兼容 { exception } 返回体并完成状态刷新', async () => {
    renderPage()
    await screen.findByText('订单导出误报豁免')

    fireEvent.click(screen.getByRole('button', { name: '启用' }))
    expect(await screen.findByText('操作成功')).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) => String(c[0]).includes('/exceptions/exc-1/enable') && (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(true)
  })

  it('无 gateway_configs.publish 权限时不展示「发布到网关」按钮', async () => {
    renderPage()
    await screen.findByText('订单导出误报豁免')
    expect(screen.queryByRole('button', { name: /发布到网关/ })).not.toBeInTheDocument()
  })

  it('具备 gateway_configs.publish 权限时可原地点击「发布到网关」下发配置', async () => {
    useAuthStore.setState({
      user: makeUser(['exceptions.read', 'exceptions.manage', 'gateway_configs.publish']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    renderPage()
    await screen.findByText('订单导出误报豁免')

    fireEvent.click(screen.getByRole('button', { name: /发布到网关/ }))
    const confirmBtn = await screen.findByRole('button', { name: '确认发布' })
    expect(screen.getAllByText('发布到网关确认').length).toBeGreaterThan(0)
    fireEvent.click(confirmBtn)

    expect(await screen.findByText('网关配置发布成功，例外策略已生效')).toBeInTheDocument()
    expect(
      (fetch as Mock).mock.calls.some(
        (c) =>
          String(c[0]).includes('/gateway-config/publish') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      ),
    ).toBe(true)
  })

  it('例外详情与影响预览展示生成的 SecLang 规则原文', async () => {
    const sampleSecLang =
      'SecRule REQUEST_FILENAME "@streq /api/orders/export" "id:8000001,phase:1,pass,nolog,setvar:tx.jz_exc_8000001=1"\nSecRule TX:jz_exc_8000001 "@eq 1" "id:8000002,phase:1,pass,log,tag:\'jiuzhang-exception\',ctl:ruleRemoveById=942100"'
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const ok = (data: unknown) =>
          Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/preview')) {
          return ok({ ...PREVIEW_RESULT, generated_seclang: sampleSecLang })
        }
        if (url.includes('/applications') || url.includes('/protection-policies')) {
          return ok({ items: [], total: 0, page: 1, page_size: 100 })
        }
        const method = init?.method ?? 'GET'
        if (/\/exceptions\/[^/?]+/.test(url) && method === 'GET') {
          return ok({ exception: makeException(), is_broad: false, generated_seclang: sampleSecLang })
        }
        if (url.includes('/exceptions')) {
          return ok({ items: [makeException()], total: 1, page: 1, page_size: 20 })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )

    renderPage()
    fireEvent.click(await screen.findByText('订单导出误报豁免'))
    expect(await screen.findByText('生成的 SecLang 规则（两规则标记法）')).toBeInTheDocument()
    expect(screen.getByText(/ctl:ruleRemoveById=942100/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: '影响预览' }))
    expect(await screen.findByText('预览生成的 SecLang')).toBeInTheDocument()
  })
})
