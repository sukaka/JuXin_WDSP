import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
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
    if (url.includes('/applications')) return ok({ items: [], total: 0, page: 1, page_size: 100 })
    if (url.includes('/protection-policies')) {
      return ok({ items: [], total: 0, page: 1, page_size: 100 })
    }
    const method = init?.method ?? 'GET'
    if (/\/exceptions\/[^/?]+/.test(url) && method === 'GET') {
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
    expect(disabledTexts.some((t) => t.includes('LOG_ONLY'))).toBe(true)
    expect(disabledTexts.some((t) => t.includes('ADJUST_SCORE'))).toBe(true)
    expect(disabledTexts.every((t) => t.includes('不支持新启用'))).toBe(true)
    const enabled = document.querySelectorAll(
      '.ant-select-item-option:not(.ant-select-item-option-disabled)',
    )
    const enabledTexts = Array.from(enabled).map((o) => o.textContent ?? '')
    expect(enabledTexts.some((t) => t.includes('REMOVE_RULE'))).toBe(true)
    expect(enabledTexts.some((t) => t.includes('OBSERVE_RULE'))).toBe(false)
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

    // 添加一条规则引用：detector_id 下拉（受支持注册表）+ rule_id + model_version(可空)
    fireEvent.click(screen.getByRole('button', { name: /添加规则引用/ }))
    expect(await screen.findByPlaceholderText('rule_id（稳定规则标识）')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('model_version（可空）')).toBeInTheDocument()

    fireEvent.mouseDown(selectOfFormItem('例外动作'))
    const options = Array.from(
      document.querySelectorAll('.ant-select-item-option-content'),
    ).map((o) => o.textContent ?? '')
    expect(options.some((t) => t.includes('OBSERVE_RULE'))).toBe(true)
    expect(options.some((t) => t.includes('REMOVE_RULE'))).toBe(false)
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
      await screen.findByText('该例外待审查（NEEDS_REVIEW），达标前禁止启用'),
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
    expect(screen.getByText(/改为 REMOVE_VAR_DETECTION 精确目标排除/)).toBeInTheDocument()
    expect(
      screen.getByText('校验状态：待审查（NEEDS_REVIEW），达标前禁止启用'),
    ).toBeInTheDocument()
  })
})
