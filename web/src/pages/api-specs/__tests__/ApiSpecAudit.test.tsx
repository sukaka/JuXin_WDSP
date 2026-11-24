import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiSpecsPage from '../ApiSpecsPage'
import { specAuditCSV } from '../specAuditExport'
import type { ApiSpecAudit } from '../../../api/apiSecurity'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

vi.mock('../specAuditExport', () => ({ specAuditCSV: vi.fn() }))

const user: CurrentUser = {
  id: 'u1',
  username: 'reader',
  display_name: '规范查看员',
  status: 'ACTIVE',
  roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
  permissions: ['api_spec.read'],
  must_change_password: false,
}

const specs = [
  {
    id: 'spec-v1',
    name: 'payment-api',
    version_no: 1,
    status: 'HISTORICAL',
    format: 'openapi3',
    file_name: 'payment-v1.json',
    content_hash: 'aaaaaa1234567890',
    endpoint_count: 3,
    imported_by: null,
    created_at: '2026-07-01T03:00:00Z',
  },
  {
    id: 'spec-v2',
    name: 'payment-api',
    version_no: 2,
    status: 'ACTIVE',
    format: 'openapi3',
    file_name: 'payment-v2.json',
    content_hash: 'bbbbbb1234567890',
    endpoint_count: 4,
    imported_by: null,
    created_at: '2026-07-21T03:00:00Z',
  },
]

function makeAudit(
  specId: string,
  overrides: Partial<ApiSpecAudit> = {},
): ApiSpecAudit {
  return {
    spec_id: specId,
    format: 'openapi3',
    operation_count: 1,
    issue_count: 1,
    high_count: 1,
    medium_count: 0,
    items: [
      {
        rule_id: 'PATH_PARAMETER_MISSING',
        severity: 'HIGH',
        endpoint_key: 'GET /v1/users/{user_id}',
        param_in: 'path',
        param_name: 'user_id',
        message: `${specId} 审计结果`,
      },
    ],
    truncated: false,
    ...overrides,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

let auditResponses: Record<string, { status: number; body: unknown }>
let auditCalls: Array<{ id: string; method: string }>
let listedSpecs = specs
const clickedLinks: HTMLAnchorElement[] = []
const createObjectURLMock = vi.fn<(blob: Blob) => string>()
const revokeObjectURLMock = vi.fn<(url: string) => void>()
const auditCSV = '规则,严重级别\n路径参数缺失,高\n'

function success(data: unknown) {
  return { status: 200, body: { code: 'SUCCESS', message: 'ok', data } }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiSpecsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function openAudit(row = 0): Promise<HTMLElement> {
  await screen.findAllByText('payment-api')
  fireEvent.click(screen.getAllByRole('button', { name: '规范审计' })[row])
  return screen.findByRole('dialog')
}

async function closeAudit(drawer: HTMLElement) {
  fireEvent.click(within(drawer).getByRole('button', { name: 'Close' }))
  await waitFor(() => expect(drawer).not.toBeInTheDocument())
}

function expectStatistic(drawer: HTMLElement, title: string, value: number) {
  const statistic = within(drawer)
    .getByText(title, { selector: '.ant-statistic-title' })
    .closest('.ant-statistic')
  expect(statistic).toHaveTextContent(String(value))
}

describe('ApiSpecsPage 规范审计', () => {
  beforeEach(() => {
    useAuthStore.setState({ user, csrfToken: null, initialized: true })
    vi.mocked(specAuditCSV).mockReset().mockReturnValue(auditCSV)
    createObjectURLMock.mockReset().mockReturnValue('blob:api-spec-audit')
    revokeObjectURLMock.mockReset()
    clickedLinks.length = 0
    const NativeURL = URL
    vi.stubGlobal(
      'URL',
      class extends NativeURL {
        static createObjectURL = createObjectURLMock
        static revokeObjectURL = revokeObjectURLMock
      },
    )
    vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clickedLinks.push(this)
    })
    listedSpecs = specs
    auditCalls = []
    auditResponses = {
      'spec-v1': success(makeAudit('spec-v1')),
      'spec-v2': success(makeAudit('spec-v2')),
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const auditMatch = url.match(
          /^\/api\/v1\/api-security\/specs\/([^/]+)\/audit$/,
        )
        if (auditMatch) {
          const id = auditMatch[1]
          auditCalls.push({ id, method: init?.method ?? 'GET' })
          const response = auditResponses[id]
          if (!response)
            return Promise.reject(new Error(`unexpected audit: ${id}`))
          return Promise.resolve(jsonResponse(response.status, response.body))
        }
        if (url.startsWith('/api/v1/api-security/specs?')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: listedSpecs,
                page: 1,
                page_size: 20,
                total: listedSpecs.length,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('真实查询当前版本并展示统计、规则中文映射和完整明细', async () => {
    auditResponses['spec-v1'] = success(
      makeAudit('spec-v1', {
        operation_count: 4,
        issue_count: 6,
        high_count: 3,
        medium_count: 3,
        items: [
          {
            rule_id: 'PATH_PARAMETER_MISSING',
            severity: 'HIGH',
            endpoint_key: 'GET /v1/users/{user_id}',
            param_in: 'path',
            param_name: 'user_id',
            message: '路径参数 user_id 缺少定义',
          },
          {
            rule_id: 'PATH_PARAMETER_NOT_REQUIRED',
            severity: 'MEDIUM',
            endpoint_key: 'GET /v1/orders/{order_id}',
            param_in: 'path',
            param_name: 'order_id',
            message: '路径参数 order_id 必须设为必填',
          },
          {
            rule_id: 'PATH_PARAMETER_UNDECLARED',
            severity: 'HIGH',
            endpoint_key: 'GET /v1/tenants/{tenant_id}',
            param_in: 'path',
            param_name: 'tenant_id',
            message: '路径模板包含未声明参数 tenant_id',
          },
          {
            rule_id: 'SENSITIVE_QUERY_PARAMETER',
            severity: 'MEDIUM',
            endpoint_key: 'GET /v1/session',
            param_in: 'query',
            param_name: 'access_token',
            message: '敏感参数不应通过 URL 查询字符串传递',
          },
          {
            rule_id: 'SUCCESS_RESPONSE_MISSING',
            severity: 'HIGH',
            endpoint_key: 'GET /v1/users',
            param_in: '',
            param_name: '',
            message: '缺少明确 2xx 成功响应声明',
          },
          {
            rule_id: 'ERROR_RESPONSE_MISSING',
            severity: 'MEDIUM',
            endpoint_key: 'POST /v1/orders',
            param_in: '',
            param_name: '',
            message: '缺少 default/4xx/5xx 错误响应声明',
          },
        ],
      }),
    )
    renderPage()
    const drawer = await openAudit()

    expect(await within(drawer).findByText('路径参数缺失')).toBeInTheDocument()
    expect(within(drawer).getByText('路径参数未标记必填')).toBeInTheDocument()
    expect(within(drawer).getByText('路径参数未声明')).toBeInTheDocument()
    expect(within(drawer).getByText('敏感查询参数')).toBeInTheDocument()
    expect(within(drawer).getByText('成功响应未声明')).toBeInTheDocument()
    expect(within(drawer).getByText('错误响应未声明')).toBeInTheDocument()
    expect(
      within(drawer).queryByText('PATH_PARAMETER_MISSING'),
    ).not.toBeInTheDocument()
    expect(within(drawer).getAllByRole('cell', { name: '高' })).toHaveLength(3)
    expect(within(drawer).getAllByRole('cell', { name: '中' })).toHaveLength(3)
    expect(within(drawer).getAllByText('路径参数')).toHaveLength(3)
    expect(within(drawer).getByText('查询参数')).toBeInTheDocument()
    expect(
      within(drawer).getByText('GET /v1/users/{user_id}'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('user_id')).toBeInTheDocument()
    expect(within(drawer).getByText('access_token')).toBeInTheDocument()
    expect(
      within(drawer).getByText('敏感参数不应通过 URL 查询字符串传递'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('GET /v1/users')).toBeInTheDocument()
    expect(within(drawer).getByText('POST /v1/orders')).toBeInTheDocument()
    expect(
      within(drawer).getByText('缺少明确 2xx 成功响应声明'),
    ).toBeInTheDocument()
    expect(
      within(drawer).getByText('缺少 default/4xx/5xx 错误响应声明'),
    ).toBeInTheDocument()
    expectStatistic(drawer, '操作数', 4)
    expectStatistic(drawer, '问题数', 6)
    expectStatistic(drawer, '高危问题', 3)
    expectStatistic(drawer, '中危问题', 3)
    expect(auditCalls).toEqual([{ id: 'spec-v1', method: 'GET' }])
    const request = vi
      .mocked(fetch)
      .mock.calls.find(([input]) =>
        String(input).endsWith('/specs/spec-v1/audit'),
      )
    expect(request?.[1]?.body).toBeUndefined()
  })

  it('展示认证方案未定义与查询参数传递 API Key 的真实明细', async () => {
    auditResponses['spec-v1'] = success(
      makeAudit('spec-v1', {
        operation_count: 2,
        issue_count: 2,
        high_count: 2,
        medium_count: 0,
        items: [
          {
            rule_id: 'SECURITY_SCHEME_UNDEFINED',
            severity: 'HIGH',
            endpoint_key: 'GET /v1/orders/{order_id}',
            param_in: 'SECURITY',
            param_name: 'bearerAuth',
            message: '操作引用的认证方案 bearerAuth 未定义',
          },
          {
            rule_id: 'API_KEY_IN_QUERY',
            severity: 'HIGH',
            endpoint_key: 'POST /v1/orders',
            param_in: 'QUERY',
            param_name: 'api_key',
            message: '认证方案 apiKeyQuery 通过查询参数 api_key 传递 API Key',
          },
        ],
      }),
    )
    renderPage()
    const drawer = await openAudit()

    expect(
      await within(drawer).findByText('认证方案未定义'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('查询参数传递 API Key')).toBeInTheDocument()
    expect(within(drawer).getAllByRole('cell', { name: '高' })).toHaveLength(2)
    expect(within(drawer).getByText('认证方案')).toBeInTheDocument()
    expect(within(drawer).getByText('查询参数')).toBeInTheDocument()
    expect(
      within(drawer).getByText('GET /v1/orders/{order_id}'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('POST /v1/orders')).toBeInTheDocument()
    expect(within(drawer).getByText('bearerAuth')).toBeInTheDocument()
    expect(within(drawer).getByText('api_key')).toBeInTheDocument()
    expect(
      within(drawer).getByText('操作引用的认证方案 bearerAuth 未定义'),
    ).toBeInTheDocument()
    expect(
      within(drawer).getByText(
        '认证方案 apiKeyQuery 通过查询参数 api_key 传递 API Key',
      ),
    ).toBeInTheDocument()
  })

  it('导出当前结果调用纯函数并下载 UTF-8 CSV', async () => {
    const audit = makeAudit('spec-v1')
    auditResponses['spec-v1'] = success(audit)
    renderPage()
    const drawer = await openAudit()
    expect(
      await within(drawer).findByText('spec-v1 审计结果'),
    ).toBeInTheDocument()
    const exportButton = within(drawer).getByRole('button', {
      name: '导出当前结果',
    })
    await waitFor(() => expect(exportButton).toBeEnabled())

    fireEvent.click(exportButton)

    expect(specAuditCSV).toHaveBeenCalledTimes(1)
    expect(specAuditCSV).toHaveBeenCalledWith(audit)
    expect(createObjectURLMock).toHaveBeenCalledTimes(1)
    const blob = createObjectURLMock.mock.calls[0][0]
    expect(blob).toBeInstanceOf(Blob)
    expect(blob.type).toBe('text/csv;charset=utf-8')
    const content = await new Promise<string>((resolve, reject) => {
      const reader = new FileReader()
      reader.onload = () => resolve(reader.result as string)
      reader.onerror = () => reject(reader.error)
      reader.readAsText(blob)
    })
    expect(content).toBe(auditCSV)
    expect(clickedLinks[0]?.href).toBe('blob:api-spec-audit')
    expect(clickedLinks[0]?.download).toBe('api-spec-audit-payment-api-v1.csv')
    expect(clickedLinks[0]?.isConnected).toBe(false)
    expect(revokeObjectURLMock).toHaveBeenCalledWith('blob:api-spec-audit')
  })

  it('导出文件名清理路径字符并限制规范名称长度', async () => {
    listedSpecs = [
      {
        ...specs[0],
        name: `../payment\\api/*?${'长'.repeat(100)}`,
        version_no: 7,
      },
      specs[1],
    ]
    renderPage()
    const drawer = await openAudit()
    expect(
      await within(drawer).findByText('spec-v1 审计结果'),
    ).toBeInTheDocument()
    const exportButton = within(drawer).getByRole('button', {
      name: '导出当前结果',
    })
    await waitFor(() => expect(exportButton).toBeEnabled())

    fireEvent.click(exportButton)

    expect(clickedLinks[0]?.download).toContain('payment_api')
    expect(clickedLinks[0]?.download).toContain('-v7.csv')
    expect(clickedLinks[0]?.download).not.toMatch(/[\\/]/)
    expect(clickedLinks[0]?.download.length).toBeLessThanOrEqual(110)
  })

  it('仅含响应声明规则时展示严重级别、接口键和说明', async () => {
    auditResponses['spec-v1'] = success(
      makeAudit('spec-v1', {
        operation_count: 2,
        issue_count: 2,
        high_count: 1,
        medium_count: 1,
        items: [
          {
            rule_id: 'SUCCESS_RESPONSE_MISSING',
            severity: 'HIGH',
            endpoint_key: 'GET /v1/health',
            param_in: '',
            param_name: '',
            message: '缺少明确 2xx 成功响应声明',
          },
          {
            rule_id: 'ERROR_RESPONSE_MISSING',
            severity: 'MEDIUM',
            endpoint_key: 'POST /v1/payments',
            param_in: '',
            param_name: '',
            message: '缺少 default/4xx/5xx 错误响应声明',
          },
        ],
      }),
    )
    renderPage()
    const drawer = await openAudit()

    expect(
      await within(drawer).findByText('成功响应未声明'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('错误响应未声明')).toBeInTheDocument()
    expect(within(drawer).getByRole('cell', { name: '高' })).toBeVisible()
    expect(within(drawer).getByRole('cell', { name: '中' })).toBeVisible()
    expect(within(drawer).getByText('GET /v1/health')).toBeInTheDocument()
    expect(within(drawer).getByText('POST /v1/payments')).toBeInTheDocument()
    expect(
      within(drawer).getByText('缺少明确 2xx 成功响应声明'),
    ).toBeInTheDocument()
    expect(
      within(drawer).getByText('缺少 default/4xx/5xx 错误响应声明'),
    ).toBeInTheDocument()
  })

  it('空结果显示明确空态且禁用导出，不填充演示明细', async () => {
    auditResponses['spec-v1'] = success(
      makeAudit('spec-v1', {
        operation_count: 3,
        issue_count: 0,
        high_count: 0,
        medium_count: 0,
        items: [],
      }),
    )
    renderPage()
    const drawer = await openAudit()

    expect(
      await within(drawer).findByText('未发现本批规则问题'),
    ).toBeInTheDocument()
    expect(
      within(drawer).queryByText('spec-v1 审计结果'),
    ).not.toBeInTheDocument()
    expectStatistic(drawer, '问题数', 0)
    const exportButton = within(drawer).getByRole('button', {
      name: '导出当前结果',
    })
    expect(exportButton).toBeDisabled()
    fireEvent.click(exportButton)
    expect(specAuditCSV).not.toHaveBeenCalled()
    expect(createObjectURLMock).not.toHaveBeenCalled()
  })

  it('truncated 为真时提示仅导出当前已返回明细', async () => {
    auditResponses['spec-v1'] = success(
      makeAudit('spec-v1', { issue_count: 650, truncated: true }),
    )
    renderPage()
    const drawer = await openAudit()

    expect(
      await within(drawer).findByText(
        '问题明细较多，只展示前 500 条；导出仅包含当前已返回明细',
      ),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('spec-v1 审计结果')).toBeInTheDocument()
    const exportButton = within(drawer).getByRole('button', {
      name: '导出当前结果',
    })
    await waitFor(() => expect(exportButton).toBeEnabled())
    fireEvent.click(exportButton)
    expect(specAuditCSV).toHaveBeenCalledWith(
      expect.objectContaining({ spec_id: 'spec-v1', truncated: true }),
    )
  })

  it('查询失败展示后端错误，禁用导出且不显示空结果或旧明细', async () => {
    auditResponses['spec-v1'] = {
      status: 500,
      body: { code: 'INTERNAL_ERROR', message: '审计服务暂不可用', data: null },
    }
    renderPage()
    const drawer = await openAudit()

    expect(
      await within(drawer).findByText('规范审计加载失败'),
    ).toBeInTheDocument()
    expect(within(drawer).getByText('审计服务暂不可用')).toBeInTheDocument()
    expect(
      within(drawer).queryByText('未发现本批规则问题'),
    ).not.toBeInTheDocument()
    expect(
      within(drawer).queryByText('spec-v1 审计结果'),
    ).not.toBeInTheDocument()
    const exportButton = within(drawer).getByRole('button', {
      name: '导出当前结果',
    })
    expect(exportButton).toBeDisabled()
    fireEvent.click(exportButton)
    expect(specAuditCSV).not.toHaveBeenCalled()
    expect(createObjectURLMock).not.toHaveBeenCalled()
  })

  it('版本切换加载期间禁用导出，返回后只导出当前版本', async () => {
    renderPage()
    const firstDrawer = await openAudit(0)
    expect(
      await within(firstDrawer).findByText('spec-v1 审计结果'),
    ).toBeInTheDocument()
    await closeAudit(firstDrawer)

    let resolveV2!: (response: Response) => void
    const pendingV2 = new Promise<Response>((resolve) => {
      resolveV2 = resolve
    })
    const fetchImplementation = vi.mocked(fetch).getMockImplementation()
    vi.mocked(fetch).mockImplementation((input, init) => {
      if (String(input).endsWith('/specs/spec-v2/audit')) return pendingV2
      return (
        fetchImplementation?.(input, init) ??
        Promise.reject(new Error('missing fetch implementation'))
      )
    })

    const secondDrawer = await openAudit(1)
    const exportButton = within(secondDrawer).getByRole('button', {
      name: '导出当前结果',
    })
    expect(exportButton).toBeDisabled()
    fireEvent.click(exportButton)
    expect(specAuditCSV).not.toHaveBeenCalled()
    expect(createObjectURLMock).not.toHaveBeenCalled()

    resolveV2(jsonResponse(200, success(makeAudit('spec-v2')).body))
    expect(
      await within(secondDrawer).findByText('spec-v2 审计结果'),
    ).toBeInTheDocument()
    await waitFor(() => expect(exportButton).toBeEnabled())
    fireEvent.click(exportButton)

    expect(specAuditCSV).toHaveBeenCalledTimes(1)
    expect(vi.mocked(specAuditCSV).mock.calls[0][0].spec_id).toBe('spec-v2')
    expect(clickedLinks[0]?.download).toBe('api-spec-audit-payment-api-v2.csv')
  })

  it('关闭清理选择，重复打开不同版本不会复用旧版本明细', async () => {
    renderPage()
    const firstDrawer = await openAudit(0)
    expect(
      await within(firstDrawer).findByText('spec-v1 审计结果'),
    ).toBeInTheDocument()
    await closeAudit(firstDrawer)

    const secondDrawer = await openAudit(1)
    expect(
      await within(secondDrawer).findByText('spec-v2 审计结果'),
    ).toBeInTheDocument()
    expect(secondDrawer).toHaveTextContent('规范审计：payment-api v2')
    expect(
      within(secondDrawer).queryByText('spec-v1 审计结果'),
    ).not.toBeInTheDocument()
    await closeAudit(secondDrawer)

    const reopenedDrawer = await openAudit(0)
    expect(
      await within(reopenedDrawer).findByText('spec-v1 审计结果'),
    ).toBeInTheDocument()
    expect(
      within(reopenedDrawer).queryByText('spec-v2 审计结果'),
    ).not.toBeInTheDocument()
    expect(auditCalls.map((call) => call.id)).toEqual([
      'spec-v1',
      'spec-v2',
      'spec-v1',
    ])
  })
})
