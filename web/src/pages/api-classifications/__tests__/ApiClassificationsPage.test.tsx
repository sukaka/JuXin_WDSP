import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiClassificationsPage from '../ApiClassificationsPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const PROTOCOL_CASES = [
  ['REST', 'REST'],
  ['REST_JSON', 'REST/JSON'],
  ['REST_XML', 'REST/XML'],
  ['FORM_API', 'Form 表单'],
  ['GRAPHQL', 'GraphQL'],
  ['JSON_RPC', 'JSON-RPC'],
  ['XML_RPC', 'XML-RPC'],
  ['SOAP', 'SOAP'],
  ['WEBHOOK', 'Webhook'],
  ['FILE_UPLOAD', '文件上传'],
  ['FILE_DOWNLOAD', '文件下载'],
  ['WEBSOCKET_HANDSHAKE', 'WebSocket 握手'],
  ['SERVER_SENT_EVENTS', 'SSE'],
  ['GRPC', 'gRPC'],
  ['WEBSOCKET', 'WebSocket'],
  ['UNKNOWN_HTTP_API', '未知 HTTP API'],
] as const

const INTERACTION_MODE_CASES = [
  ['REQUEST_RESPONSE', '请求响应'],
  ['RPC', '远程调用'],
  ['EVENT_CALLBACK', '事件回调'],
  ['FILE_TRANSFER', '文件传输'],
  ['SERVER_PUSH', '服务端推送'],
  ['BIDIRECTIONAL_STREAM', '双向流'],
] as const

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(data: unknown): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    },
  )
}

function classificationRow(id: string, dimension: string, value: string) {
  return {
    id,
    dimension,
    value,
    description: `${dimension} 说明`,
    created_at: '2026-01-01T00:00:00Z',
  }
}

function stubClassificationRows(rows: Array<Record<string, unknown>>) {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/classifications')) {
        return Promise.resolve(jsonResponse({ builtin: [], custom: rows }))
      }
      if (url.includes('/api-security/endpoints')) {
        return Promise.resolve(
          jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    }),
  )
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiClassificationsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ApiClassificationsPage', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['api_classification.manage']),
      csrfToken: null,
      initialized: true,
    })
    stubClassificationRows([])
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('动态分类行提供带名称的原生删除按钮', async () => {
    renderPage()
    const addButton = await screen.findByRole('button', { name: /添加维度/ })
    fireEvent.click(addButton)

    const deleteButton = screen.getByRole('button', { name: '删除此分类维度' })
    expect(deleteButton).toHaveAttribute('type', 'button')

    fireEvent.click(deleteButton)
    expect(
      screen.queryByRole('button', { name: '删除此分类维度' }),
    ).not.toBeInTheDocument()
  })

  it('EXPOSURE 维度分类显示中文取值与来源，不暴露英文枚举', async () => {
    stubClassificationRows([classificationRow('c1', 'EXPOSURE', 'PUBLIC')])
    renderPage()

    expect(await screen.findByText('暴露范围')).toBeInTheDocument()
    expect(screen.getByText('外网')).toBeInTheDocument()
    expect(screen.getByText('自定义')).toBeInTheDocument()
    expect(screen.queryByText('PUBLIC')).not.toBeInTheDocument()

    fireEvent.doubleClick(screen.getByText('外网'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('暴露范围')).toBeInTheDocument()
    expect(within(drawer).getByText('外网')).toBeInTheDocument()
    expect(within(drawer).queryByText('PUBLIC')).not.toBeInTheDocument()
  })

  it('技术协议表格复用协议词表展示当前值与历史值', async () => {
    stubClassificationRows(
      PROTOCOL_CASES.map(([value], index) =>
        classificationRow(`protocol-${index}`, 'TECHNICAL_PROTOCOL', value),
      ),
    )
    renderPage()

    const table = screen.getByRole('table')
    expect(
      await within(table).findByText(PROTOCOL_CASES[0][1]),
    ).toBeInTheDocument()
    for (const [, label] of PROTOCOL_CASES) {
      expect(within(table).getByText(label)).toBeInTheDocument()
    }
  })

  it('交互模式表格展示全部固定取值的中文标签', async () => {
    stubClassificationRows(
      INTERACTION_MODE_CASES.map(([value], index) =>
        classificationRow(`interaction-${index}`, 'INTERACTION_MODE', value),
      ),
    )
    renderPage()

    const table = screen.getByRole('table')
    expect(
      await within(table).findByText(INTERACTION_MODE_CASES[0][1]),
    ).toBeInTheDocument()
    for (const [value, label] of INTERACTION_MODE_CASES) {
      expect(within(table).getByText(label)).toBeInTheDocument()
      expect(within(table).queryByText(value)).not.toBeInTheDocument()
    }
  })

  it('数据敏感等级在表格和详情抽屉中显示中文并保留自定义值', async () => {
    const cases = [
      ['HIGH', '高'],
      ['MEDIUM', '中'],
      ['LOW', '低'],
      ['UNKNOWN', '未知'],
    ] as const
    stubClassificationRows([
      ...cases.map(([value], index) =>
        classificationRow(`sensitivity-${index}`, 'DATA_SENSITIVITY', value),
      ),
      classificationRow(
        'sensitivity-custom',
        'DATA_SENSITIVITY',
        'BUSINESS_SECRET',
      ),
    ])
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findAllByText('数据敏感等级')).toHaveLength(
      cases.length + 1,
    )
    for (const [value, label] of cases) {
      expect(within(table).getByText(label)).toBeInTheDocument()
      expect(within(table).queryByText(value)).not.toBeInTheDocument()
    }
    expect(within(table).getByText('BUSINESS_SECRET')).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('高'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('数据敏感等级')).toBeInTheDocument()
    expect(within(drawer).getByText('高')).toBeInTheDocument()
    expect(within(drawer).queryByText('HIGH')).not.toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('BUSINESS_SECRET'))
    expect(
      await within(drawer).findByText('BUSINESS_SECRET'),
    ).toBeInTheDocument()
  })

  it('身份要求在表格和详情抽屉中显示中文并保留自定义值', async () => {
    const cases = [
      ['AUTH_REQUIRED', '需要认证（观测）'],
      ['AUTH_OPTIONAL', '可选认证（观测）'],
      ['ANONYMOUS_ALLOWED', '允许匿名（观测）'],
      ['ANONYMOUS_REJECTED', '匿名被拒（观测）'],
      ['AUTHENTICATED_OBSERVED', '仅观测到认证成功'],
    ] as const
    stubClassificationRows([
      ...cases.map(([value], index) =>
        classificationRow(`identity-${index}`, 'IDENTITY_REQUIREMENT', value),
      ),
      classificationRow(
        'identity-custom',
        'IDENTITY_REQUIREMENT',
        'CUSTOM_IDENTITY_REQUIREMENT',
      ),
    ])
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findAllByText('身份要求')).toHaveLength(
      cases.length + 1,
    )
    for (const [value, label] of cases) {
      expect(within(table).getByText(label)).toBeInTheDocument()
      expect(within(table).queryByText(value)).not.toBeInTheDocument()
    }
    expect(
      within(table).getByText('CUSTOM_IDENTITY_REQUIREMENT'),
    ).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('需要认证（观测）'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('身份要求')).toBeInTheDocument()
    expect(within(drawer).getByText('需要认证（观测）')).toBeInTheDocument()
    expect(within(drawer).queryByText('AUTH_REQUIRED')).not.toBeInTheDocument()

    fireEvent.doubleClick(
      within(table).getByText('CUSTOM_IDENTITY_REQUIREMENT'),
    )
    expect(
      await within(drawer).findByText('CUSTOM_IDENTITY_REQUIREMENT'),
    ).toBeInTheDocument()
  })

  it('业务流程阶段在表格和详情抽屉中显示中文并保留自定义值', async () => {
    const cases = [
      ['START', '开始'],
      ['INTERMEDIATE', '中间'],
      ['TERMINAL', '终点'],
      ['START_AND_TERMINAL', '起止一体'],
      ['MULTI_STAGE', '多阶段'],
    ] as const
    stubClassificationRows([
      ...cases.map(([value], index) =>
        classificationRow(`flow-stage-${index}`, 'BUSINESS_FLOW_STAGE', value),
      ),
      classificationRow(
        'flow-stage-custom',
        'BUSINESS_FLOW_STAGE',
        'CUSTOM_FLOW_STAGE',
      ),
    ])
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findAllByText('业务流程阶段')).toHaveLength(
      cases.length + 1,
    )
    for (const [value, label] of cases) {
      expect(within(table).getByText(label)).toBeInTheDocument()
      expect(within(table).queryByText(value)).not.toBeInTheDocument()
    }
    expect(within(table).getByText('CUSTOM_FLOW_STAGE')).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('开始'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('业务流程阶段')).toBeInTheDocument()
    expect(within(drawer).getByText('开始')).toBeInTheDocument()
    expect(within(drawer).queryByText('START')).not.toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('CUSTOM_FLOW_STAGE'))
    expect(
      await within(drawer).findByText('CUSTOM_FLOW_STAGE'),
    ).toBeInTheDocument()
  })

  it('风险标签在表格和详情抽屉中显示中文并保留自定义类型', async () => {
    const cases = [
      ['SHADOW', '影子API'],
      ['ZOMBIE', '僵尸API'],
      ['DEPRECATED', '已下线API'],
      ['BOLA', '对象级越权'],
      ['BFLA', '功能级越权'],
      ['SCHEMA_DEVIATION', '模型偏离'],
      ['SENSITIVE_LEAK', '敏感数据泄露'],
      ['MASS_ASSIGNMENT', '批量赋值'],
      ['BEHAVIOR_ANOMALY', '行为异常'],
      ['MULTI_RISK', '多重风险'],
    ] as const
    stubClassificationRows([
      ...cases.map(([value], index) =>
        classificationRow(`risk-${index}`, 'RISK_LABEL', value),
      ),
      classificationRow('risk-custom', 'RISK_LABEL', 'CUSTOM_RISK'),
    ])
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findAllByText('风险标签')).toHaveLength(
      cases.length + 1,
    )
    for (const [value, label] of cases) {
      expect(within(table).getByText(label)).toBeInTheDocument()
      expect(within(table).queryByText(value)).not.toBeInTheDocument()
    }
    expect(within(table).getByText('CUSTOM_RISK')).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('影子API'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('风险标签')).toBeInTheDocument()
    expect(within(drawer).getByText('影子API')).toBeInTheDocument()
    expect(within(drawer).queryByText('SHADOW')).not.toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('CUSTOM_RISK'))
    expect(await within(drawer).findByText('CUSTOM_RISK')).toBeInTheDocument()
  })

  it('业务对象仅翻译多重业务对象并在表格和详情中保留其他类型', async () => {
    stubClassificationRows([
      classificationRow('object-multi', 'BUSINESS_OBJECT', 'MULTI_OBJECT'),
      classificationRow('object-order', 'BUSINESS_OBJECT', 'ORDER'),
      classificationRow(
        'object-custom',
        'BUSINESS_OBJECT',
        'CUSTOM_BUSINESS_OBJECT',
      ),
    ])
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findAllByText('业务对象')).toHaveLength(3)
    expect(within(table).getByText('多重业务对象')).toBeInTheDocument()
    expect(within(table).queryByText('MULTI_OBJECT')).not.toBeInTheDocument()
    expect(within(table).getByText('ORDER')).toBeInTheDocument()
    expect(
      within(table).getByText('CUSTOM_BUSINESS_OBJECT'),
    ).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('多重业务对象'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('业务对象')).toBeInTheDocument()
    expect(within(drawer).getByText('多重业务对象')).toBeInTheDocument()
    expect(within(drawer).queryByText('MULTI_OBJECT')).not.toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('ORDER'))
    expect(await within(drawer).findByText('ORDER')).toBeInTheDocument()
  })

  it('技术协议与交互模式在详情抽屉中显示中文维度和取值', async () => {
    stubClassificationRows([
      classificationRow('protocol-grpc', 'TECHNICAL_PROTOCOL', 'GRPC'),
      classificationRow('interaction-rpc', 'INTERACTION_MODE', 'RPC'),
    ])
    renderPage()

    const table = screen.getByRole('table')
    fireEvent.doubleClick(await within(table).findByText('gRPC'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('技术协议')).toBeInTheDocument()
    expect(within(drawer).getByText('gRPC')).toBeInTheDocument()
    expect(within(drawer).queryByText('GRPC')).not.toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('远程调用'))
    expect(await within(drawer).findByText('交互模式')).toBeInTheDocument()
    expect(within(drawer).getByText('远程调用')).toBeInTheDocument()
    expect(within(drawer).queryByText('RPC')).not.toBeInTheDocument()
  })

  it('未识别的技术协议与交互模式在表格和详情抽屉中保留原文', async () => {
    stubClassificationRows([
      classificationRow(
        'protocol-unknown',
        'TECHNICAL_PROTOCOL',
        'FUTURE_PROTOCOL',
      ),
      classificationRow(
        'interaction-unknown',
        'INTERACTION_MODE',
        'FUTURE_INTERACTION',
      ),
    ])
    renderPage()

    const table = screen.getByRole('table')
    fireEvent.doubleClick(await within(table).findByText('FUTURE_PROTOCOL'))
    const drawer = await screen.findByRole('dialog')
    expect(within(drawer).getByText('技术协议')).toBeInTheDocument()
    expect(within(drawer).getByText('FUTURE_PROTOCOL')).toBeInTheDocument()

    fireEvent.doubleClick(within(table).getByText('FUTURE_INTERACTION'))
    expect(await within(drawer).findByText('交互模式')).toBeInTheDocument()
    expect(within(drawer).getByText('FUTURE_INTERACTION')).toBeInTheDocument()
  })

  it('扩展分类维度（PURPOSE/ACCESS/ACTION/BUSINESS_DOMAIN/DATA_LEVEL/LIFECYCLE/DIRECTION/AUTH_TYPE/动态RISK_LABEL）均展示中文', async () => {
    const cases: [string, string, string][] = [
      ['PURPOSE', 'TRADE', '交易支付'],
      ['ACCESS', 'READ_WRITE', '读写'],
      ['ACTION', 'TOKEN_REFRESH', '刷新令牌'],
      ['BUSINESS_DOMAIN', 'TRANSACTION_FUND', '交易资金'],
      ['DATA_LEVEL', 'CORE', '核心数据'],
      ['LIFECYCLE', 'CONFIRMED', '已确认'],
      ['DIRECTION', 'EAST_WEST', '东西向'],
      ['AUTH_TYPE', 'cookie_session', 'Cookie 会话'],
      ['RISK_LABEL', 'LLM_PROMPT_INJECTION', 'LLM 提示词注入'],
    ]
    stubClassificationRows(
      cases.map(([dim, val], idx) => classificationRow(`ext-${idx}`, dim, val)),
    )
    renderPage()

    const table = screen.getByRole('table')
    expect(await within(table).findByText('交易支付')).toBeInTheDocument()
    for (const [, raw, expected] of cases) {
      expect(within(table).getByText(expected)).toBeInTheDocument()
      expect(within(table).queryByText(raw)).not.toBeInTheDocument()
    }
  })

  it('创建分类返回 CustomTaxonomyItem 时正常提示「分类已创建」', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (init?.method === 'POST' && url.endsWith('/api-security/classifications')) {
          return Promise.resolve(
            jsonResponse({
              id: 'tax-1',
              dimension: 'BU',
              value: 'FINANCE',
              description: '金融事业部',
              created_at: '2026-08-01T00:00:00Z',
            }),
          )
        }
        if (url.includes('/api-security/classifications')) {
          return Promise.resolve(jsonResponse({ builtin: [], custom: [] }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(
            jsonResponse({ items: [], page: 1, page_size: 100, total: 0 }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新增分类/ }))
    const drawer = await screen.findByRole('dialog')
    fireEvent.change(within(drawer).getByLabelText('维度'), { target: { value: 'BU' } })
    fireEvent.change(within(drawer).getByLabelText('取值'), { target: { value: 'FINANCE' } })
    fireEvent.click(within(drawer).getByRole('button', { name: /创\s*建/ }))
    expect(await screen.findByText('分类已创建')).toBeInTheDocument()
  })
})
