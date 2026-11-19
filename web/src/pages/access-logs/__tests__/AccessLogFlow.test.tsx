import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ComponentProps } from 'react'
import AccessLogFlow from '../AccessLogFlow'
import type { FlowResult } from '../../../api/accessLogs'
import type EChart from '../../../components/EChart'

let graphNodeKinds: string[] = []
let lastTooltipFormatter: ((params: unknown) => string) | undefined
vi.mock('../../../components/EChart', () => ({
  default: ({ option }: ComponentProps<typeof EChart>) => {
    const series = (option.series ?? []) as Array<{ data?: Array<{ id: string }> }>
    graphNodeKinds = (series[0]?.data ?? []).map((node) => node.id.split(':')[0])
    const tooltip = option.tooltip as { formatter?: (params: unknown) => string } | undefined
    lastTooltipFormatter = tooltip?.formatter
    return <div data-testid="audit-flow-chart" />
  },
}))

const flow: FlowResult = {
  request_count: 2, sensitive_request_count: 2, truncated: false, data_source: 'access_logs+api_runtime_events',
  start_time: '2026-11-17T00:00:00Z', end_time: '2026-11-17T01:00:00Z',
  nodes: [
    { id: 'SOURCE:192.0.2.10', name: '192.0.2.10', kind: 'SOURCE', request_count: 2, field_hits: 0, verified: false, other: false, filters: { client_ip: '192.0.2.10' }, request_ids: ['req-1', 'req-2'], drill_exact: true },
    { id: 'ACCOUNT:identity-1', name: '身份 identity-1', kind: 'ACCOUNT', request_count: 2, field_hits: 0, verified: true, other: false, filters: { identity_fingerprint: 'identity-1' }, request_ids: ['req-1', 'req-2'], drill_exact: true },
    { id: 'REQUEST_FIELD:form.pwd', name: 'form.pwd · credential', kind: 'REQUEST_FIELD', request_count: 2, field_hits: 2, verified: false, other: false, filters: { field_path: 'form.pwd', direction: 'REQUEST', data_type: 'credential', request_id: 'req-pcap-e2e' }, request_ids: ['req-1', 'req-2'], drill_exact: true },
    { id: 'APPLICATION:shop', name: '订单系统', kind: 'APPLICATION', request_count: 2, field_hits: 0, verified: false, other: false, filters: { application_id: 'app-1' }, request_ids: ['req-1', 'req-2'], drill_exact: true },
    { id: 'API:POST /v1/login', name: 'POST /v1/login', kind: 'API', request_count: 2, field_hits: 0, verified: false, other: false, filters: { endpoint_key: 'POST /v1/login' }, request_ids: ['req-1', 'req-2'], drill_exact: true },
    { id: 'RESPONSE_FIELD:json.id_card', name: 'json.id_card · id_card', kind: 'RESPONSE_FIELD', request_count: 1, field_hits: 1, verified: false, other: false, filters: { field_path: 'json.id_card', direction: 'RESPONSE' }, request_ids: ['req-1'], drill_exact: true },
  ],
  edges: [],
}

function renderFlow(onDrill = vi.fn()) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(<QueryClientProvider client={client}><AccessLogFlow filters={{ start_time: '2026-11-17T00:00:00Z', end_time: '2026-11-17T01:00:00Z' }} onDrill={onDrill} /></QueryClientProvider>)
  return onDrill
}

describe('AccessLogFlow', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    graphNodeKinds = []
    lastTooltipFormatter = undefined
  })
  it('显示真实请求与字段计数，类型开关只改变显示', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({ code: 'SUCCESS', data: flow }), { status: 200 }))))
    renderFlow()
    expect(await screen.findByText('去重请求 2')).toBeInTheDocument()
    expect(screen.getByText('字段命中 3')).toBeInTheDocument()
    expect(screen.getByText('已验证')).toBeInTheDocument()
    expect(graphNodeKinds).toContain('REQUEST_FIELD')
    fireEvent.click(screen.getByLabelText('请求敏感字段'))
    await waitFor(() => expect(graphNodeKinds).not.toContain('REQUEST_FIELD'))
    expect(screen.getByText('字段命中 3')).toBeInTheDocument()
  })
  it('从字段下钻时使用真实请求ID和方向，不含字段值', async () => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(new Response(JSON.stringify({ code: 'SUCCESS', data: flow }), { status: 200 }))))
    const drill = renderFlow()
    const button = await screen.findByRole('button', { name: '请求敏感字段 / form.pwd · credential' })
    fireEvent.click(button)
    expect(drill).toHaveBeenCalledWith(expect.objectContaining({ field_path: 'form.pwd', direction: 'REQUEST', request_ids: 'req-1,req-2' }))
    expect(JSON.stringify(drill.mock.calls)).not.toContain('password-value')
  })

  it('tooltip 渲染对节点名称执行 HTML 转义，防止存储型 XSS', async () => {
    const xssName = '<img src=x onerror="alert(1)">'
    const xssFlow: FlowResult = {
      ...flow,
      nodes: [
        {
          ...flow.nodes[0],
          id: 'API:xss',
          kind: 'API',
          name: xssName,
        },
      ],
      edges: [],
    }
    vi.stubGlobal(
      'fetch',
      vi.fn(() => Promise.resolve(new Response(JSON.stringify({ code: 'SUCCESS', data: xssFlow }), { status: 200 }))),
    )
    renderFlow()
    expect(await screen.findByTestId('audit-flow-chart')).toBeInTheDocument()
    expect(lastTooltipFormatter).toBeTypeOf('function')
    const html = lastTooltipFormatter!({ dataType: 'node', data: { id: 'API:xss' } })
    expect(html).not.toContain('<img')
    expect(html).toContain('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;')
  })
})
