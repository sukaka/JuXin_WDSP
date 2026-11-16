import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ResponseSchemaPanel from '../ResponseSchemaPanel'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function setPermissions(permissions: string[]) {
  const user: CurrentUser = {
    id: 'u1',
    username: 'observer',
    display_name: '观测员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
  useAuthStore.setState({ user, csrfToken: null, initialized: true })
}

function jsonResponse(status: number, data: unknown): Response {
  return new Response(
    JSON.stringify({
      code: status === 200 ? 'SUCCESS' : 'INTERNAL_ERROR',
      message: status === 200 ? 'ok' : 'schema query failed',
      data,
    }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return render(
    <QueryClientProvider client={queryClient}>
      <ResponseSchemaPanel endpointId="e1" />
    </QueryClientProvider>,
  )
}

describe('ResponseSchemaPanel', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('读取真实运行时 Schema，展开字段路径并披露截断', async () => {
    setPermissions(['api_model.read'])
    const fetchMock = vi.fn().mockResolvedValue(
      jsonResponse(200, {
        items: [
          {
            id: 'schema-200',
            endpoint_key: 'GET /v1/orders/{id}',
            status_code: 200,
            fields: { 'order.id': 'number', state: 'string' },
            content_type: 'application/json',
            truncated: false,
            content_hash: 'abcdefabcdefabcdef',
            sample_count: 12,
            first_seen: '2026-11-01T00:00:00Z',
            last_seen: '2026-11-02T00:00:00Z',
            updated_at: '2026-11-02T00:00:00Z',
          },
          {
            id: 'schema-500',
            endpoint_key: 'GET /v1/orders/{id}',
            status_code: 500,
            fields: { error: 'string' },
            content_type: 'application/json',
            truncated: true,
            content_hash: '1234567890abcdef',
            sample_count: 2,
            first_seen: '2026-11-01T00:00:00Z',
            last_seen: '2026-11-02T00:00:00Z',
            updated_at: '2026-11-02T00:00:00Z',
          },
        ],
      }),
    )
    vi.stubGlobal('fetch', fetchMock)
    renderPanel()
    expect(await screen.findByText('200')).toBeInTheDocument()
    expect(screen.getByText('500')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('曾截断')).toBeInTheDocument()
    const expand = document.querySelector('.ant-table-row-expand-icon')
    expect(expand).toBeTruthy()
    fireEvent.click(expand as HTMLElement)
    expect(await screen.findByText('order.id')).toBeInTheDocument()
    expect(screen.getByText('number')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/api-security/endpoints/e1/response-schemas',
      expect.objectContaining({ method: 'GET' }),
    )
  })

  it('无权限时不发起查询', () => {
    setPermissions([])
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    renderPanel()
    expect(
      screen.getByText('缺少 api_model.read 权限，无法查看响应 Schema'),
    ).toBeInTheDocument()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('展示空结果与真实查询错误', async () => {
    setPermissions(['api_model.read'])
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(200, { items: [] }))
      .mockResolvedValueOnce(jsonResponse(500, null))
    vi.stubGlobal('fetch', fetchMock)
    const view = renderPanel()
    expect(
      await screen.findByText('当前接口暂无运行时响应 Schema 学习结果'),
    ).toBeInTheDocument()
    view.unmount()
    renderPanel()
    expect(await screen.findByText('schema query failed')).toBeInTheDocument()
  })
})
