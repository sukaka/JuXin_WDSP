import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ProtectionPoliciesPage from '../ProtectionPoliciesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const POLICY_ITEM = {
  id: 'pol-1',
  code: 'default-observe',
  name: '默认观察策略',
  description: '基础防护',
  is_builtin: false,
  status: 'ACTIVE',
  protection_mode: 'OBSERVE',
  paranoia_level: 1,
  inbound_anomaly_threshold: 5,
  outbound_anomaly_threshold: 4,
  request_body_access: true,
  response_body_access: false,
  blocking_status_code: 403,
  usage_count: 0,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  version: 1,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <ProtectionPoliciesPage />
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

describe('ProtectionPoliciesPage 防护策略', () => {
  let detailAppIds: string[] | null
  let detailDomains: Array<{
    id: string
    application_id: string
    application_code: string
    application_name: string
    hostname: string
  }> | null
  let createCalls: unknown[]

  beforeEach(() => {
    detailAppIds = null
    detailDomains = null
    createCalls = []
    useAuthStore.setState({
      user: makeUser([
        'protection_policies.read',
        'protection_policies.create',
        'protection_policies.update',
        'protection_policies.delete',
      ]),
      csrfToken: null,
      initialized: true,
    })

    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.endsWith('/protection-policies')) {
          const body = JSON.parse(String(init?.body))
          createCalls.push(body)
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...POLICY_ITEM, ...body, id: 'pol-new' },
            }),
          )
        }
        if (method === 'GET' && url.includes('/protection-policies/pol-1')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...POLICY_ITEM, application_ids: detailAppIds, domains: detailDomains },
            }),
          )
        }
        if (method === 'GET' && url.includes('/protection-policies')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [POLICY_ITEM], page: 1, page_size: 20, total: 1 },
            }),
          )
        }
        if (method === 'GET' && url.includes('/applications')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [{ id: 'app-1', name: '商城主站', code: 'shop' }],
                page: 1,
                page_size: 100,
                total: 1,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('新建策略表单限制入站/出站异常阈值为 1–100，越界输入被截断且合法边界可提交', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建策略/ }))

    const inboundInput = (await screen.findByLabelText(
      '入站异常阈值',
    )) as HTMLInputElement
    const outboundInput = screen.getByLabelText(
      '出站异常阈值',
    ) as HTMLInputElement

    expect(inboundInput).toHaveAttribute('aria-valuemin', '1')
    expect(inboundInput).toHaveAttribute('aria-valuemax', '100')
    expect(outboundInput).toHaveAttribute('aria-valuemin', '1')
    expect(outboundInput).toHaveAttribute('aria-valuemax', '100')
    expect(screen.getByText(/范围 1–100；请求异常评分/)).toBeInTheDocument()
    expect(screen.getByText(/范围 1–100；响应异常评分/)).toBeInTheDocument()

    // AntD InputNumber 带 min/max 时，失焦会将越界值截断到 100 / 1，不会把 >100 的值提交给后端
    fireEvent.change(inboundInput, { target: { value: '150' } })
    fireEvent.blur(inboundInput)
    await waitFor(() => expect(inboundInput.value).toBe('100'))

    fireEvent.change(outboundInput, { target: { value: '120' } })
    fireEvent.blur(outboundInput)
    await waitFor(() => expect(outboundInput.value).toBe('100'))

    fireEvent.change(screen.getByLabelText('策略编码'), {
      target: { value: 'strict-web' },
    })
    fireEvent.change(screen.getByLabelText('策略名称'), {
      target: { value: '严格防护' },
    })
    fireEvent.change(inboundInput, { target: { value: '100' } })
    fireEvent.change(outboundInput, { target: { value: '1' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => expect(createCalls).toHaveLength(1))
    expect(createCalls[0]).toMatchObject({
      code: 'strict-web',
      name: '严格防护',
      inbound_anomaly_threshold: 100,
      outbound_anomaly_threshold: 1,
    })
  })

  it('小数输入（5.5 / 1.5）失焦时由 precision=0 约束为整数，未失焦原始小数被整数校验拦截且不提交 POST', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建策略/ }))

    const inboundInput = (await screen.findByLabelText(
      '入站异常阈值',
    )) as HTMLInputElement
    const outboundInput = screen.getByLabelText(
      '出站异常阈值',
    ) as HTMLInputElement

    fireEvent.change(screen.getByLabelText('策略编码'), {
      target: { value: 'decimal-guard' },
    })
    fireEvent.change(screen.getByLabelText('策略名称'), {
      target: { value: '小数防护测试' },
    })

    // 1) 未失焦直接提交原始小数：Form 整数校验器拦截并显示「请输入整数」，不触发 POST /protection-policies
    fireEvent.change(inboundInput, { target: { value: '5.5' } })
    fireEvent.change(outboundInput, { target: { value: '1.5' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => expect(screen.getAllByText('请输入整数')).toHaveLength(2))
    expect(createCalls).toHaveLength(0)

    // 2) 失焦后 AntD InputNumber precision={0} 自动四舍五入为整数，随后可合法提交整数给后端
    fireEvent.blur(inboundInput)
    fireEvent.blur(outboundInput)
    await waitFor(() => expect(inboundInput.value).toBe('6'))
    await waitFor(() => expect(outboundInput.value).toBe('2'))

    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(createCalls).toHaveLength(1))
    expect(createCalls[0]).toMatchObject({
      code: 'decimal-guard',
      name: '小数防护测试',
      inbound_anomaly_threshold: 6,
      outbound_anomaly_threshold: 2,
    })
  })

  it('策略详情抽屉对 application_ids=null 安全归一化为 0 个绑定应用', async () => {
    detailAppIds = null
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    expect(await screen.findByText('绑定应用（0）')).toBeInTheDocument()
    expect(screen.getByText('暂无应用绑定该策略')).toBeInTheDocument()
  })

  it('策略详情抽屉展示已绑定的应用名称与域名列表', async () => {
    detailAppIds = ['app-1']
    detailDomains = [
      {
        id: 'dom-1',
        application_id: 'app-1',
        application_code: 'shop',
        application_name: '商城主站',
        hostname: 'jxdr.cn',
      },
    ]
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    expect(await screen.findByText('绑定应用（1）')).toBeInTheDocument()
    expect(await screen.findByText('商城主站')).toBeInTheDocument()
    expect(screen.getByText('绑定域名（1）')).toBeInTheDocument()
    expect(screen.getByText('jxdr.cn')).toBeInTheDocument()
  })
})
