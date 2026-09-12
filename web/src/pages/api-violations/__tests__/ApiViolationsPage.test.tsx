import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import dayjs from 'dayjs'
import ApiViolationsPage from '../ApiViolationsPage'
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

const endpointsData = {
  items: [
    {
      id: 'e1',
      http_method: 'POST',
      normalized_path: '/v1/orders',
      endpoint_key: 'POST /v1/orders',
      api_confidence: 0.9,
      asset_status: 'CONFIRMED',
      learning_status: 'LEARNED',
      is_api: true,
      hit_count: 8,
      first_seen_at: '2026-07-01T10:00:00Z',
      last_seen_at: '2026-07-22T09:00:00Z',
    },
  ],
  page: 1,
  page_size: 100,
  total: 1,
}

const violation = {
  id: 'v1',
  endpoint_id: 'e1',
  model_version_id: 'm1',
  request_id: 'req-v1',
  violation_type: 'type_mismatch',
  field_path: 'order.amount',
  expected: 'number',
  observed: 'string',
  action_taken: 'BLOCK',
  occurred_at: '2026-08-01T10:00:00Z',
}

const violationsData = { items: [violation], page: 1, page_size: 20, total: 1 }

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiViolationsPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 点击占位文本所属 Select 的下拉项（antd 6 占位符 class 为 .ant-select-placeholder，与表头同文案时据此消歧） */
async function selectOption(placeholder: string, optionText: string) {
  const candidates = screen.getAllByText(placeholder)
  const target = candidates.find((el) => el.closest('.ant-select-placeholder')) ?? candidates[0]
  fireEvent.mouseDown(target)
  const options = await screen.findAllByText(optionText)
  const option = options.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('ApiViolationsPage', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/violations')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: violationsData }))
        }
        if (url.includes('/api-security/endpoints')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: endpointsData }))
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    useAuthStore.setState({ user: makeUser(['api_runtime.read']), csrfToken: null, initialized: true })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染违例列表：类型中文标签、字段路径、期望/观测值、执行动作；接口按 endpoint_id 映射为接口键', async () => {
    renderPage()
    expect(await screen.findByText('类型不匹配')).toBeInTheDocument()
    expect(screen.getByText('order.amount')).toBeInTheDocument()
    expect(screen.getByText('number')).toBeInTheDocument()
    expect(screen.getByText('string')).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
    // endpoint_id=e1 经接口选项映射为接口键展示（过滤器下拉未打开时唯一）
    expect(screen.getAllByText('POST /v1/orders').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('req-v1')).toBeInTheDocument()
  })

  it('接口过滤：选择接口后请求携带 endpoint_id', async () => {
    renderPage()
    await screen.findByText('类型不匹配')
    await selectOption('接口', 'POST /v1/orders')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('/api-security/violations?') && u.includes('endpoint_id=e1'))).toBe(true)
    })
  })

  it('违例类型过滤：选择「类型不匹配」后请求携带 violation_type=type_mismatch', async () => {
    renderPage()
    await screen.findByText('类型不匹配')
    await selectOption('违例类型', '类型不匹配')
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('violation_type=type_mismatch'))).toBe(true)
    })
  })

  it('时间过滤：选择发生时间范围后请求携带 start_time/end_time（ISO 8601）', async () => {
    renderPage()
    await screen.findByText('类型不匹配')
    // 打开 RangePicker，点选当月 10 日与 12 日（面板默认展示当月，避免跨月翻页的不稳定性）
    const startDay = dayjs().date(10).format('YYYY-MM-DD')
    const endDay = dayjs().date(12).format('YYYY-MM-DD')
    const picker = document.querySelector('.ant-picker') as HTMLElement
    expect(picker).toBeTruthy()
    const pickerInput = picker.querySelector('input') as HTMLElement
    // antd 6：focus + 点选面板容器 + 点击输入框组合触发面板打开
    fireEvent.focus(pickerInput)
    fireEvent.mouseDown(picker)
    fireEvent.click(pickerInput)
    const startCell = await waitFor(() => {
      const cell = document.querySelector(`.ant-picker-cell[title="${startDay}"] .ant-picker-cell-inner`)
      expect(cell).toBeTruthy()
      return cell as HTMLElement
    })
    fireEvent.click(startCell)
    const endCell = await waitFor(() => {
      const cell = document.querySelector(`.ant-picker-cell[title="${endDay}"] .ant-picker-cell-inner`)
      expect(cell).toBeTruthy()
      return cell as HTMLElement
    })
    fireEvent.click(endCell)
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(urls.some((u) => u.includes('start_time=') && u.includes('end_time='))).toBe(true)
    })
  })
})
