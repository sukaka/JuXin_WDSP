import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import EndpointDetailDrawer from '../EndpointDetailDrawer'
import type { ApiEndpointItem } from '../../../api/apiAssets'
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

/** EChart 在 jsdom 下无法真实渲染（无 canvas），替换为捕获 option 的桩组件 */
const chartProps = vi.hoisted(() => [] as { option: unknown; height?: number }[])
vi.mock('../../../components/EChart', () => ({
  default: (props: { option: unknown; height?: number }) => {
    chartProps.push(props)
    return <div data-testid="echart-stub" data-height={props.height} />
  },
}))

function lastChartOption(): {
  xAxis: { data: string[] }
  yAxis: { minInterval: number }
  series: { name: string; smooth: boolean; data: number[] }[]
} {
  const last = chartProps[chartProps.length - 1]
  expect(last).toBeTruthy()
  return JSON.parse(JSON.stringify(last.option))
}

const endpoint: ApiEndpointItem = {
  id: 'e1',
  application_name: '',
  directory_path: '/test/php',
  http_method: 'GET',
  normalized_path: '/v1/users/{id}',
  raw_path_example: '/v1/users/1',
  endpoint_key: 'GET /v1/users/{id}',
  protocol_type: 'REST',
  api_confidence: 0.6,
  asset_status: 'DISCOVERED',
  learning_status: 'LEARNING',
  is_api: true,
  hit_count: 3,
  first_seen_at: '2026-07-01T10:00:00Z',
  last_seen_at: '2026-07-22T08:30:00Z',
  classification_locked: false,
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-22T08:30:00Z',
}

const trend24h = {
  endpoint_id: 'e1',
  bucket_seconds: 300,
  range: '24h',
  total: 42,
  points: [
    { time: '2026-08-12T00:00:00Z', count: 3 },
    { time: '2026-08-12T00:05:00Z', count: 30 },
    { time: '2026-08-12T00:10:00Z', count: 9 },
  ],
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderDrawer(target: ApiEndpointItem | null = endpoint) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <EndpointDetailDrawer endpoint={target} onClose={() => {}} />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 默认 mock：模型版本为空（聚焦趋势卡片），traffic-trend 返回 24h 数据 */
function stubFetch(trendBody: unknown = trend24h) {
  vi.stubGlobal(
    'fetch',
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
        return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: trendBody }))
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [], page: 1, page_size: 100, total: 0 } }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    }),
  )
}

describe('EndpointDetailDrawer 访问趋势', () => {
  beforeEach(() => {
    chartProps.length = 0
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染波形图：默认 24h 请求，展示总访问量与峰值桶，option 为平滑面积折线', async () => {
    stubFetch()
    renderDrawer()
    expect(await screen.findByText('访问趋势')).toBeInTheDocument()
    // 默认 range=24h
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some((u) => u.includes('/api-security/endpoints/e1/traffic-trend') && u.includes('range=24h')),
      ).toBe(true)
    })
    // 图表容器渲染
    expect(await screen.findByTestId('echart-stub')).toBeInTheDocument()
    // 总访问量与峰值桶（count 最大的桶）
    expect(screen.getByText(/总访问量 42/)).toBeInTheDocument()
    expect(screen.getByText(/峰值 30 次/)).toBeInTheDocument()
    // option：series 计数、平滑面积折线、y 轴 minInterval=1、24h x 轴 HH:mm
    const option = lastChartOption()
    expect(option.series[0].data).toEqual([3, 30, 9])
    expect(option.series[0].smooth).toBe(true)
    expect(option.series[0].name).toBe('访问量')
    expect(option.yAxis.minInterval).toBe(1)
    expect(option.xAxis.data).toHaveLength(3)
    for (const label of option.xAxis.data) {
      expect(label).toMatch(/^\d{2}:\d{2}$/)
    }
  })

  it('无数据：显示「暂无访问数据」空态且不渲染图表', async () => {
    stubFetch({ endpoint_id: 'e1', bucket_seconds: 300, range: '24h', total: 0, points: [] })
    renderDrawer()
    expect(await screen.findByText('暂无访问数据')).toBeInTheDocument()
    expect(screen.queryByTestId('echart-stub')).not.toBeInTheDocument()
  })

  it('切换 7 天：携带 range=7d 重新查询，x 轴按 MM-DD HH:mm 格式化', async () => {
    stubFetch()
    renderDrawer()
    await screen.findByTestId('echart-stub')
    ;(fetch as Mock).mockImplementation((input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              endpoint_id: 'e1',
              bucket_seconds: 300,
              range: '7d',
              total: 7,
              points: [
                { time: '2026-08-06T00:00:00Z', count: 2 },
                { time: '2026-08-07T00:00:00Z', count: 5 },
              ],
            },
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(
          jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [], page: 1, page_size: 100, total: 0 } }),
        )
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    fireEvent.click(screen.getByText('7天'))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some((u) => u.includes('/api-security/endpoints/e1/traffic-trend') && u.includes('range=7d')),
      ).toBe(true)
    })
    await waitFor(() => {
      const option = lastChartOption()
      expect(option.series[0].data).toEqual([2, 5])
      for (const label of option.xAxis.data) {
        expect(label).toMatch(/^\d{2}-\d{2} \d{2}:\d{2}$/)
      }
    })
  })

  it('抽屉关闭（endpoint 为 null）：不发起 traffic-trend 查询', async () => {
    stubFetch()
    renderDrawer(null)
    // 等待一个宏任务周期，确保即使误触发查询也已发出请求
    await new Promise((r) => setTimeout(r, 50))
    const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
    expect(urls.some((u) => u.includes('traffic-trend'))).toBe(false)
    expect(urls).toHaveLength(0)
  })

  it('GET 接口无参数：展示「未观测到参数」空态而非「暂无参数数据」', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: trend24h }))
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [
                  {
                    id: 'mv1',
                    api_endpoint_id: 'e1',
                    endpoint_key: 'GET /v1/users/{id}',
                    status: 'FORMAL',
                    schema: {},
                    content_hash: 'h1',
                    version_number: 1,
                    change_summary: '',
                    created_reason: '',
                    created_at: '2026-07-10T00:00:00Z',
                  },
                ],
                page: 1,
                page_size: 100,
                total: 1,
              },
            }),
          )
        }
        if (url.includes('/api-security/models/mv1/parameters')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [], page: 1, page_size: 100, total: 0 } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    renderDrawer()
    expect(
      await screen.findByText('该接口为 GET 请求，未观测到 PATH / QUERY / BODY 参数'),
    ).toBeInTheDocument()
    expect(screen.queryByText('当前版本暂无参数数据')).not.toBeInTheDocument()
  })
})

describe('EndpointDetailDrawer 业务标签', () => {
  const endpointWithType: ApiEndpointItem = { ...endpoint, business_type: 'LOGIN' }

  /** 默认 mock：趋势/模型版本为空数据；PATCH 可由 patchImpl 定制响应 */
  function stubFetchWithPatch(patchImpl?: (url: string, init?: RequestInit) => Response) {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (init?.method === 'PATCH' && url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(
            patchImpl
              ? patchImpl(url, init)
              : jsonResponse(200, {
                  code: 'SUCCESS',
                  message: 'ok',
                  data: { endpoint: { ...endpointWithType, business_type: 'EXPORT' }, message: '已保存' },
                }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: trend24h }))
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(
            jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { items: [], page: 1, page_size: 100, total: 0 } }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  }

  /** 定位「业务标签」描述项的内容单元格 */
  function businessTypeCell(): HTMLElement {
    const labelCell = screen.getByText('业务标签').closest('th,td') as HTMLElement
    expect(labelCell).toBeTruthy()
    const contentCell = labelCell.nextElementSibling as HTMLElement
    expect(contentCell).toBeTruthy()
    return contentCell
  }

  /** 打开业务标签下拉并点选指定项（antd 6 Select 无 .ant-select-selector，直接点 .ant-select） */
  async function chooseBusinessType(optionText: string) {
    const select = businessTypeCell().querySelector('.ant-select') as HTMLElement
    expect(select).toBeTruthy()
    fireEvent.mouseDown(select)
    const options = await screen.findAllByText(optionText)
    const option = options.find((el) => el.closest('.ant-select-item-option-content'))
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示当前业务标签中文名；无 api_asset.edit 权限时选择框禁用且无保存按钮', async () => {
    useAuthStore.setState({ user: makeUser([]), csrfToken: null, initialized: true })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    const cell = businessTypeCell()
    expect(within(cell).getByText('登录')).toBeInTheDocument()
    expect(cell.querySelector('.ant-select')).toHaveClass('ant-select-disabled')
    expect(within(cell).queryByRole('button', { name: /保\s*存/ })).not.toBeInTheDocument()
    const patchCalls = (fetch as Mock).mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'PATCH',
    )
    expect(patchCalls).toHaveLength(0)
  })

  it('未变更时保存按钮保持禁用', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.edit']), csrfToken: null, initialized: true })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    expect(screen.getByRole('button', { name: /保\s*存/ })).toBeDisabled()
  })

  it('有权限时修改并保存：PATCH 携带 business_type，成功后提示并更新显示', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.edit']), csrfToken: 'csrf-token', initialized: true })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    await chooseBusinessType('导出')
    const saveBtn = screen.getByRole('button', { name: /保\s*存/ })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    await waitFor(() => {
      const patchCall = (fetch as Mock).mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === 'PATCH',
      )
      expect(patchCall).toBeTruthy()
      expect(String(patchCall![0])).toContain('/api-security/endpoints/e1')
      expect(JSON.parse(String((patchCall![1] as RequestInit).body))).toEqual({ business_type: 'EXPORT' })
    })
    expect(await screen.findByText('已保存')).toBeInTheDocument()
    // 成功后以服务端返回值为准更新显示，保存按钮回到禁用态
    const cell = businessTypeCell()
    expect(cell.querySelector('.ant-select-content')?.textContent).toContain('导出')
    await waitFor(() => expect(screen.getByRole('button', { name: /保\s*存/ })).toBeDisabled())
  })

  it('保存失败（400 字段级错误）时展示服务端错误消息', async () => {
    useAuthStore.setState({ user: makeUser(['api_asset.edit']), csrfToken: null, initialized: true })
    stubFetchWithPatch(() =>
      jsonResponse(400, { code: 'INVALID_ARGUMENT', message: 'business_type 取值非法', data: null }),
    )
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    await chooseBusinessType('导出')
    fireEvent.click(screen.getByRole('button', { name: /保\s*存/ }))

    expect(await screen.findByText('business_type 取值非法')).toBeInTheDocument()
  })
})
