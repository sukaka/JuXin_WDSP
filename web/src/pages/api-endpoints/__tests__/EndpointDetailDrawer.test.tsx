import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
  vi,
  type Mock,
} from 'vitest'
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
import EndpointDetailDrawer from '../EndpointDetailDrawer'
import type { ApiEndpointItem } from '../../../api/apiAssets'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import { formatDateTime } from '../../../utils/format'

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
const chartProps = vi.hoisted(
  () => [] as { option: unknown; height?: number }[],
)
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

/** 暴露面判定空视图（从未评估；既有用例的默认 stub，聚焦各自主题） */
const exposureEmpty = {
  endpoint_id: 'e1',
  endpoint_key: 'GET /v1/users/{id}',
  locked: false,
  current: { value: '', source: '', confidence: 0 },
  assessment: null,
}

/** 资产档案 fixture：覆盖所属单位/业务系统/三类负责人/数据等级/API 等级/认证方式与多标签 */
const assetFixture = {
  endpoint_id: 'e1',
  purpose: '用户查询',
  exposure: 'PUBLIC',
  data_classification: 'UNKNOWN',
  owner: '张XX',
  tags: ['对账', '第三方回调'],
  business_type: 'LOGIN',
  organization: 'XX集团金融事业部',
  business_system: '客户经营管理平台',
  technical_owner: '李XX',
  data_owner: '王XX',
  data_level: 'IMPORTANT',
  api_level: 'LEVEL_3',
  auth_type: 'TOKEN',
  created_at: '2026-07-01T10:00:00Z',
  updated_at: '2026-07-22T08:30:00Z',
}

/** 详情 GET 响应（资产档案 + 近 7 天日均调用量） */
function detailJson(asset: unknown = assetFixture): Response {
  return jsonResponse(200, {
    code: 'SUCCESS',
    message: 'ok',
    data: { endpoint: { ...endpoint, asset }, daily_requests: 18721 },
  })
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
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: trendBody,
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/exposure')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: exposureEmpty,
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/response-schemas')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: {
              items: [
                {
                  id: 'schema-1',
                  endpoint_key: 'GET /v1/users/{id}',
                  status_code: 200,
                  fields: { 'user.id': 'number', state: 'string' },
                  content_type: 'application/json',
                  truncated: false,
                  content_hash: 'abcdef0123456789',
                  sample_count: 18,
                  first_seen: '2026-07-01T10:00:00Z',
                  last_seen: '2026-07-22T08:30:00Z',
                  updated_at: '2026-07-22T08:30:00Z',
                },
              ],
            },
          }),
        )
      }
      if (url.includes('/api-security/endpoints/e1/models')) {
        return Promise.resolve(
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [], page: 1, page_size: 100, total: 0 },
          }),
        )
      }
      if (url.endsWith('/api-security/endpoints/e1')) {
        return Promise.resolve(detailJson())
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
        urls.some(
          (u) =>
            u.includes('/api-security/endpoints/e1/traffic-trend') &&
            u.includes('range=24h'),
        ),
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
    stubFetch({
      endpoint_id: 'e1',
      bucket_seconds: 300,
      range: '24h',
      total: 0,
      points: [],
    })
    renderDrawer()
    expect(await screen.findByText('暂无访问数据')).toBeInTheDocument()
    expect(screen.queryByTestId('echart-stub')).not.toBeInTheDocument()
  })

  it('导出档案：有权限时打开单个 API 详细 JSON URL', async () => {
    const openMock = vi.fn()
    vi.stubGlobal('open', openMock)
    useAuthStore.setState({
      user: makeUser(['api_asset.export']),
      csrfToken: null,
      initialized: true,
    })
    stubFetch()
    renderDrawer()
    fireEvent.click(await screen.findByRole('button', { name: /导出档案/ }))
    expect(openMock).toHaveBeenCalledWith(
      '/api/v1/api-security/endpoints/e1/export?format=json',
      '_blank',
    )
  })

  it('导出档案：无 api_asset.export 权限时隐藏', async () => {
    useAuthStore.setState({
      user: makeUser([]),
      csrfToken: null,
      initialized: true,
    })
    stubFetch()
    renderDrawer()
    await screen.findByText('访问趋势')
    expect(
      screen.queryByRole('button', { name: /导出档案/ }),
    ).not.toBeInTheDocument()
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
          jsonResponse(200, {
            code: 'SUCCESS',
            message: 'ok',
            data: { items: [], page: 1, page_size: 100, total: 0 },
          }),
        )
      }
      if (url.endsWith('/api-security/endpoints/e1')) {
        return Promise.resolve(detailJson())
      }
      return Promise.reject(new Error(`unexpected url: ${url}`))
    })
    fireEvent.click(screen.getByText('7天'))
    await waitFor(() => {
      const urls = (fetch as Mock).mock.calls.map((c) => String(c[0]))
      expect(
        urls.some(
          (u) =>
            u.includes('/api-security/endpoints/e1/traffic-trend') &&
            u.includes('range=7d'),
        ),
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
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: trend24h,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/exposure')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: exposureEmpty,
            }),
          )
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
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 100, total: 0 },
            }),
          )
        }
        if (url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(detailJson())
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
    renderDrawer()
    expect(
      await screen.findByText(
        '该接口为 GET 请求，未观测到 PATH / QUERY / BODY 参数',
      ),
    ).toBeInTheDocument()
    expect(screen.queryByText('当前版本暂无参数数据')).not.toBeInTheDocument()
  })
})

describe('EndpointDetailDrawer 业务标签', () => {
  const endpointWithType: ApiEndpointItem = {
    ...endpoint,
    business_type: 'LOGIN',
  }

  /** 默认 mock：趋势/模型版本为空数据；PATCH 可由 patchImpl 定制响应 */
  function stubFetchWithPatch(
    patchImpl?: (url: string, init?: RequestInit) => Response,
  ) {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (
          init?.method === 'PATCH' &&
          url.endsWith('/api-security/endpoints/e1')
        ) {
          return Promise.resolve(
            patchImpl
              ? patchImpl(url, init)
              : jsonResponse(200, {
                  code: 'SUCCESS',
                  message: 'ok',
                  data: {
                    endpoint: { ...endpointWithType, business_type: 'EXPORT' },
                    message: '已保存',
                  },
                }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: trend24h,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/exposure')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: exposureEmpty,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 100, total: 0 },
            }),
          )
        }
        if (url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(detailJson())
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  }

  /** 定位「业务标签」描述项的内容单元格 */
  function businessTypeCell(): HTMLElement {
    const labelCell = screen
      .getByText('业务标签')
      .closest('th,td') as HTMLElement
    expect(labelCell).toBeTruthy()
    const contentCell = labelCell.nextElementSibling as HTMLElement
    expect(contentCell).toBeTruthy()
    return contentCell
  }

  /** 打开业务标签下拉并点选指定项（antd 6 Select 无 .ant-select-selector，直接点 .ant-select） */
  async function chooseBusinessType(optionText: string) {
    const select = businessTypeCell().querySelector(
      '.ant-select',
    ) as HTMLElement
    expect(select).toBeTruthy()
    fireEvent.mouseDown(select)
    const options = await screen.findAllByText(optionText)
    const option = options.find((el) =>
      el.closest('.ant-select-item-option-content'),
    )
    expect(option).toBeTruthy()
    fireEvent.click(option as HTMLElement)
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示当前业务标签中文名；无 api_asset.edit 权限时选择框禁用且无保存按钮', async () => {
    useAuthStore.setState({
      user: makeUser([]),
      csrfToken: null,
      initialized: true,
    })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    const cell = businessTypeCell()
    expect(within(cell).getByText('登录')).toBeInTheDocument()
    expect(cell.querySelector('.ant-select')).toHaveClass('ant-select-disabled')
    expect(
      within(cell).queryByRole('button', { name: /保\s*存/ }),
    ).not.toBeInTheDocument()
    const patchCalls = (fetch as Mock).mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'PATCH',
    )
    expect(patchCalls).toHaveLength(0)
  })

  it('未变更时保存按钮保持禁用', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: null,
      initialized: true,
    })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    expect(
      within(businessTypeCell()).getByRole('button', { name: /保\s*存/ }),
    ).toBeDisabled()
  })

  it('有权限时修改并保存：PATCH 携带 business_type，成功后提示并更新显示', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: 'csrf-token',
      initialized: true,
    })
    stubFetchWithPatch()
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    await chooseBusinessType('导出')
    const saveBtn = within(businessTypeCell()).getByRole('button', {
      name: /保\s*存/,
    })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    await waitFor(() => {
      const patchCall = (fetch as Mock).mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === 'PATCH',
      )
      expect(patchCall).toBeTruthy()
      expect(String(patchCall![0])).toContain('/api-security/endpoints/e1')
      expect(
        JSON.parse(String((patchCall![1] as RequestInit).body)),
      ).toMatchObject({
        business_type: 'EXPORT',
        organization: 'XX集团金融事业部',
        tags: ['对账', '第三方回调'],
      })
    })
    expect(await screen.findByText('已保存')).toBeInTheDocument()
    // 成功后以服务端返回值为准更新显示，保存按钮回到禁用态
    const cell = businessTypeCell()
    expect(cell.querySelector('.ant-select-content')?.textContent).toContain(
      '导出',
    )
    await waitFor(() =>
      expect(
        within(businessTypeCell()).getByRole('button', { name: /保\s*存/ }),
      ).toBeDisabled(),
    )
  })

  it('保存失败（400 字段级错误）时展示服务端错误消息', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: null,
      initialized: true,
    })
    stubFetchWithPatch(() =>
      jsonResponse(400, {
        code: 'INVALID_ARGUMENT',
        message: 'business_type 取值非法',
        data: null,
      }),
    )
    renderDrawer(endpointWithType)

    await screen.findByText('业务标签')
    await chooseBusinessType('导出')
    fireEvent.click(
      within(businessTypeCell()).getByRole('button', { name: /保\s*存/ }),
    )

    expect(
      await screen.findByText('business_type 取值非法'),
    ).toBeInTheDocument()
  })
})

describe('EndpointDetailDrawer 暴露面判定', () => {
  const exposurePublic = {
    endpoint_id: 'e1',
    endpoint_key: 'GET /v1/users/{id}',
    locked: false,
    current: { value: 'PUBLIC', source: 'TRAFFIC_OBSERVED', confidence: 0.9 },
    assessment: {
      verdict: 'PUBLIC',
      source: 'TRAFFIC_OBSERVED',
      confidence: 'HIGH',
      evidence: [
        {
          type: 'traffic',
          summary: '近 7 天观测到 3 个公网来源指纹，覆盖 5 个自然日',
        },
        { type: 'config', summary: '归属域名 api.example.com 解析至公网地址' },
      ],
      assessed_at: '2026-08-12T06:00:00Z',
    },
  }

  /** 暴露面 mock：GET 返回 exposureBody；POST reassess 可由 reassessImpl 定制响应 */
  function stubExposureFetch(
    exposureBody: unknown = exposurePublic,
    reassessImpl?: () => Response,
  ) {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (
          init?.method === 'POST' &&
          url.includes('/api-security/endpoints/e1/exposure/reassess')
        ) {
          return Promise.resolve(
            reassessImpl
              ? reassessImpl()
              : jsonResponse(200, {
                  code: 'SUCCESS',
                  message: 'ok',
                  data: {
                    assessment: exposurePublic.assessment,
                    applied: true,
                    message: '已完成重新评估',
                  },
                }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/exposure')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: exposureBody,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: trend24h,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 100, total: 0 },
            }),
          )
        }
        if (url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(detailJson())
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染评估结果：当前判定/来源/置信度/最近评估时间与证据列表', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read']),
      csrfToken: null,
      initialized: true,
    })
    stubExposureFetch()
    renderDrawer()

    expect(await screen.findByText('暴露面判定')).toBeInTheDocument()
    // 当前判定（PUBLIC→外网）与来源（TRAFFIC_OBSERVED→流量观测）
    expect(await screen.findByText('外网')).toBeInTheDocument()
    expect(screen.getByText('流量观测')).toBeInTheDocument()
    // 置信度（HIGH→高）与最近评估时间（与 formatDateTime 同一口径，避免时区脆弱性）
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(
      screen.getByText(formatDateTime('2026-08-12T06:00:00Z')),
    ).toBeInTheDocument()
    // 证据列表（summary 后端已生成中文，逐条渲染）
    expect(
      screen.getByText('近 7 天观测到 3 个公网来源指纹，覆盖 5 个自然日'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('归属域名 api.example.com 解析至公网地址'),
    ).toBeInTheDocument()
  })

  it('重新评估：api_asset.edit 权限下展示按钮，点击触发 POST，提示成功并重新查询', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: 'csrf-token',
      initialized: true,
    })
    stubExposureFetch()
    renderDrawer()

    fireEvent.click(await screen.findByRole('button', { name: /重新评估/ }))
    await waitFor(() => {
      const postCall = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes(
            '/api-security/endpoints/e1/exposure/reassess',
          ) && (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(postCall).toBeTruthy()
    })
    expect(await screen.findByText('已完成重新评估')).toBeInTheDocument()
    // 成功后失效并重新查询 exposure（初次加载 + 失效后各一次）
    await waitFor(() => {
      const gets = (fetch as Mock).mock.calls.filter(
        (c) =>
          String(c[0]).endsWith('/api-security/endpoints/e1/exposure') &&
          (c[1] as RequestInit | undefined)?.method === 'GET',
      )
      expect(gets.length).toBeGreaterThanOrEqual(2)
    })
  })

  it('无 api_asset.edit 权限时不展示重新评估按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read']),
      csrfToken: null,
      initialized: true,
    })
    stubExposureFetch()
    renderDrawer()

    expect(await screen.findByText('外网')).toBeInTheDocument()
    expect(
      screen.queryByRole('button', { name: /重新评估/ }),
    ).not.toBeInTheDocument()
  })

  it('未评估（assessment 为 null）：展示「暂无评估结果」空态而非报错', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read']),
      csrfToken: null,
      initialized: true,
    })
    stubExposureFetch(exposureEmpty)
    renderDrawer()

    expect(await screen.findByText('暴露面判定')).toBeInTheDocument()
    expect(await screen.findByText('暂无评估结果')).toBeInTheDocument()
  })
})

describe('EndpointDetailDrawer 资产档案', () => {
  /** 档案 mock：趋势/模型/暴露面为空数据；PATCH 默认回显请求体中的档案 */
  function stubProfileFetch() {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        if (
          init?.method === 'PATCH' &&
          url.endsWith('/api-security/endpoints/e1')
        ) {
          const body = JSON.parse(String(init.body)) as Record<string, unknown>
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                endpoint: { ...endpoint, asset: body },
                message: '资产信息已更新',
              },
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: trend24h,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/exposure')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: exposureEmpty,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/models')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 100, total: 0 },
            }),
          )
        }
        if (url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(detailJson())
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('渲染档案字段、多标签与只读项（互联网暴露/日均调用量）', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: null,
      initialized: true,
    })
    stubProfileFetch()
    renderDrawer()

    expect(
      await screen.findByDisplayValue('XX集团金融事业部'),
    ).toBeInTheDocument()
    expect(screen.getByDisplayValue('客户经营管理平台')).toBeInTheDocument()
    expect(screen.getByDisplayValue('张XX')).toBeInTheDocument()
    expect(screen.getByDisplayValue('李XX')).toBeInTheDocument()
    expect(screen.getByDisplayValue('王XX')).toBeInTheDocument()
    // 枚举中文词表：重要数据 / 三级 / Token
    expect(screen.getByText('重要数据')).toBeInTheDocument()
    expect(screen.getByText('三级')).toBeInTheDocument()
    expect(screen.getByText('Token')).toBeInTheDocument()
    // 多标签
    expect(screen.getByText('对账')).toBeInTheDocument()
    expect(screen.getByText('第三方回调')).toBeInTheDocument()
    // 只读项：互联网暴露（asset.exposure=PUBLIC → 是）与日均调用量千分位
    expect(screen.getByText('是')).toBeInTheDocument()
    expect(screen.getByText('日均 18,721 次（近 7 天）')).toBeInTheDocument()
  })

  it('编辑所属单位后保存：PATCH 提交完整档案表单且保留其他字段', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.edit']),
      csrfToken: 'csrf-token',
      initialized: true,
    })
    stubProfileFetch()
    renderDrawer()

    const input = await screen.findByDisplayValue('XX集团金融事业部')
    fireEvent.change(input, { target: { value: 'XX集团银行事业部' } })
    const saveBtn = screen.getByRole('button', { name: '保存档案' })
    expect(saveBtn).not.toBeDisabled()
    fireEvent.click(saveBtn)

    await waitFor(() => {
      const patchCall = (fetch as Mock).mock.calls.find(
        (c) => (c[1] as RequestInit | undefined)?.method === 'PATCH',
      )
      expect(patchCall).toBeTruthy()
      expect(
        JSON.parse(String((patchCall![1] as RequestInit).body)),
      ).toMatchObject({
        organization: 'XX集团银行事业部',
        business_system: '客户经营管理平台',
        owner: '张XX',
        technical_owner: '李XX',
        data_owner: '王XX',
        data_level: 'IMPORTANT',
        api_level: 'LEVEL_3',
        auth_type: 'TOKEN',
        tags: ['对账', '第三方回调'],
      })
    })
    expect(await screen.findByText('资产信息已更新')).toBeInTheDocument()
  })

  it('无 api_asset.edit 权限：表单禁用且无保存档案按钮', async () => {
    useAuthStore.setState({
      user: makeUser(['api_asset.read']),
      csrfToken: null,
      initialized: true,
    })
    stubProfileFetch()
    renderDrawer()

    expect(await screen.findByDisplayValue('XX集团金融事业部')).toBeDisabled()
    expect(
      screen.queryByRole('button', { name: '保存档案' }),
    ).not.toBeInTheDocument()
  })
})

describe('EndpointDetailDrawer 响应 Schema', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('在接口详情中读取真实运行时响应 Schema', async () => {
    useAuthStore.setState({
      user: makeUser(['api_model.read']),
      csrfToken: null,
      initialized: true,
    })
    stubFetch()
    renderDrawer()
    expect(await screen.findByText('响应 Schema（运行时）')).toBeInTheDocument()
    expect(await screen.findByText('200')).toBeInTheDocument()
    expect(screen.getByText('18')).toBeInTheDocument()
    await waitFor(() => {
      expect(
        (fetch as Mock).mock.calls.some((call) =>
          String(call[0]).includes(
            '/api-security/endpoints/e1/response-schemas',
          ),
        ),
      ).toBe(true)
    })
  })
})

describe('EndpointDetailDrawer 参数格式候选', () => {
  function parameterFixture(
    parameterName: string,
    observedConstraints: Record<string, unknown>,
  ) {
    return {
      id: `param-${parameterName}`,
      model_version_id: 'mv1',
      direction: 'REQUEST',
      location: 'QUERY',
      structured_path: parameterName,
      parameter_name: parameterName,
      base_type: 'string',
      semantic_type: '',
      required: false,
      nullable: false,
      empty_allowed: false,
      observed_constraints: observedConstraints,
      recommended_constraints: {},
      confirmed_constraints: {},
      sensitivity_level: 'UNKNOWN',
      confidence: 0.9,
      created_at: '2026-07-10T00:00:00Z',
    }
  }

  function stubParameterFetch(parameters: unknown[]) {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api-security/endpoints/e1/traffic-trend')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: trend24h,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/exposure')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: exposureEmpty,
            }),
          )
        }
        if (url.includes('/api-security/endpoints/e1/response-schemas')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [] },
            }),
          )
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
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: parameters,
                page: 1,
                page_size: 100,
                total: parameters.length,
              },
            }),
          )
        }
        if (url.endsWith('/api-security/endpoints/e1')) {
          return Promise.resolve(detailJson())
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  }

  async function formatCandidateCell(
    parameterName: string,
  ): Promise<HTMLTableCellElement> {
    const name = await screen.findByText(parameterName)
    const row = name.closest('tr')
    expect(row).not.toBeNull()
    return row!.cells[7]!
  }

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('仅从观测约束展示 UUID 格式标签与实际占比', async () => {
    stubParameterFetch([
      {
        ...parameterFixture('request_id', {
          format_candidate: 'UUID',
          format_candidate_ratio: 0.9,
        }),
        recommended_constraints: {
          format_candidate: 'EMAIL',
          format_candidate_ratio: 1,
        },
        confirmed_constraints: {
          format_candidate: 'DATE',
          format_candidate_ratio: 1,
        },
      },
    ])
    renderDrawer()

    expect(
      await screen.findByRole('columnheader', { name: '格式候选' }),
    ).toBeInTheDocument()
    expect(await formatCandidateCell('request_id')).toHaveTextContent(
      'UUID 90%',
    )
    expect(screen.queryByText('邮箱 100%')).not.toBeInTheDocument()
    expect(screen.queryByText('日期 100%')).not.toBeInTheDocument()
  })

  it('未知格式、旧观测及候选或比例缺失均展示占位符', async () => {
    stubParameterFetch([
      parameterFixture('unknown_format', {
        format_candidate: 'ULID',
        format_candidate_ratio: 0.95,
      }),
      parameterFixture('legacy_observation', {
        format_sample_count: 20,
        format_counts: { UUID: 20 },
      }),
      parameterFixture('missing_candidate', {
        format_candidate_ratio: 0.9,
      }),
      parameterFixture('missing_ratio', { format_candidate: 'EMAIL' }),
    ])
    renderDrawer()

    for (const parameterName of [
      'unknown_format',
      'legacy_observation',
      'missing_candidate',
      'missing_ratio',
    ]) {
      expect((await formatCandidateCell(parameterName)).textContent).toBe('-')
    }
    expect(screen.queryByText('ULID')).not.toBeInTheDocument()
    expect(screen.queryByText('95%')).not.toBeInTheDocument()
  })

  it('非数值或超出 0 到 1 范围的比例不展示', async () => {
    stubParameterFetch([
      parameterFixture('string_ratio', {
        format_candidate: 'UUID',
        format_candidate_ratio: '0.9',
      }),
      parameterFixture('negative_ratio', {
        format_candidate: 'UUID',
        format_candidate_ratio: -0.01,
      }),
      parameterFixture('excessive_ratio', {
        format_candidate: 'UUID',
        format_candidate_ratio: 1.01,
      }),
      parameterFixture('null_ratio', {
        format_candidate: 'UUID',
        format_candidate_ratio: null,
      }),
    ])
    renderDrawer()

    for (const parameterName of [
      'string_ratio',
      'negative_ratio',
      'excessive_ratio',
      'null_ratio',
    ]) {
      expect((await formatCandidateCell(parameterName)).textContent).toBe('-')
    }
    expect(screen.queryByText(/UUID\s/)).not.toBeInTheDocument()
  })
})
