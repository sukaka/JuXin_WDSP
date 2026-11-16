import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  API_ENDPOINT_GROUP_CODE_PATTERN,
  apiEndpointGroupsApi,
  normalizeApiEndpointGroupCode,
  toApiEndpointGroupUpdateInput,
  type ApiEndpointGroup,
} from '../apiEndpointGroups'
import { setCsrfToken } from '../client'

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(
    JSON.stringify({ code: 'SUCCESS', message: 'ok', data }),
    { status, headers: { 'Content-Type': 'application/json' } },
  )
}

function stubFetch(data: unknown, status = 200) {
  const fetchMock = vi.fn<
    (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  >(() => Promise.resolve(jsonResponse(data, status)))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

const GROUP: ApiEndpointGroup = {
  id: 'group-1',
  application_id: 'app-1',
  application_name: '订单应用',
  code: 'ORDER_CENTER',
  name: '订单中心',
  description: '订单相关接口',
  enabled: true,
  endpoint_count: 2,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
}

describe('apiEndpointGroupsApi', () => {
  beforeEach(() => setCsrfToken(null))
  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
  })

  it('list 使用冻结前缀并携带应用过滤、分页，空 items 归一化为数组', async () => {
    const fetchMock = stubFetch({
      items: null,
      page: 2,
      page_size: 10,
      total: 0,
    })
    const result = await apiEndpointGroupsApi.list({
      application_id: 'app-1',
      page: 2,
      page_size: 10,
    })
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/endpoint-groups?application_id=app-1&page=2&page_size=10',
    )
    expect(result.items).toEqual([])
    expect(result.page).toBe(2)
  })

  it('get 读取指定分组详情', async () => {
    const fetchMock = stubFetch(GROUP)
    await expect(apiEndpointGroupsApi.get('group-1')).resolves.toEqual(GROUP)
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/endpoint-groups/group-1',
    )
    expect(fetchMock.mock.calls[0][1]?.method).toBe('GET')
  })

  it('create 提交 application_id 和规范化后的完整字段，并沿用 CSRF 请求头', async () => {
    setCsrfToken('test-csrf')
    const fetchMock = stubFetch(GROUP, 201)
    await apiEndpointGroupsApi.create({
      application_id: 'app-1',
      code: 'ORDER_CENTER',
      name: '订单中心',
      description: '订单相关接口',
      enabled: true,
    })
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/endpoint-groups')
    expect(init?.method).toBe('POST')
    expect(JSON.parse(String(init?.body))).toEqual({
      application_id: 'app-1',
      code: 'ORDER_CENTER',
      name: '订单中心',
      description: '订单相关接口',
      enabled: true,
    })
    expect(init?.headers).toMatchObject({ 'X-CSRF-Token': 'test-csrf' })
  })

  it('update 使用 PUT，启停帮助函数保留其他字段且不携带出参字段', async () => {
    const fetchMock = stubFetch({ ...GROUP, enabled: false })
    const body = toApiEndpointGroupUpdateInput(GROUP, { enabled: false })
    await apiEndpointGroupsApi.update('group-1', body)
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/api-security/endpoint-groups/group-1')
    expect(init?.method).toBe('PUT')
    expect(JSON.parse(String(init?.body))).toEqual({
      code: 'ORDER_CENTER',
      name: '订单中心',
      description: '订单相关接口',
      enabled: false,
    })
  })

  it('remove 使用 DELETE 删除指定分组', async () => {
    const fetchMock = stubFetch(null)
    await apiEndpointGroupsApi.remove('group-1')
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/endpoint-groups/group-1',
    )
    expect(fetchMock.mock.calls[0][1]?.method).toBe('DELETE')
  })

  it('listEndpoints 使用真实 ApiEndpoint 分页结构并归一化空列表', async () => {
    const fetchMock = stubFetch({
      items: null,
      page: 1,
      page_size: 20,
      total: 0,
    })
    const result = await apiEndpointGroupsApi.listEndpoints('group-1', {
      page: 1,
      page_size: 20,
    })
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/endpoint-groups/group-1/endpoints?page=1&page_size=20',
    )
    expect(result.items).toEqual([])
  })

  it('addEndpoint 仅提交 endpoint_id，removeEndpoint 使用冻结成员路径', async () => {
    const fetchMock = stubFetch(null)
    await apiEndpointGroupsApi.addEndpoint('group-1', 'endpoint-1')
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/api-security/endpoint-groups/group-1/endpoints',
    )
    expect(fetchMock.mock.calls[0][1]?.method).toBe('POST')
    expect(JSON.parse(String(fetchMock.mock.calls[0][1]?.body))).toEqual({
      endpoint_id: 'endpoint-1',
    })

    await apiEndpointGroupsApi.removeEndpoint('group-1', 'endpoint-1')
    expect(String(fetchMock.mock.calls[1][0])).toBe(
      '/api/v1/api-security/endpoint-groups/group-1/endpoints/endpoint-1',
    )
    expect(fetchMock.mock.calls[1][1]?.method).toBe('DELETE')
  })
})

describe('接口组编码归一化', () => {
  it('去首尾空白并转为大写', () => {
    expect(normalizeApiEndpointGroupCode('  order_center_2  ')).toBe(
      'ORDER_CENTER_2',
    )
    expect(
      API_ENDPOINT_GROUP_CODE_PATTERN.test(
        normalizeApiEndpointGroupCode('order_center_2'),
      ),
    ).toBe(true)
  })

  it('拒绝数字开头、连字符、空白及空编码', () => {
    for (const value of ['', '1ORDER', 'ORDER-CENTER', 'ORDER CENTER']) {
      expect(API_ENDPOINT_GROUP_CODE_PATTERN.test(value)).toBe(false)
    }
  })
})
