import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { trafficAgentsApi } from '../trafficAgents'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(data: unknown) {
  const fn = vi.fn<
    (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>
  >(() =>
    Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data })),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('trafficAgentsApi', () => {
  beforeEach(() => {
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('agent 解码后端 policy_binding（policy_name / policy_version / bound_by / bound_at）并归一化 null interfaces', async () => {
    const backendAgent = {
      agent_id: 'a3c98f51-0000-4000-8000-000000000001',
      hostname: 'web-prod-01',
      ip: '10.0.1.10',
      os: 'Rocky Linux 9',
      kernel: '5.14.0',
      arch: 'x86_64',
      version: '1.0.0',
      status: 'ONLINE',
      disabled: false,
      last_seen: '2026-09-01T10:00:00Z',
      last_metrics: null,
      config_version: 5,
      applied_config_version: 5,
      clock_offset_ms: 12,
      health_score: 100,
      health_reasons: [],
      created_at: '2026-08-01T00:00:00Z',
      interfaces: null,
      policy_binding: {
        policy_id: 'pol-1',
        policy_name: 'production-web',
        policy_version: 4,
        bound_by: 'secops',
        bound_at: '2026-09-01T09:00:00Z',
      },
      http_event_schemas: [1, 2],
    }
    const fetchMock = stubFetch(backendAgent)

    const detail = await trafficAgentsApi.agent('a3c98f51-0000-4000-8000-000000000001')
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/traffic/agents/a3c98f51-0000-4000-8000-000000000001',
    )
    expect(detail.interfaces).toEqual([])
    expect(detail.policy_binding).toEqual({
      policy_id: 'pol-1',
      policy_name: 'production-web',
      policy_version: 4,
      bound_by: 'secops',
      bound_at: '2026-09-01T09:00:00Z',
    })
  })

  it('agentEvents 解码 id / agent_id / RFC3339 ts 并归一化 null items', async () => {
    const backendEvents = {
      items: [
        {
          id: 101,
          agent_id: 'a3c98f51-0000-4000-8000-000000000001',
          ts: '2026-09-01T10:00:00Z',
          event_type: 'request',
          flow_id: 'flow-1',
          src_ip: '10.1.1.10',
          src_port: 51234,
          dst_ip: '10.1.2.20',
          dst_port: 8080,
          protocol: 'tcp',
          direction: 'ingress',
          bytes_in: 120,
          bytes_out: 2048,
          tls_visibility: 'PLAINTEXT',
        },
      ],
      total: 1,
    }
    const fetchMock = stubFetch(backendEvents)

    const res = await trafficAgentsApi.agentEvents('agent-1', { page: 1, page_size: 20 })
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/traffic/agents/agent-1/events?page=1&page_size=20',
    )
    expect(res.total).toBe(1)
    expect(res.items[0].id).toBe(101)
    expect(res.items[0].agent_id).toBe('a3c98f51-0000-4000-8000-000000000001')
    expect(res.items[0].ts).toBe('2026-09-01T10:00:00Z')

    stubFetch({ items: null, total: 0 })
    const emptyRes = await trafficAgentsApi.agentEvents('agent-1', { page: 2, page_size: 20 })
    expect(emptyRes.items).toEqual([])
  })

  it('enrollmentTokens 解码 status 与可空时间戳字段并归一化 null items', async () => {
    const backendTokens = {
      items: [
        {
          id: 'tok-active',
          label: 'prod-1',
          status: 'ACTIVE',
          expires_at: '2026-09-02T00:00:00Z',
          used_at: null,
          used_by_agent_id: null,
          revoked_at: null,
          created_by: 'secops',
          created_at: '2026-09-01T00:00:00Z',
        },
        {
          id: 'tok-used',
          label: 'prod-2',
          status: 'USED',
          expires_at: '2026-09-02T00:00:00Z',
          used_at: '2026-09-01T01:00:00Z',
          used_by_agent_id: 'a3c98f51-0000-4000-8000-000000000001',
          revoked_at: null,
          created_by: 'secops',
          created_at: '2026-09-01T00:00:00Z',
        },
        {
          id: 'tok-revoked',
          label: 'prod-3',
          status: 'REVOKED',
          expires_at: '2026-09-02T00:00:00Z',
          used_at: null,
          used_by_agent_id: null,
          revoked_at: '2026-09-01T00:30:00Z',
          created_by: 'secops',
          created_at: '2026-09-01T00:00:00Z',
        },
        {
          id: 'tok-expired',
          label: 'prod-4',
          status: 'EXPIRED',
          expires_at: '2026-08-31T00:00:00Z',
          used_at: null,
          used_by_agent_id: null,
          revoked_at: null,
          created_by: 'secops',
          created_at: '2026-08-30T00:00:00Z',
        },
      ],
      total: 4,
    }
    const fetchMock = stubFetch(backendTokens)

    const res = await trafficAgentsApi.enrollmentTokens()
    expect(String(fetchMock.mock.calls[0][0])).toBe(
      '/api/v1/traffic/agents/enrollment-tokens',
    )
    expect(res.total).toBe(4)
    expect(res.items.map((t) => t.status)).toEqual([
      'ACTIVE',
      'USED',
      'REVOKED',
      'EXPIRED',
    ])
    expect(res.items[1].used_at).toBe('2026-09-01T01:00:00Z')
    expect(res.items[1].used_by_agent_id).toBe(
      'a3c98f51-0000-4000-8000-000000000001',
    )
    expect(res.items[2].revoked_at).toBe('2026-09-01T00:30:00Z')

    stubFetch({ items: null, total: 0 })
    const emptyRes = await trafficAgentsApi.enrollmentTokens()
    expect(emptyRes.items).toEqual([])
  })
})
