import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BlacklistFromEventModal from '../BlacklistFromEventModal'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const PREFILL = {
  event_id: 'evt-1',
  address: '198.51.100.77',
  rule_type: 'DENY',
  suggested_name: '事件封禁-198.51.100.77',
  suggested_reason: '安全事件联动封禁：SQL_INJECTION（来源事件 evt-1）',
  application_id: 'app-1',
  application_name: '商城站点',
  attack_type: 'SQL_INJECTION',
  severity: 'HIGH',
  related_event_count_24h: 3,
  last_attack_at: '2026-09-10T01:00:00Z',
  hit_rules: [{ rule_id: 942100, rule_name: 'SQL Injection Attack', hits: 3 }],
  suggested_duration_hours: 24,
  protected_hit: false,
  shared_egress_hint: { identity_count: 3, suspected: true },
  existing_deny_rule: null,
}

interface CapturedRequest {
  url: string
  body?: Record<string, unknown>
}

function mockFetch(prefill: unknown, captured: CapturedRequest[]) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/blacklist-prefill')) return ok({ prefill })
    if (url.endsWith('/api/v1/access-rules') && init?.method === 'POST') {
      captured.push({ url, body: JSON.parse(String(init.body)) as Record<string, unknown> })
      return ok({ rule: { id: 'rule-1' } })
    }
    if (url.includes('/access-rules/publish')) {
      captured.push({ url })
      return ok({ task: { id: 'task-1' } })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <BlacklistFromEventModal eventId="evt-1" onClose={() => {}} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('BlacklistFromEventModal', () => {
  let captured: CapturedRequest[]

  beforeEach(() => {
    captured = []
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('展示预填字段（IP/相关事件数/建议时长/命中规则）与疑似共享出口提示', async () => {
    vi.stubGlobal('fetch', mockFetch(PREFILL, captured))
    renderModal()
    expect(await screen.findByText('198.51.100.77')).toBeInTheDocument()
    expect(screen.getByText('3 次')).toBeInTheDocument()
    expect(screen.getByText(/建议 24 小时/)).toBeInTheDocument()
    expect(screen.getByText(/942100/)).toBeInTheDocument()
    expect(screen.getByText(/通过 libinjection 检测到 SQL 注入攻击/)).toBeInTheDocument()
    expect(screen.getByText('疑似共享出口/代理')).toBeInTheDocument()
    // 名称/原因预填
    expect(screen.getByDisplayValue('事件封禁-198.51.100.77')).toBeInTheDocument()
  })

  it('确认创建：携带 source_type=SECURITY_EVENT + source_event_id，默认临时封禁且默认不发布', async () => {
    vi.stubGlobal('fetch', mockFetch(PREFILL, captured))
    renderModal()
    // 等待预填初始化表单（useEffect 回填名称）
    await screen.findByDisplayValue('事件封禁-198.51.100.77')
    fireEvent.click(screen.getByRole('button', { name: '确认创建' }))
    await waitFor(() => expect(captured.some((c) => c.body)).toBe(true))
    const createReq = captured.find((c) => c.body)
    expect(createReq?.body).toMatchObject({
      rule_type: 'DENY',
      address: '198.51.100.77',
      scope_type: 'APPLICATION',
      application_id: 'app-1',
      validity_type: 'TEMPORARY',
      source_type: 'SECURITY_EVENT',
      source_event_id: 'evt-1',
      name: '事件封禁-198.51.100.77',
    })
    expect(typeof createReq?.body?.effective_until).toBe('string')
    // 未勾选立即发布 → 不调用发布接口
    expect(captured.some((c) => c.url.includes('/access-rules/publish'))).toBe(false)
  })

  it('命中保护地址：展示错误提示并禁用确认按钮', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ ...PREFILL, protected_hit: true, protected_name: '核心网关管理口' }, captured),
    )
    renderModal()
    expect(await screen.findByText('该地址命中保护地址，禁止加入黑名单')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '确认创建' })).toBeDisabled()
  })

  it('无身份数据时省略共享出口提示（不编造）', async () => {
    const noEgress: Record<string, unknown> = { ...PREFILL }
    delete noEgress.shared_egress_hint
    vi.stubGlobal('fetch', mockFetch(noEgress, captured))
    renderModal()
    await screen.findByText('198.51.100.77')
    expect(screen.queryByText('疑似共享出口/代理')).not.toBeInTheDocument()
  })

  it('已存在黑名单规则时以中文展示状态', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch(
        {
          ...PREFILL,
          existing_deny_rule: { id: 'r1', name: '历史黑名单', status: 'ACTIVE' },
        },
        captured,
      ),
    )
    renderModal()
    expect(await screen.findByText('该地址已存在黑名单规则')).toBeInTheDocument()
    expect(screen.getByText(/规则「历史黑名单」（状态：生效中）/)).toBeInTheDocument()
  })
})
