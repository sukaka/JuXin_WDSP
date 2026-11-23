import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import EventAnalysisPage from '../EventAnalysisPage'
import { useAuthStore } from '../../../../stores/auth'
import { parsePositiveRuleId } from '../../../../utils/ai'
import type { CurrentUser } from '../../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secadmin',
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

let analyzeCalls: { url: string; body: Record<string, unknown> }[]

function renderPage(entry = '/ai/event-analysis') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[entry]}>
        <AntdApp>
          <EventAnalysisPage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('EventAnalysisPage · 误报研判与事件分析 rule_id 数值契约', () => {
  beforeEach(() => {
    analyzeCalls = []
    useAuthStore.setState({
      user: makeUser(['ai.event_analysis.use', 'ai.false_positive_analysis.use']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (url.includes('/api/v1/applications')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], page: 1, page_size: 100, total: 0 },
            }),
          )
        }
        if (method === 'POST' && url.includes('/ai/analyze/')) {
          analyzeCalls.push({
            url,
            body: init?.body ? (JSON.parse(String(init.body)) as Record<string, unknown>) : {},
          })
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { task_id: 'task-1', answer: '分析完成', steps: [], evidence: [] },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    useAuthStore.getState().reset()
    vi.unstubAllGlobals()
  })

  it('误报研判 Tab：输入 rule_id=942100 时以数字 number（而非字符串）提交', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '误报研判' }))
    const fpPanel = screen.getByRole('tabpanel', { name: '误报研判' })
    const ruleInput = within(fpPanel).getByRole('spinbutton')
    fireEvent.change(ruleInput, { target: { value: '942100' } })
    fireEvent.click(within(fpPanel).getByRole('button', { name: /开始研判/ }))

    await waitFor(() => expect(analyzeCalls).toHaveLength(1))
    expect(analyzeCalls[0].url).toBe('/api/v1/ai/analyze/false-positive')
    expect(analyzeCalls[0].body.rule_id).toBe(942100)
    expect(typeof analyzeCalls[0].body.rule_id).toBe('number')
  })

  it('误报研判 Tab：仅填 event_id 且 rule_id 留空或清空时不发送 rule_id', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '误报研判' }))
    const fpPanel = screen.getByRole('tabpanel', { name: '误报研判' })
    const eventInput = within(fpPanel).getByPlaceholderText('安全事件 UUID（可选）')
    const ruleInput = within(fpPanel).getByRole('spinbutton')

    fireEvent.change(eventInput, { target: { value: '11111111-2222-3333-4444-555555555555' } })
    fireEvent.change(ruleInput, { target: { value: '942100' } })
    fireEvent.change(ruleInput, { target: { value: '' } })
    fireEvent.click(within(fpPanel).getByRole('button', { name: /开始研判/ }))

    await waitFor(() => expect(analyzeCalls).toHaveLength(1))
    expect(analyzeCalls[0].body.event_id).toBe('11111111-2222-3333-4444-555555555555')
    expect('rule_id' in analyzeCalls[0].body).toBe(false)
  })

  it('误报研判 Tab：event_id 与 rule_id 均为空时提示警告且不发请求', async () => {
    renderPage()
    fireEvent.click(screen.getByRole('tab', { name: '误报研判' }))
    const fpPanel = screen.getByRole('tabpanel', { name: '误报研判' })
    fireEvent.click(within(fpPanel).getByRole('button', { name: /开始研判/ }))

    expect(await screen.findByText('请输入事件 ID 或规则 ID')).toBeInTheDocument()
    expect(analyzeCalls).toHaveLength(0)
  })

  it('parsePositiveRuleId：空值合法回退 undefined，正整数转 number，0/负数/小数/非数字判非法', () => {
    expect(parsePositiveRuleId(undefined)).toEqual({ value: undefined, valid: true })
    expect(parsePositiveRuleId(null)).toEqual({ value: undefined, valid: true })
    expect(parsePositiveRuleId('')).toEqual({ value: undefined, valid: true })
    expect(parsePositiveRuleId('   ')).toEqual({ value: undefined, valid: true })
    expect(parsePositiveRuleId(942100)).toEqual({ value: 942100, valid: true })
    expect(parsePositiveRuleId(' 942100 ')).toEqual({ value: 942100, valid: true })
    expect(parsePositiveRuleId(0)).toEqual({ value: undefined, valid: false })
    expect(parsePositiveRuleId(-5)).toEqual({ value: undefined, valid: false })
    expect(parsePositiveRuleId(12.5)).toEqual({ value: undefined, valid: false })
    expect(parsePositiveRuleId('abc')).toEqual({ value: undefined, valid: false })
  })

  it('事件分析 Tab：rule_id=942100 以数字 number 提交到 /ai/analyze/event', async () => {
    renderPage()
    const eventPanel = screen.getByRole('tabpanel', { name: '事件分析' })
    const ruleInput = within(eventPanel).getByRole('spinbutton', { name: '规则 ID' })
    fireEvent.change(ruleInput, { target: { value: '942100' } })
    fireEvent.click(within(eventPanel).getByRole('button', { name: /开始分析/ }))

    await waitFor(() => expect(analyzeCalls).toHaveLength(1))
    expect(analyzeCalls[0].url).toBe('/api/v1/ai/analyze/event')
    expect(analyzeCalls[0].body.rule_id).toBe(942100)
    expect(typeof analyzeCalls[0].body.rule_id).toBe('number')
  })
})
