import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RequestPcapEvidence from '../RequestPcapEvidence'
import { requestPcapApi, type RequestPcapItem } from '../../../api/requestPcap'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

const evidence: RequestPcapItem = {
  artifact_id: '055c010d-f328-4c32-95f9-b995744068ae', gateway_node_id: 'gw-1', capture_point: 'GATEWAY_EGRESS',
  state: 'HOT', storage_tier: 'HOT', capture_started_at: '2026-11-17T01:00:00Z', capture_ended_at: '2026-11-17T01:01:00Z',
  packet_count: 6, dropped_count: 0, truncated: false, plaintext_size_bytes: 4096, ciphertext_size_bytes: 4200,
  plaintext_sha256: 'a'.repeat(64), ciphertext_sha256: 'b'.repeat(64), expires_at: '2026-11-18T01:01:00Z',
  integrity_status: 'UNVERIFIED', match_status: 'MATCHED', match_basis: 'HTTP1_REQUEST_ID', coverage: 'CONNECTION',
  candidate_count: 1, first_packet_no: 3, last_packet_no: 6, download_eligible: false, download_blocked_reason: 'VERIFICATION_REQUIRED',
}

function response(data: unknown, status = 200) {
  return new Response(JSON.stringify({ code: status < 400 ? 'SUCCESS' : 'INVALID_ARGUMENT', data, message: status < 400 ? '成功' : '密码错误' }), { status, headers: { 'Content-Type': 'application/json' } })
}

function renderEvidence() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
  return render(<QueryClientProvider client={client}><RequestPcapEvidence requestId="req-pcap-1" /></QueryClientProvider>)
}

function setPermissions(permissions: string[]) {
  const user: CurrentUser = { id: 'user-1', username: 'auditor', display_name: '审计员', status: 'ACTIVE', roles: [], permissions, must_change_password: false }
  useAuthStore.getState().setSession(user, 'csrf-pcap-test')
}

describe('RequestPcapEvidence', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn(() => Promise.resolve(response({ request_id: 'req-pcap-1', items: [evidence] }))))
  })
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
    useAuthStore.getState().reset()
  })

  it('无独立读取权限时不请求PCAP接口', () => {
    setPermissions(['access_logs.read'])
    renderEvidence()
    expect(screen.queryByText('PCAP 证据')).not.toBeInTheDocument()
    expect(fetch).not.toHaveBeenCalled()
  })

  it('填写理由后核验真实证据并更新可下载状态', async () => {
    setPermissions(['request_pcap.read', 'request_pcap.verify'])
    renderEvidence()
    expect(await screen.findByText('未核验')).toBeInTheDocument()
    expect(screen.getByText('连接级 PCAP 可能包含同连接的其他请求，导出前请确认授权范围。')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '完整性核验' }))
    const verifyButton = screen.getByRole('button', { name: '开始核验' })
    expect(verifyButton).toBeDisabled()
    fireEvent.change(screen.getByLabelText('核验理由'), { target: { value: '检查攻击证据' } })
    ;(fetch as Mock).mockImplementation((input, init) => {
      if (String(input).includes('/verify')) {
        expect(init?.method).toBe('POST')
        expect(init?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf-pcap-test' })
        expect(JSON.parse(String(init?.body))).toEqual({ request_id: 'req-pcap-1', reason: '检查攻击证据' })
        return Promise.resolve(response({ ...evidence, integrity_status: 'PASS', download_eligible: true }))
      }
      return Promise.resolve(response({ request_id: 'req-pcap-1', items: [evidence] }))
    })
    fireEvent.click(verifyButton)
    expect(await screen.findByText('完整性通过')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '申请派生下载' })).not.toBeInTheDocument()
  })

  it('密码二次确认后只发起一次短时派生下载', async () => {
    setPermissions(['request_pcap.read', 'request_pcap.download'])
    vi.spyOn(requestPcapApi, 'downloadUrl').mockReturnValue('/api/v1/request-pcap/artifacts/test/download?grant_id=grant-1')
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {})
    ;(fetch as Mock).mockImplementation((input, init) => {
      if (String(input).includes('/download-grants')) {
        expect(init?.method).toBe('POST')
        expect(init?.headers).toMatchObject({ 'X-CSRF-Token': 'csrf-pcap-test' })
        expect(JSON.parse(String(init?.body))).toEqual({ request_id: 'req-pcap-1', reason: '安全事件取证', password: 'current-password' })
        return Promise.resolve(response({ grant_id: 'grant-1', expires_at: '2026-11-17T01:02:00Z', artifact_id: evidence.artifact_id, request_id: 'req-pcap-1' }, 201))
      }
      return Promise.resolve(response({ request_id: 'req-pcap-1', items: [{ ...evidence, integrity_status: 'PASS', download_eligible: true }] }))
    })
    renderEvidence()
    fireEvent.click(await screen.findByRole('button', { name: '申请派生下载' }))
    expect(screen.getByRole('button', { name: '授权并下载' })).toBeDisabled()
    fireEvent.change(screen.getByLabelText('下载理由'), { target: { value: '安全事件取证' } })
    fireEvent.change(screen.getByLabelText('当前账号密码'), { target: { value: 'current-password' } })
    fireEvent.click(screen.getByRole('button', { name: '授权并下载' }))
    await waitFor(() => expect(click).toHaveBeenCalledTimes(1))
    expect(requestPcapApi.downloadUrl).toHaveBeenCalledWith(expect.objectContaining({ grant_id: 'grant-1' }))
    expect(document.querySelector('a[href*="grant_id"]')).toBeNull()
  })

  it('关闭并重开派生下载弹窗时清空密码输入，不残留旧密码', async () => {
    setPermissions(['request_pcap.read', 'request_pcap.download'])
    ;(fetch as Mock).mockImplementation(() =>
      Promise.resolve(response({ request_id: 'req-pcap-1', items: [{ ...evidence, integrity_status: 'PASS', download_eligible: true }] })),
    )
    renderEvidence()
    fireEvent.click(await screen.findByRole('button', { name: '申请派生下载' }))
    const pwdInput = screen.getByLabelText('当前账号密码') as HTMLInputElement
    fireEvent.change(pwdInput, { target: { value: 'Secret@123' } })
    expect(pwdInput.value).toBe('Secret@123')

    // 取消关闭后再次打开，密码必须已清空
    fireEvent.click(screen.getByRole('button', { name: /取\s*消|^Cancel$/ }))
    fireEvent.click(screen.getByRole('button', { name: '申请派生下载' }))
    expect((await screen.findByLabelText('当前账号密码') as HTMLInputElement).value).toBe('')
  })

  it('在途核验完成后写入原 requestId 缓存键，切换 requestId 不污染新请求的 PCAP 缓存', async () => {
    setPermissions(['request_pcap.read', 'request_pcap.verify'])
    let resolveVerify: ((res: Response) => void) | undefined
    const evidence2: RequestPcapItem = {
      ...evidence,
      artifact_id: '11111111-2222-3333-4444-555555555555',
      integrity_status: 'UNVERIFIED',
    }
    ;(fetch as Mock).mockImplementation((input) => {
      const url = String(input)
      if (url.includes('/verify')) {
        return new Promise<Response>((resolve) => {
          resolveVerify = resolve
        })
      }
      if (url.includes('req-pcap-2')) {
        return Promise.resolve(response({ request_id: 'req-pcap-2', items: [evidence2] }))
      }
      return Promise.resolve(response({ request_id: 'req-pcap-1', items: [evidence] }))
    })

    const client = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } })
    const { rerender } = render(
      <QueryClientProvider client={client}>
        <RequestPcapEvidence requestId="req-pcap-1" />
      </QueryClientProvider>,
    )
    expect(await screen.findByText('未核验')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '完整性核验' }))
    fireEvent.change(screen.getByLabelText('核验理由'), { target: { value: '核验1' } })
    fireEvent.click(screen.getByRole('button', { name: '开始核验' }))
    await waitFor(() => expect(resolveVerify).toBeDefined())

    // 核验尚未返回即切换至 req-pcap-2
    rerender(
      <QueryClientProvider client={client}>
        <RequestPcapEvidence requestId="req-pcap-2" />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(client.getQueryData(['request-pcap', 'req-pcap-2'])).toBeTruthy())

    // req-pcap-1 的核验结果晚到：只能更新 req-pcap-1 缓存，不得污染 req-pcap-2
    resolveVerify!(response({ ...evidence, integrity_status: 'PASS', download_eligible: true }))
    await waitFor(() => {
      const cache1 = client.getQueryData<{ items: RequestPcapItem[] }>(['request-pcap', 'req-pcap-1'])
      expect(cache1?.items[0].integrity_status).toBe('PASS')
    })
    const cache2 = client.getQueryData<{ request_id: string; items: RequestPcapItem[] }>(['request-pcap', 'req-pcap-2'])
    expect(cache2?.request_id).toBe('req-pcap-2')
    expect(cache2?.items[0].artifact_id).toBe(evidence2.artifact_id)
    expect(cache2?.items[0].integrity_status).toBe('UNVERIFIED')
  })
})
