import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import LicensePage from '../LicensePage'
import { useAuthStore } from '../../../stores/auth'
import { useLicenseStore } from '../../../stores/license'
import type { CurrentUser, LicenseHistoryItem, LicenseState } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
    permissions,
    must_change_password: false,
  }
}

function makeState(partial: Partial<LicenseState>): LicenseState {
  return {
    valid: false,
    product: '',
    quotas: { max_applications: 0, max_api_endpoints: 0, max_qps: 0 },
    features: [],
    expires_at: null,
    license_id: '',
    customer: '',
    license_type: '',
    reason: '',
    host_fingerprint: '',
    ...partial,
  }
}

function makeHistoryItem(partial: Partial<LicenseHistoryItem>): LicenseHistoryItem {
  return {
    id: 'r1',
    license_id: 'LIC-2025-0099',
    license_type: 'FORMAL',
    product: 'wdsp',
    customer: '历史客户',
    status: 'ACTIVE',
    imported_by: null,
    imported_at: '2026-08-20T08:00:00Z',
    expires_at: null,
    perpetual: true,
    machine_fingerprint: '',
    quotas: { max_applications: 10, max_api_endpoints: 100, max_qps: 0 },
    features: [],
    created_at: '2026-08-20T08:00:00Z',
    ...partial,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** 默认 fetch mock：历史分页返回一条记录；导入返回导入后的最新状态 */
function mockFetch(opts: { importState?: LicenseState; importError?: { status: number; message: string } } = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = init?.method ?? 'GET'
    if (url.includes('/license/import') && method === 'POST') {
      if (opts.importError) {
        return Promise.resolve(
          jsonResponse(opts.importError.status, {
            code: 'LICENSE_INVALID',
            message: opts.importError.message,
          }),
        )
      }
      return Promise.resolve(
        jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: opts.importState }),
      )
    }
    if (url.includes('/license/history')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { items: [makeHistoryItem({})], page: 1, page_size: 20, total: 1 },
        }),
      )
    }
    if (url.includes('/product/edition')) {
      return Promise.resolve(
        jsonResponse(200, {
          code: 'SUCCESS',
          message: 'ok',
          data: { edition: 'wdsp', api_dynamic_protection: true, web_waf_enabled: true },
        }),
      )
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <LicensePage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('LicensePage 授权管理页', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', mockFetch())
    useAuthStore.setState({
      user: makeUser(['license.manage', 'license.read']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useLicenseStore.getState().reset()
    useAuthStore.getState().reset()
  })

  it('有效授权：状态卡/配额用量/指纹复制/历史列表完整渲染', async () => {
    useLicenseStore.setState({
      status: makeState({
        valid: true,
        product: 'wdsp',
        license_type: 'FORMAL',
        customer: '某某公司',
        license_id: 'LIC-2026-0001',
        expires_at: '2099-12-31T00:00:00Z',
        quotas: { max_applications: 10, max_api_endpoints: 100, max_qps: 0 },
        usage: { applications: 4, api_endpoints: 20 },
        host_fingerprint: 'sha256:abcdef0123456789',
        protection_state: {
          schema_version: 'wdsp-license-protection/v1',
          protection_form: 'STANDARD_OFFLINE',
          commercial_authorization: 'AUTHORIZED',
          artifact_integrity: 'VERIFIED',
          gateway_protection: 'PROTECTED',
          confidential_computing: 'UNSUPPORTED',
          recovery: 'NONE',
        },
      }),
      initialized: true,
    })
    const { container } = renderPage()

    expect(screen.getByText('授权有效')).toBeInTheDocument()
    expect(screen.getByText('九章Web动态防护系统')).toBeInTheDocument()
    expect(screen.getByText('正式授权')).toBeInTheDocument()
    expect(screen.getByText('某某公司')).toBeInTheDocument()
    expect(screen.getByText('LIC-2026-0001')).toBeInTheDocument()
    // 永久之外的远期到期正常展示日期；QPS=0 显示「不限」
    expect(screen.getByText('全局 QPS')).toBeInTheDocument()
    expect(screen.getByText('不限')).toBeInTheDocument()
    // usage 存在时展示 用量/上限
    expect(screen.getByText('4 / 10')).toBeInTheDocument()
    expect(screen.getByText('20 / 100')).toBeInTheDocument()
    // 本机指纹 + 一键复制按钮 + 提示
    expect(screen.getByText('sha256:abcdef0123456789')).toBeInTheDocument()
    expect(container.querySelector('.ant-typography-copy')).toBeTruthy()
    expect(screen.getByText(/请将本机指纹发给厂家/)).toBeInTheDocument()
    expect(screen.getByText('标准离线交付')).toBeInTheDocument()
    expect(screen.getByText('完整性已验证')).toBeInTheDocument()
    expect(screen.getByText('网关防护可用')).toBeInTheDocument()
    expect(screen.getByText('当前平台不支持')).toBeInTheDocument()
    // 有 license.manage：拖拽导入区可见
    expect(screen.getByText(/拖拽 .lic 授权文件/)).toBeInTheDocument()
    // 历史列表加载
    expect(await screen.findByText('生效中')).toBeInTheDocument()
    expect(screen.getByText('永久')).toBeInTheDocument()
  })

  it('无效授权：大状态/无效原因展示，配额卡不渲染', () => {
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '机器指纹不匹配', host_fingerprint: 'sha256:host' }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText('授权无效')).toBeInTheDocument()
    expect(screen.getByText('机器指纹不匹配')).toBeInTheDocument()
    expect(screen.getByText('未授权')).toBeInTheDocument()
    expect(screen.queryByText('授权配额')).not.toBeInTheDocument()
    expect(screen.queryByText('授权有效')).not.toBeInTheDocument()
  })

  it('旧版状态响应缺少多维字段时：明确提示未知，不推断保护能力', () => {
    useLicenseStore.setState({
      status: makeState({ valid: true, product: 'wdsp' }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText('当前接口未返回多维授权与防护状态')).toBeInTheDocument()
    expect(screen.getByText(/不会据此推断产物完整性/)).toBeInTheDocument()
    expect(screen.queryByText('网关防护可用')).not.toBeInTheDocument()
  })

  it('临期授权（≤7 天）：红色倒计时', () => {
    const inThreeDays = new Date(Date.now() + 3 * 86_400_000).toISOString()
    useLicenseStore.setState({
      status: makeState({
        valid: true,
        product: 'waf',
        license_type: 'TRIAL',
        expires_at: inThreeDays,
      }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText(/剩余 3 天/)).toBeInTheDocument()
    expect(screen.getByText('试用授权')).toBeInTheDocument()
  })

  it('永久授权：到期时间显示「永久」', () => {
    useLicenseStore.setState({
      status: makeState({ valid: true, product: 'api', license_type: 'FORMAL', expires_at: null }),
      initialized: true,
    })
    renderPage()

    // 状态卡与历史列表均可能出现「永久」
    expect(screen.getAllByText('永久').length).toBeGreaterThan(0)
    expect(screen.getByText('九章API安全系统')).toBeInTheDocument()
  })

  it('未采集指纹：提示未采集与部署文档', () => {
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权', host_fingerprint: '' }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText('未采集到本机指纹')).toBeInTheDocument()
    expect(screen.getByText(/详见部署文档/)).toBeInTheDocument()
  })

  it('无 license.manage 权限：导入区显示只读提示', () => {
    useAuthStore.setState({ user: makeUser(['license.read']) })
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText(/无授权导入权限/)).toBeInTheDocument()
    expect(screen.queryByText(/拖拽 .lic 授权文件/)).not.toBeInTheDocument()
  })

  it('无 license.read 权限：历史区显示只读提示且不发历史请求', () => {
    useAuthStore.setState({ user: makeUser(['license.manage']) })
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    renderPage()

    expect(screen.getByText(/无授权历史查看权限/)).toBeInTheDocument()
    expect(
      (fetch as ReturnType<typeof vi.fn>).mock.calls.some((c) =>
        String(c[0]).includes('/license/history'),
      ),
    ).toBe(false)
  })

  it('导入成功：二次确认（展示文件名与后果）后提交，提示成功并刷新授权状态', async () => {
    const imported = makeState({
      valid: true,
      product: 'wdsp',
      license_type: 'FORMAL',
      customer: '新客户',
      license_id: 'LIC-2026-0002',
    })
    vi.stubGlobal('fetch', mockFetch({ importState: imported }))
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    const { container } = renderPage()

    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    expect(input).toBeTruthy()
    const file = new File(['{"payload":{}}'], 'test.lic', { type: 'application/json' })
    fireEvent.change(input, { target: { files: [file] } })

    // 二次确认：展示文件名与「立即生效并取代当前授权」后果；确认前不得提交
    expect(
      await screen.findByText(/确定导入授权文件「test\.lic」吗？导入后立即生效并取代当前授权/),
    ).toBeInTheDocument()
    expect(
      (fetch as ReturnType<typeof vi.fn>).mock.calls.some((c) =>
        String(c[0]).includes('/license/import'),
      ),
    ).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: /确\s*认\s*导\s*入/ }))

    expect(await screen.findByText('授权导入成功')).toBeInTheDocument()
    expect(useLicenseStore.getState().status?.valid).toBe(true)
    expect(useLicenseStore.getState().status?.customer).toBe('新客户')
    // 生效产品形态可能变化：触发产品能力重载
    expect(
      (fetch as ReturnType<typeof vi.fn>).mock.calls.some((c) =>
        String(c[0]).includes('/product/edition'),
      ),
    ).toBe(true)
  })

  it('导入确认框取消：不发起导入请求', async () => {
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    const { container } = renderPage()

    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, {
      target: { files: [new File(['bad'], 'bad.lic', { type: 'application/json' })] },
    })

    expect(await screen.findByText(/确定导入授权文件「bad\.lic」吗/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /取\s*消|^Cancel$/ }))
    await screen.findByText('导入历史')
    expect(
      (fetch as ReturnType<typeof vi.fn>).mock.calls.some((c) =>
        String(c[0]).includes('/license/import'),
      ),
    ).toBe(false)
  })

  it('导入失败：确认后响应信封 message 原样展示', async () => {
    vi.stubGlobal(
      'fetch',
      mockFetch({ importError: { status: 422, message: '授权文件验签失败' } }),
    )
    useLicenseStore.setState({
      status: makeState({ valid: false, reason: '未导入授权' }),
      initialized: true,
    })
    const { container } = renderPage()

    const input = container.querySelector('input[type="file"]') as HTMLInputElement
    fireEvent.change(input, {
      target: { files: [new File(['bad'], 'bad.lic', { type: 'application/json' })] },
    })
    fireEvent.click(
      await screen.findByRole('button', { name: /确\s*认\s*导\s*入/ }),
    )

    expect(await screen.findByText('授权文件验签失败')).toBeInTheDocument()
    // 失败不改变现有状态
    expect(useLicenseStore.getState().status?.valid).toBe(false)
  })

  it('状态加载失败：错误提示与重试入口', () => {
    useLicenseStore.setState({ status: null, initialized: true })
    renderPage()

    expect(screen.getByText('加载授权状态失败')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /重\s*试/ })).toBeInTheDocument()
  })
})
