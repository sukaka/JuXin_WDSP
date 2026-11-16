import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import VulnIntelPage from '../VulnIntelPage'
import { parseImportJson } from '../../../api/vulnIntel'
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

const ADVISORY = {
  cve_id: 'CVE-2026-0001',
  title: 'PHP 远程代码执行漏洞',
  summary: 'PHP 8.1 在特定配置下存在远程代码执行风险，攻击者可构造恶意请求执行任意代码。',
  severity: 'MEDIUM',
  cvss_score: 7.5,
  published_at: '2026-10-15T00:00:00Z',
  last_modified_at: '2026-10-16T00:00:00Z',
  tech_tags: ['php'],
  references: ['https://nvd.nist.gov/vuln/detail/CVE-2026-0001'],
  source: 'NVD',
}

const OVERVIEW = {
  total: 128,
  recent_7d: 6,
  critical: 5,
  high: 9,
  sources: [
    {
      source: 'NVD',
      status: 'FAILED',
      last_sync_at: '2026-10-21T02:00:00Z',
      records_upserted: 0,
      failure_message: '连接 NVD API 超时',
    },
  ],
}

const DETAIL = {
  advisory: ADVISORY,
  applications: [{ application_id: 'app-1', code: 'mall', name: '商城门户' }],
}

const SETTINGS = { watch_techs: ['php'], min_severity: 'LOW', sync_enabled: true }

const TECH_ASSETS = {
  items: [
    { application_id: 'app-1', code: 'mall', name: '商城门户', tech_tags: ['php'] },
    { application_id: 'app-2', code: 'blog', name: '企业博客', tech_tags: [] },
  ],
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

interface MockOptions {
  importStatus?: number
  syncStatus?: string
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/vuln-intel/overview')) return ok(OVERVIEW)
    if (url.includes('/vuln-intel/settings')) {
      if (init?.method === 'PUT') return ok(SETTINGS)
      return ok(SETTINGS)
    }
    if (url.includes('/vuln-intel/tech-assets')) {
      if (init?.method === 'PUT') return ok({ message: '已保存' })
      return ok(TECH_ASSETS)
    }
    if (url.includes('/vuln-intel/import')) {
      if (opts.importStatus) {
        return Promise.resolve(
          jsonResponse(opts.importStatus, {
            code: 'VALIDATION_FAILED',
            message: '第 1 条 cve_id 格式非法',
            data: null,
          }),
        )
      }
      return ok({ imported: 1, added: 1, updated: 0, alerts: 1 })
    }
    if (url.includes('/vuln-intel/sync')) {
      return ok({ status: opts.syncStatus ?? 'SUCCESS', records_upserted: 5 })
    }
    if (url.includes('/vuln-intel/advisories/')) return ok(DETAIL)
    if (url.includes('/vuln-intel/advisories')) {
      return ok({ items: [ADVISORY], total: 1, page: 1, page_size: 20 })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={['/vuln-intel']}>
          <VulnIntelPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('VulnIntelPage 漏洞情报', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['vuln_intel.read', 'vuln_intel.manage']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('概览卡：总数/近7日/超危/高危与情报源失败原因展示，管理按钮齐全', async () => {
    renderPage()

    expect(await screen.findByText('128')).toBeInTheDocument()
    expect(screen.getByText('漏洞总数')).toBeInTheDocument()
    expect(screen.getByText('近 7 日新增')).toBeInTheDocument()
    expect(screen.getByText('6')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('9')).toBeInTheDocument()
    // 情报源同步状态与失败原因
    expect(screen.getByText(/NVD 失败/)).toBeInTheDocument()
    expect(screen.getByText('NVD 同步失败：连接 NVD API 超时')).toBeInTheDocument()
    // 管理入口（manage 权限）
    expect(screen.getByRole('button', { name: /手动同步/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /手动导入/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /技术资产/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /订阅设置/ })).toBeInTheDocument()
    // 系统告警入口
    expect(screen.getByRole('button', { name: /漏洞情报告警/ })).toBeInTheDocument()
  })

  it('列表渲染：CVE/标题/级别/CVSS/技术标签/发布日期/来源', async () => {
    renderPage()

    expect(await screen.findAllByText('CVE-2026-0001')).not.toHaveLength(0)
    expect(screen.getByText('PHP 远程代码执行漏洞')).toBeInTheDocument()
    expect(screen.getByText('中危')).toBeInTheDocument()
    expect(screen.getByText('7.5')).toBeInTheDocument()
    expect(screen.getByText('PHP')).toBeInTheDocument()
    expect(screen.getByText('2026-10-15')).toBeInTheDocument()
    expect(screen.getByText('NVD')).toBeInTheDocument()
    expect(screen.getByText('共 1 条')).toBeInTheDocument()
  })

  it('关键词过滤：回车后列表请求携带 keyword 参数', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    const input = screen.getByPlaceholderText('搜索 CVE 编号或标题')
    fireEvent.change(input, { target: { value: 'php' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })

    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) =>
        String(c[0]).includes('/vuln-intel/advisories?'),
      )
      expect(calls.some((c) => String(c[0]).includes('keyword=php'))).toBe(true)
    })
  })

  it('详情抽屉：描述、参考链接与受影响应用', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getAllByRole('button', { name: 'CVE-2026-0001' })[0])

    expect(await screen.findByText('漏洞详情：CVE-2026-0001')).toBeInTheDocument()
    expect(
      screen.getByText(/PHP 8.1 在特定配置下存在远程代码执行风险/),
    ).toBeInTheDocument()
    expect(screen.getByText('受影响应用（1）')).toBeInTheDocument()
    expect(screen.getByText('商城门户')).toBeInTheDocument()
    expect(screen.getByText('mall')).toBeInTheDocument()
    expect(screen.getByText('参考链接（1）')).toBeInTheDocument()
    const link = screen.getByRole('link', {
      name: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
    })
    expect(link.getAttribute('href')).toBe('https://nvd.nist.gov/vuln/detail/CVE-2026-0001')
  })

  it('订阅设置：加载当前配置，保存时 PUT 更新后的设置', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /订阅设置/ }))
    const dialog = await screen.findByRole('dialog')
    // 表单回填当前设置（watch_techs 标签与同步开关）
    expect(await within(dialog).findByText('php')).toBeInTheDocument()
    const syncSwitch = within(dialog).getByRole('switch')
    expect(syncSwitch).toBeChecked()
    // 关闭在线同步后保存
    fireEvent.click(syncSwitch)
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => {
      const put = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/vuln-intel/settings') &&
          (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(put).toBeTruthy()
      const body = JSON.parse(String((put![1] as RequestInit).body))
      expect(body).toEqual({ watch_techs: ['php'], min_severity: 'LOW', sync_enabled: false })
    })
    expect(await screen.findByText('订阅设置已保存')).toBeInTheDocument()
  })

  it('技术资产：切换 PHP 标记后保存，PUT 全量应用标记', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /技术资产/ }))
    const dialog = await screen.findByRole('dialog')
    expect(await within(dialog).findByText('商城门户')).toBeInTheDocument()
    expect(within(dialog).getByText('企业博客')).toBeInTheDocument()

    const mallSwitch = within(dialog).getByRole('switch', { name: '标记 商城门户 为 PHP 应用' })
    const blogSwitch = within(dialog).getByRole('switch', { name: '标记 企业博客 为 PHP 应用' })
    expect(mallSwitch).toBeChecked()
    expect(blogSwitch).not.toBeChecked()
    // 取消商城门户、勾选企业博客
    fireEvent.click(mallSwitch)
    fireEvent.click(blogSwitch)
    fireEvent.click(within(dialog).getByRole('button', { name: /保\s*存/ }))

    await waitFor(() => {
      const put = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/vuln-intel/tech-assets') &&
          (c[1] as RequestInit | undefined)?.method === 'PUT',
      )
      expect(put).toBeTruthy()
      const body = JSON.parse(String((put![1] as RequestInit).body))
      expect(body.items).toEqual([
        { application_id: 'app-1', tech_tags: [] },
        { application_id: 'app-2', tech_tags: ['php'] },
      ])
    })
    expect(await screen.findByText('技术资产标记已保存')).toBeInTheDocument()
  })

  it('手动导入：合法 JSON 提交并展示导入统计', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /手动导入/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('导入 JSON 内容'), {
      target: {
        value:
          '[{"cve_id":"CVE-2026-0002","title":"PHP 信息泄露漏洞","severity":"HIGH","published_at":"2026-10-20"}]',
      },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /导\s*入/ }))

    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/vuln-intel/import') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
      const body = JSON.parse(String((post![1] as RequestInit).body))
      expect(body.advisories).toHaveLength(1)
      expect(body.advisories[0].cve_id).toBe('CVE-2026-0002')
      expect(body.advisories[0].severity).toBe('HIGH')
    })
    expect(
      await within(dialog).findByText(
        (_, el) => el?.textContent === '导入完成：共 1 条，新增 1 条，更新 0 条，触发告警 1 条。',
      ),
    ).toBeInTheDocument()
  })

  it('手动导入：非法 JSON 前端拦截，展示错误且不发起请求', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /手动导入/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('导入 JSON 内容'), {
      target: { value: 'not-json' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /导\s*入/ }))

    expect(
      await within(dialog).findByText('JSON 格式不正确，请检查输入内容'),
    ).toBeInTheDocument()
    const posts = (fetch as Mock).mock.calls.filter(
      (c) =>
        String(c[0]).includes('/vuln-intel/import') &&
        (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(posts).toHaveLength(0)
  })

  it('手动导入：后端校验失败展示后端错误消息', async () => {
    vi.stubGlobal('fetch', mockFetch({ importStatus: 400 }))
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /手动导入/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('导入 JSON 内容'), {
      target: {
        value:
          '[{"cve_id":"CVE-BAD","title":"测试","severity":"HIGH","published_at":"2026-10-20"}]',
      },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /导\s*入/ }))

    expect(await within(dialog).findByText('第 1 条 cve_id 格式非法')).toBeInTheDocument()
  })

  it('手动同步：触发 POST 同步并展示结果', async () => {
    renderPage()
    await screen.findByText('PHP 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /手动同步/ }))

    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/vuln-intel/sync') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
    })
    expect(await screen.findByText('同步完成，新增/更新 5 条')).toBeInTheDocument()
  })

  it('无 vuln_intel.manage 权限：隐藏全部写操作入口，保留读能力', async () => {
    useAuthStore.setState({
      user: makeUser(['vuln_intel.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('PHP 远程代码执行漏洞')
    expect(screen.queryByRole('button', { name: /手动同步/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /手动导入/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /技术资产/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /订阅设置/ })).not.toBeInTheDocument()
    // 读能力保留：告警入口、列表与详情按钮可用
    expect(screen.getByRole('button', { name: /漏洞情报告警/ })).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '详情' }).length).toBeGreaterThan(0)
  })
})

describe('parseImportJson 导入内容解析', () => {
  it('接受数组与 advisories 包装两种形态并规范化字段', () => {
    const fromArray = parseImportJson(
      '[{"cve_id":"cve-2026-0003","title":"t","severity":"high","published_at":"2026-10-01"}]',
    )
    expect(fromArray[0].cve_id).toBe('CVE-2026-0003')
    expect(fromArray[0].severity).toBe('HIGH')
    const fromWrapper = parseImportJson(
      '{"advisories":[{"cve_id":"CVE-2026-0004","title":"t","severity":"LOW","published_at":"2026-10-01"}]}',
    )
    expect(fromWrapper).toHaveLength(1)
  })

  it('缺字段与空数组给出中文错误', () => {
    expect(() => parseImportJson('[]')).toThrow('请输入包含 advisories 的非空 JSON 数组')
    expect(() => parseImportJson('[{"title":"t"}]')).toThrow('第 1 条缺少 cve_id')
    expect(() => parseImportJson('[{"cve_id":"CVE-2026-0001"}]')).toThrow('第 1 条缺少 title')
  })
})
