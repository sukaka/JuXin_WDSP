import { afterEach, beforeEach, describe, expect, it, vi, type Mock } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import VulnRefsPage from '../VulnRefsPage'
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

const REF_ITEM = {
  id: 'vr-1',
  cnnvd_id: 'CNNVD-202401-2345',
  cve_id: 'CVE-2024-0001',
  title: 'Apache Struts2 远程代码执行漏洞',
  severity: 'CRITICAL',
  published_at: '2024-01-15',
  url: 'https://www.cnnvd.org.cn/home/loophole?id=CNNVD-202401-2345',
  rule_count: 2,
  event_count_30d: 3,
  created_at: '2026-09-01T08:00:00Z',
  updated_at: '2026-09-10T08:00:00Z',
}

const REF_DETAIL = {
  ref: REF_ITEM,
  rules: [
    {
      rule_id: 7100001,
      rule_source: 'CUSTOM',
      rule_name: 'Struts2 RCE 虚拟补丁',
      description: '拦截 Struts2 OGNL 注入',
      enabled: true,
    },
  ],
  event_count_30d: 3,
  sample_events: [
    {
      id: 'evt-1',
      occurred_at: '2026-09-01T10:00:00Z',
      attack_type: 'REMOTE_CODE_EXECUTION',
      client_ip: '1.2.3.4',
      request_path: '/struts/login.action',
      action: 'BLOCK',
    },
  ],
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

interface MockOptions {
  createStatus?: number
  detailStatus?: number
}

function mockFetch(opts: MockOptions = {}) {
  return vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const ok = (data: unknown) =>
      Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
    if (url.includes('/waf/vuln-refs/')) {
      if (init?.method === 'DELETE') return ok({ message: '已删除' })
      if (init?.method === 'PUT') return ok(REF_ITEM)
      if (opts.detailStatus) {
        return Promise.resolve(
          jsonResponse(opts.detailStatus, { code: 'NOT_FOUND', message: '档案不存在', data: null }),
        )
      }
      return ok(REF_DETAIL)
    }
    if (url.includes('/waf/vuln-refs')) {
      if (init?.method === 'POST') {
        if (opts.createStatus === 409) {
          return Promise.resolve(
            jsonResponse(409, {
              code: 'CONFLICT',
              message: 'CNNVD 编号 CNNVD-202401-2345 已存在档案',
              data: null,
            }),
          )
        }
        return ok(REF_ITEM)
      }
      return ok({ items: [REF_ITEM], total: 1, page: 1, page_size: 20 })
    }
    return Promise.reject(new Error(`unexpected url: ${url}`))
  })
}

function renderPage(initialEntries: string[] = ['/waf/vuln-refs']) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <MemoryRouter initialEntries={initialEntries}>
          <VulnRefsPage />
        </MemoryRouter>
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('VulnRefsPage 漏洞档案', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['waf_rules.read', 'waf_rule.vuln_ref.edit']),
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal('fetch', mockFetch())
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表渲染：编号/规范名称/危害等级/发布时间/关联计数/操作按钮', async () => {
    renderPage()

    expect(await screen.findByText('CNNVD-202401-2345')).toBeInTheDocument()
    expect(screen.getByText('CVE-2024-0001')).toBeInTheDocument()
    expect(screen.getByText('Apache Struts2 远程代码执行漏洞')).toBeInTheDocument()
    expect(screen.getByText('超危')).toBeInTheDocument()
    expect(screen.getByText('2024-01-15')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建档案/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '编辑' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '删除' })).toBeInTheDocument()
  })

  it('关键词搜索：回车后列表请求携带 keyword 参数', async () => {
    renderPage()
    await screen.findByText('Apache Struts2 远程代码执行漏洞')

    const input = screen.getByPlaceholderText('搜索编号或规范名称')
    fireEvent.change(input, { target: { value: 'Struts2' } })
    fireEvent.keyDown(input, { key: 'Enter', code: 'Enter' })

    await waitFor(() => {
      const calls = (fetch as Mock).mock.calls.filter((c) =>
        String(c[0]).includes('/waf/vuln-refs?'),
      )
      expect(calls.some((c) => String(c[0]).includes('keyword=Struts2'))).toBe(true)
    })
  })

  it('新建档案：提交合法表单后 POST 创建', async () => {
    renderPage()
    await screen.findByText('Apache Struts2 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /新建档案/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：CNNVD-202401-2345'), {
      target: { value: 'CNNVD-202401-2345' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：CVE-2024-0001（可选）'), {
      target: { value: 'CVE-2024-0001' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：Apache Struts2 远程代码执行漏洞'), {
      target: { value: 'Apache Struts2 远程代码执行漏洞' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('https://www.cnnvd.org.cn/...（可选）'), {
      target: { value: 'https://www.cnnvd.org.cn/home/loophole?id=CNNVD-202401-2345' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => {
      const post = (fetch as Mock).mock.calls.find(
        (c) =>
          String(c[0]).includes('/waf/vuln-refs') &&
          (c[1] as RequestInit | undefined)?.method === 'POST',
      )
      expect(post).toBeTruthy()
      const body = JSON.parse(String((post![1] as RequestInit).body))
      expect(body.cnnvd_id).toBe('CNNVD-202401-2345')
      expect(body.cve_id).toBe('CVE-2024-0001')
      expect(body.severity).toBe('HIGH')
    })
    expect(await screen.findByText('漏洞档案「CNNVD-202401-2345」已创建')).toBeInTheDocument()
  })

  it('新建 409 冲突：展示后端错误消息', async () => {
    vi.stubGlobal('fetch', mockFetch({ createStatus: 409 }))
    renderPage()
    await screen.findByText('Apache Struts2 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /新建档案/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：CNNVD-202401-2345'), {
      target: { value: 'CNNVD-202401-2345' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：Apache Struts2 远程代码执行漏洞'), {
      target: { value: '重复档案' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    expect(
      await screen.findByText('CNNVD 编号 CNNVD-202401-2345 已存在档案'),
    ).toBeInTheDocument()
  })

  it('编号格式校验：非法 CNNVD 编号拦截提交，不发起 POST', async () => {
    renderPage()
    await screen.findByText('Apache Struts2 远程代码执行漏洞')

    fireEvent.click(screen.getByRole('button', { name: /新建档案/ }))
    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByPlaceholderText('如：CNNVD-202401-2345'), {
      target: { value: 'CNNVD-2024-01' },
    })
    fireEvent.change(within(dialog).getByPlaceholderText('如：Apache Struts2 远程代码执行漏洞'), {
      target: { value: '测试档案' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /确\s*定|^OK$/ }))

    expect(
      await within(dialog).findByText('格式应为 CNNVD-YYYYMM-NNN（如 CNNVD-202401-2345）'),
    ).toBeInTheDocument()
    const posts = (fetch as Mock).mock.calls.filter(
      (c) => (c[1] as RequestInit | undefined)?.method === 'POST',
    )
    expect(posts).toHaveLength(0)
  })

  it('?focus= 打开详情抽屉：档案信息、官方条目链接、关联规则与样例事件', async () => {
    renderPage(['/waf/vuln-refs?focus=CNNVD-202401-2345'])

    expect(await screen.findByText('漏洞档案详情：CNNVD-202401-2345')).toBeInTheDocument()
    // 档案信息
    expect(screen.getAllByText('Apache Struts2 远程代码执行漏洞').length).toBeGreaterThan(0)
    const link = screen.getByRole('link', { name: 'CNNVD 官方条目' })
    expect(link.getAttribute('href')).toBe(
      'https://www.cnnvd.org.cn/home/loophole?id=CNNVD-202401-2345',
    )
    // 关联规则表
    expect(screen.getByText('关联规则（1）')).toBeInTheDocument()
    expect(screen.getByText('7100001')).toBeInTheDocument()
    expect(screen.getByText('Struts2 RCE 虚拟补丁')).toBeInTheDocument()
    expect(screen.getByText('CUSTOM')).toBeInTheDocument()
    expect(screen.getAllByText('启用').length).toBeGreaterThanOrEqual(2)
    // 近 30 天事件计数与样例事件
    expect(screen.getByText('近 30 天命中事件（3）')).toBeInTheDocument()
    expect(screen.getByText('1.2.3.4')).toBeInTheDocument()
    expect(screen.getByText('/struts/login.action')).toBeInTheDocument()
    expect(screen.getByText('远程代码执行')).toBeInTheDocument()
    expect(screen.getByText('阻断')).toBeInTheDocument()
  })

  it('详情抽屉：javascript: 官方条目链接不渲染为可点击超链接', async () => {
    const evilDetail = {
      ...REF_DETAIL,
      ref: { ...REF_ITEM, url: 'javascript:alert(document.domain)' },
    }
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) =>
          Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/waf/vuln-refs/')) return ok(evilDetail)
        return ok({ items: [REF_ITEM], total: 1, page: 1, page_size: 20 })
      }),
    )
    renderPage(['/waf/vuln-refs?focus=CNNVD-202401-2345'])
    expect(await screen.findByText('漏洞档案详情：CNNVD-202401-2345')).toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'CNNVD 官方条目' })).not.toBeInTheDocument()
    expect(screen.getByText('javascript:alert(document.domain)')).toBeInTheDocument()
  })

  it('无 waf_rule.vuln_ref.edit 权限：隐藏新建/编辑/删除，保留读操作', async () => {
    useAuthStore.setState({
      user: makeUser(['waf_rules.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('Apache Struts2 远程代码执行漏洞')
    expect(screen.queryByRole('button', { name: /新建档案/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '删除' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: '详情' }).length).toBeGreaterThan(0)
  })
})
