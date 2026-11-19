import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import RolesPage from '../RolesPage'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const ROLES = [
  {
    id: 'role-1',
    code: 'SECURITY_ADMIN',
    name: '安全管理员',
    description: '负责安全策略配置',
    is_builtin: true,
  },
]

const PERMISSIONS = [
  { id: 'p1', code: 'applications.read', name: '查看应用', module: 'applications', description: '查看应用列表' },
  { id: 'p2', code: 'applications.create', name: '创建应用', module: 'applications', description: '新建应用' },
  { id: 'p3', code: 'waf_rules.read', name: '查看规则', module: 'waf_rules', description: '查看 WAF 规则' },
  { id: 'p4', code: 'custom_mod.read', name: '自定义权限', module: 'custom_mod', description: '未知模块回退' },
]

describe('RolesPage 权限模块中文化展示', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.endsWith('/roles/role-1')) {
          return ok({
            role: ROLES[0],
            user_count: 2,
            permissions: PERMISSIONS.slice(0, 3),
          })
        }
        if (url.endsWith('/roles')) return ok({ items: ROLES })
        if (url.endsWith('/permissions')) return ok({ items: PERMISSIONS })
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('全部权限清单与角色权限抽屉均按中文模块名分组展示，未知模块原样回退', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <RolesPage />
        </AntdApp>
      </QueryClientProvider>,
    )

    expect(await screen.findByText('应用管理（2）')).toBeInTheDocument()
    expect(screen.getByText('防护规则（1）')).toBeInTheDocument()
    expect(screen.getByText('custom_mod（1）')).toBeInTheDocument()
    expect(screen.queryByText('applications（2）')).not.toBeInTheDocument()
    expect(screen.queryByText('waf_rules（1）')).not.toBeInTheDocument()

    // 打开角色详情抽屉，模块标题同样中文化
    fireEvent.click(screen.getByRole('button', { name: '查看权限' }))
    expect(await screen.findByText('角色权限：安全管理员')).toBeInTheDocument()
    expect(screen.getAllByText('应用管理（2）').length).toBeGreaterThanOrEqual(2)
    expect(screen.getAllByText('防护规则（1）').length).toBeGreaterThanOrEqual(2)
  })
})
