import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import AccessRulesPage, { IPAccessRulePanel } from '../AccessRulesPage'
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

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

function renderPanel(node: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>{node}</AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('AccessRulesPage 批量导入 CSV 提示文案', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['access_rules.read', 'access_rules.manage', 'access_rules.import']),
      csrfToken: 'csrf-1',
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL) => {
        const url = String(input)
        if (url.includes('/api/v1/applications')) {
          return Promise.resolve(
            jsonResponse({
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], total: 0, page: 1, page_size: 100 },
            }),
          )
        }
        if (url.includes('/api/v1/access-rules')) {
          return Promise.resolve(
            jsonResponse({
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [], total: 0, page: 1, page_size: 20 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('黑名单批量导入弹窗明确提示支持中/英文表头与取值，并可直接导入本页导出 CSV', async () => {
    renderPanel(<AccessRulesPage />)

    fireEvent.click(await screen.findByRole('button', { name: /导\s*入/ }))
    const dialog = await screen.findByRole('dialog')

    expect(
      within(dialog).getByText(
        /CSV 表头须含「地址」或 address 列，支持中文\/英文表头（地址\/address、规则类型\/rule_type、生效范围\/scope_type、应用编码\/application_code、失效时间\/effective_until、原因\/reason）及中文\/英文取值（黑名单\/白名单 或 DENY\/ALLOW，全局\/指定应用 或 GLOBAL\/APPLICATION），可直接导入本页导出的 CSV 文件/,
      ),
    ).toBeInTheDocument()

    const textarea = within(dialog).getByPlaceholderText(/地址,规则类型,生效范围/)
    expect(textarea).toHaveAttribute(
      'placeholder',
      '地址,规则类型,生效范围\n203.0.113.66,黑名单,全局\n198.51.100.0/24,黑名单,全局',
    )
  })

  it('白名单面板批量导入弹窗使用白名单中文示例占位符', async () => {
    renderPanel(<IPAccessRulePanel fixedRuleType="ALLOW" embedded />)

    fireEvent.click(await screen.findByRole('button', { name: /导\s*入/ }))
    const dialog = await screen.findByRole('dialog')

    const textarea = within(dialog).getByPlaceholderText(/地址,规则类型,生效范围/)
    expect(textarea).toHaveAttribute(
      'placeholder',
      '地址,规则类型,生效范围\n203.0.113.66,白名单,全局\n198.51.100.0/24,白名单,全局',
    )
  })
})
