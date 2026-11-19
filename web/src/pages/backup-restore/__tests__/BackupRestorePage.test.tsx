import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BackupRestorePage from '../BackupRestorePage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  })
}

const VERIFIED_BACKUP = {
  id: 'bk-12345678',
  backup_type: 'FULL',
  status: 'SUCCESS',
  file_size: 4096,
  file_hash: 'abcdef1234567890',
  verified: true,
  requested_at: '2026-09-10T01:00:00Z',
}

const RESTORE_PREVIEW = {
  compatible: true,
  backup_type: 'FULL',
  backup_time: '2026-09-10T01:00:00Z',
  schema_version: 78,
  current_schema_version: 78,
  tables: [
    { name: 'applications', group: 'DATABASE', backup_rows: 5, in_scope: true, match: true },
    { name: 'protection_policies', group: 'CONFIG', backup_rows: 3, in_scope: true, match: true },
    { name: 'certificates', group: 'CERTIFICATE', backup_rows: 2, in_scope: true, match: true },
  ],
}

describe('BackupRestorePage 恢复预览分组中文化', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: {
        id: 'u1',
        username: 'ops',
        display_name: '系统管理员',
        status: 'ACTIVE',
        roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
        permissions: ['backups.read', 'backups.create', 'backups.restore'],
        must_change_password: false,
      } as CurrentUser,
      csrfToken: null,
      initialized: true,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const ok = (data: unknown) => Promise.resolve(jsonResponse({ code: 'SUCCESS', message: 'ok', data }))
        if (url.includes('/restores/validate') && init?.method === 'POST') {
          return ok({ preview: RESTORE_PREVIEW })
        }
        if (url.includes('/restores')) {
          return ok({ items: [], total: 0, page: 1, page_size: 20 })
        }
        if (url.includes('/backups')) {
          return ok({ items: [VERIFIED_BACKUP], total: 1, page: 1, page_size: 20 })
        }
        return Promise.reject(new Error(`unexpected url: ${url}`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('恢复向导校验预览表格中「分组」列以中文展示', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <BackupRestorePage />
        </AntdApp>
      </QueryClientProvider>,
    )

    fireEvent.click(screen.getByRole('tab', { name: '恢复管理' }))
    fireEvent.click(await screen.findByRole('button', { name: /发起恢复/ }))

    // 选择备份（antd v6 鼠标事件落在 .ant-select 根节点）
    const modal = await screen.findByRole('dialog')
    const select = modal.querySelector('.ant-select') as HTMLElement
    expect(select).toBeTruthy()
    fireEvent.mouseDown(select)
    const option = await screen.findByText(/bk-12345/, {
      selector: '.ant-select-item-option-content',
    })
    fireEvent.click(option)

    fireEvent.click(screen.getByRole('button', { name: '下一步' }))
    fireEvent.click(await screen.findByRole('button', { name: '开始校验' }))

    // 校验预览表格分组列中文化，不显示裸英文分组名
    expect(await screen.findByText('基础数据与拓扑')).toBeInTheDocument()
    expect(screen.getByText('策略与配置')).toBeInTheDocument()
    expect(screen.getByText('证书与密钥')).toBeInTheDocument()
    expect(screen.queryByText('DATABASE')).not.toBeInTheDocument()
    expect(screen.queryByText('CONFIG')).not.toBeInTheDocument()
    expect(screen.queryByText('CERTIFICATE')).not.toBeInTheDocument()
  })
})
