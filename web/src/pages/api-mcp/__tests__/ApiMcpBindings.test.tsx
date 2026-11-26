import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import BindingsTab from '../BindingsTab'
import { ApiError } from '../../../api/client'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import { validateOAuthResourceMetadataUrl } from '../../../utils/mcp'

vi.mock('../../../api/mcp', () => ({
  mcpApi: {
    listCatalogs: vi.fn(),
    listBindings: vi.fn(),
    createBinding: vi.fn(),
    updateBinding: vi.fn(),
    deleteBinding: vi.fn(),
  },
}))
vi.mock('../../../api/applications', () => ({
  applicationsApi: { list: vi.fn() },
}))

import { mcpApi } from '../../../api/mcp'
import { applicationsApi } from '../../../api/applications'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

const binding = {
  id: 'b1',
  application_id: 'app1',
  endpoint_path: '/mcp',
  catalog_id: 'c1',
  catalog_name: 'pay-tools',
  mode: 'OBSERVE',
  response_guard_mode: 'SANITIZE',
  require_session_binding: true,
  oauth_resource_metadata_url: 'https://mcp.example.com/.well-known/oauth-protected-resource',
  version: 3,
  created_by: 'sec',
  created_at: '2026-10-01T00:00:00Z',
  updated_at: '2026-10-05T00:00:00Z',
}

const FULL = ['api_spec.read', 'api_spec.manage']

function renderTab(permissions: string[]) {
  useAuthStore.setState({ user: makeUser(permissions), csrfToken: null, initialized: true })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <BindingsTab />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('BindingsTab（NG-MCP G1 绑定管理）', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(mcpApi.listBindings).mockResolvedValue({ items: [binding], total: 1 })
    vi.mocked(mcpApi.listCatalogs).mockResolvedValue({
      items: [
        {
          id: 'c1', name: 'pay-tools', service_identity: 'mcp://pay.example.com', protocol_version: '2025-11-25',
          source: 'MANUAL_IMPORT', status: 'ENABLED', catalog_hash: `mcp-catalog-sha256:v1:${'a'.repeat(64)}`,
          version: 2, created_by: 'sec', created_at: '2026-10-01T00:00:00Z', updated_at: '2026-10-05T00:00:00Z',
          tool_count: 3, approved_count: 1, pending_count: 1, rejected_count: 1,
        },
      ],
      total: 1,
    })
    vi.mocked(mcpApi.createBinding).mockResolvedValue(binding)
    vi.mocked(mcpApi.updateBinding).mockResolvedValue({ ...binding, mode: 'PROTECT', version: 4 })
    vi.mocked(mcpApi.deleteBinding).mockResolvedValue({ status: 'deleted' })
    vi.mocked(applicationsApi.list).mockResolvedValue({
      items: [{ id: 'app1', code: 'SHOP', name: '商城' }],
      total: 1,
      page: 1,
      page_size: 100,
    } as never)
  })

  it('绑定列表：应用名映射/端点路径/目录/模式/响应防护/会话绑定/OAuth元数据/版本', async () => {
    renderTab(FULL)
    expect(await screen.findByText('商城（SHOP）')).toBeInTheDocument()
    expect(screen.getByText('/mcp')).toBeInTheDocument()
    expect(screen.getByText('pay-tools')).toBeInTheDocument()
    expect(screen.getByText('观察')).toBeInTheDocument()
    expect(screen.getByText('净化隐写')).toBeInTheDocument()
    expect(screen.getByText('已绑定')).toBeInTheDocument()
    expect(
      screen.getByText('https://mcp.example.com/.well-known/oauth-protected-resource'),
    ).toBeInTheDocument()
    expect(screen.getByText('v3')).toBeInTheDocument()
  })

  it('新建绑定：载荷含响应防护/会话绑定/OAuth元数据；路径与 https:// 校验', async () => {
    renderTab(FULL)
    fireEvent.click(await screen.findByRole('button', { name: /新建绑定/ }))
    const dialog = await screen.findByRole('dialog')
    // 路径形态校验（非 / 开头）与非 https:// 元数据地址校验
    fireEvent.change(within(dialog).getByPlaceholderText('如：/mcp'), { target: { value: 'mcp' } })
    fireEvent.change(
      within(dialog).getByPlaceholderText(
        'https://mcp.example.com/.well-known/oauth-protected-resource',
      ),
      { target: { value: 'http://insecure.example.com/meta' } },
    )
    fireEvent.click(within(dialog).getByRole('button', { name: '创建绑定' }))
    expect(await within(dialog).findByText(/须为 \/ 开头精确路径/)).toBeInTheDocument()
    expect(
      await within(dialog).findByText(/必须以 https:\/\/ 开头/),
    ).toBeInTheDocument()
    expect(mcpApi.createBinding).not.toHaveBeenCalled()
    // 完整填写后提交
    fireEvent.mouseDown(within(dialog).getByText('选择应用'))
    const appOption = (await screen.findAllByText('商城（SHOP）')).find((el) =>
      el.closest('.ant-select-item-option-content'),
    ) as HTMLElement
    fireEvent.click(appOption)
    fireEvent.change(within(dialog).getByPlaceholderText('如：/mcp'), { target: { value: '/mcp' } })
    fireEvent.mouseDown(within(dialog).getByText('选择目录'))
    const catalogOption = (await screen.findAllByText('pay-tools（启用）')).find((el) =>
      el.closest('.ant-select-item-option-content'),
    ) as HTMLElement
    fireEvent.click(catalogOption)
    fireEvent.click(within(dialog).getByRole('switch'))
    fireEvent.change(
      within(dialog).getByPlaceholderText(
        'https://mcp.example.com/.well-known/oauth-protected-resource',
      ),
      { target: { value: 'https://mcp.example.com/.well-known/oauth-protected-resource' } },
    )
    fireEvent.click(within(dialog).getByRole('button', { name: '创建绑定' }))
    await waitFor(() =>
      expect(mcpApi.createBinding).toHaveBeenCalledWith({
        application_id: 'app1',
        endpoint_path: '/mcp',
        catalog_id: 'c1',
        mode: 'OBSERVE',
        response_guard_mode: 'OBSERVE',
        require_session_binding: true,
        oauth_resource_metadata_url:
          'https://mcp.example.com/.well-known/oauth-protected-resource',
      }),
    )
  })

  it('编辑绑定：PUT 携带响应防护/会话绑定/OAuth元数据与乐观锁 version；409 精确提示「版本冲突，请刷新后重试」', async () => {
    renderTab(FULL)
    fireEvent.click(await screen.findByRole('button', { name: '编辑' }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/当前乐观锁版本 v3/)).toBeInTheDocument()
    // 改 mode 为 PROTECT
    fireEvent.mouseDown(within(dialog).getByText('观察'))
    fireEvent.click(await screen.findByText('实断'))
    // 第一次提交 409 版本冲突
    vi.mocked(mcpApi.updateBinding).mockRejectedValueOnce(new ApiError('binding version conflict（乐观锁不匹配）', 'RESOURCE_CONFLICT', 409))
    fireEvent.click(within(dialog).getByRole('button', { name: '保 存' }))
    expect(await within(dialog).findByText('版本冲突，请刷新后重试')).toBeInTheDocument()
    expect(mcpApi.updateBinding).toHaveBeenCalledWith('b1', {
      catalog_id: 'c1',
      mode: 'PROTECT',
      response_guard_mode: 'SANITIZE',
      require_session_binding: true,
      oauth_resource_metadata_url:
        'https://mcp.example.com/.well-known/oauth-protected-resource',
      version: 3,
    })
  })

  it('解绑：Popconfirm 确认后 DELETE', async () => {
    renderTab(FULL)
    fireEvent.click(await screen.findByRole('button', { name: '解绑' }))
    fireEvent.click(await screen.findByRole('button', { name: '确认解绑' }))
    await waitFor(() => expect(mcpApi.deleteBinding).toHaveBeenCalledWith('b1'))
  })

  it('权限隐藏：无 manage 时新建/编辑/解绑全部隐藏（非禁用）', async () => {
    renderTab(['api_spec.read'])
    await screen.findByText('/mcp')
    expect(screen.queryByRole('button', { name: /新建绑定/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '编辑' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '解绑' })).not.toBeInTheDocument()
  })

  it('OAuth 2.1 资源元数据 URL 校验与后端/网关对齐（拒绝非 https、#片段、引号/反斜杠、控制字符与内嵌凭据）', () => {
    expect(validateOAuthResourceMetadataUrl('')).toBeNull()
    expect(
      validateOAuthResourceMetadataUrl(
        'https://mcp.example.com/.well-known/oauth-protected-resource',
      ),
    ).toBeNull()
    expect(validateOAuthResourceMetadataUrl('http://mcp.example.com/meta')).toContain(
      'https://',
    )
    expect(
      validateOAuthResourceMetadataUrl('https://mcp.example.com/meta#frag'),
    ).toContain('片段标识')
    expect(
      validateOAuthResourceMetadataUrl('https://mcp.example.com/meta#'),
    ).toContain('片段标识')
    expect(
      validateOAuthResourceMetadataUrl('https://mcp.example.com/"bad'),
    ).toContain('引号')
    expect(
      validateOAuthResourceMetadataUrl('https://user:pass@mcp.example.com/meta'),
    ).toContain('不含内嵌凭据')
  })
})
