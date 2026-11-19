import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ApiFileCompliancePage from '../ApiFileCompliancePage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

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

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const ruleUpload = {
  id: 'r1',
  direction: 'UPLOAD',
  match_type: 'EXT',
  match_value: 'exe',
  action: 'BLOCK',
  reason: '禁止上传可执行文件',
  enabled: true,
  created_by: 'admin',
  created_at: '2026-08-01T02:00:00Z',
  updated_at: '2026-08-10T02:00:00Z',
}

const ruleDownload = {
  id: 'r2',
  direction: 'DOWNLOAD',
  match_type: 'FILENAME_REGEX',
  match_value: '.*\\.sql$',
  action: 'OBSERVE',
  reason: '',
  enabled: false,
  created_by: null,
  created_at: '2026-08-02T02:00:00Z',
  updated_at: '2026-08-11T02:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AntdApp>
          <ApiFileCompliancePage />
        </AntdApp>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

/** 通过 Form.Item 标签定位下拉并展开，再点击选项（antd v6 选项按 .ant-select-item-option-content 消歧） */
async function selectFormItem(label: string, optionText: string) {
  const item = screen.getByText(label, { selector: 'label' }).closest('.ant-form-item')
  fireEvent.mouseDown(item?.querySelector('.ant-select') as HTMLElement)
  const candidates = await screen.findAllByText(optionText)
  const option = candidates.find((el) => el.closest('.ant-select-item-option-content'))
  expect(option).toBeTruthy()
  fireEvent.click(option as HTMLElement)
}

describe('ApiFileCompliancePage', () => {
  let createBodies: unknown[]
  let patchCalls: { url: string; body: unknown }[]
  let deleteUrls: string[]

  beforeEach(() => {
    createBodies = []
    patchCalls = []
    deleteUrls = []
    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.includes('/api-security/file-compliance-rules')) {
          createBodies.push(JSON.parse(String(init?.body)))
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: ruleUpload }))
        }
        if (method === 'PATCH' && url.includes('/api-security/file-compliance-rules/')) {
          patchCalls.push({ url, body: JSON.parse(String(init?.body)) })
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: ruleDownload }))
        }
        if (method === 'DELETE' && url.includes('/api-security/file-compliance-rules/')) {
          deleteUrls.push(url)
          return Promise.resolve(jsonResponse(200, { code: 'SUCCESS', message: 'ok', data: { status: 'deleted' } }))
        }
        if (method === 'GET' && url.includes('/api-security/file-compliance-rules')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [ruleUpload, ruleDownload], page: 1, page_size: 20, total: 2 },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('列表渲染：方向/匹配类型/动作标签、匹配值、理由与启用开关', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row1 = (await screen.findByText('exe')).closest('tr') as HTMLElement
    expect(within(row1).getByText('上传')).toBeInTheDocument()
    expect(within(row1).getByText('扩展名')).toBeInTheDocument()
    expect(within(row1).getByText('阻断')).toBeInTheDocument()
    expect(within(row1).getByText('禁止上传可执行文件')).toBeInTheDocument()
    expect(within(row1).getByRole('switch', { name: '启停规则 扩展名:exe' })).toBeChecked()

    const row2 = screen.getByText('.*\\.sql$').closest('tr') as HTMLElement
    expect(within(row2).getByText('下载')).toBeInTheDocument()
    expect(within(row2).getByText('文件名正则')).toBeInTheDocument()
    expect(within(row2).getByText('观察')).toBeInTheDocument()
    // 空理由渲染占位符
    expect(within(row2).getByText('-')).toBeInTheDocument()
    expect(within(row2).getByRole('switch', { name: '启停规则 文件名正则:.*\\.sql$' })).not.toBeChecked()
  })

  it('新建：match_type 联动 match_value 提示，提交体正确', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建文件合规规则')
    // 默认 EXT：提示 .exe 示例
    expect(screen.getByText(/扩展名，如 \.exe/)).toBeInTheDocument()
    expect(screen.getByPlaceholderText('.exe')).toBeInTheDocument()

    // 切换 MIME：提示 application/pdf 示例（联动为异步更新，用 findBy 等待）
    await selectFormItem('匹配类型', 'MIME 类型（MIME）')
    expect(await screen.findByText(/MIME 类型，如 application\/pdf/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('匹配值'), { target: { value: 'application/pdf' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(createBodies).toHaveLength(1))
    expect(createBodies[0]).toEqual({
      direction: 'UPLOAD',
      match_type: 'MIME',
      match_value: 'application/pdf',
      action: 'OBSERVE',
      reason: '',
      enabled: true,
    })
  })

  it('match_type 联动校验：FILENAME_REGEX 非法正则不提交并提示', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /新建规则/ }))
    await screen.findByText('新建文件合规规则')

    await selectFormItem('匹配类型', '文件名正则（FILENAME_REGEX）')
    // 提示 REGEX 示例（联动为异步更新，用 findBy 等待）
    expect(await screen.findByText(/文件名正则（RE2 语法），如 \.\*\\\.sql\$/)).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('匹配值'), { target: { value: '((*' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))

    expect(await screen.findByText(/正则无法编译/)).toBeInTheDocument()
    expect(createBodies).toHaveLength(0)
  })

  it('编辑：预填表单，PATCH 提交全量字段', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row = (await screen.findByText('.*\\.sql$')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /编\s*辑/ }))

    await screen.findByText('编辑规则：文件名正则:.*\\.sql$')
    await waitFor(() => {
      expect(screen.getByLabelText('匹配值')).toHaveValue('.*\\.sql$')
    })

    fireEvent.click(screen.getByRole('button', { name: /确\s*定|^OK$/ }))
    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toContain('/api-security/file-compliance-rules/r2')
    expect(patchCalls[0].body).toEqual({
      direction: 'DOWNLOAD',
      match_type: 'FILENAME_REGEX',
      match_value: '.*\\.sql$',
      action: 'OBSERVE',
      reason: '',
      enabled: false,
    })
  })

  it('启停：Switch 触发确认弹窗，确认后 PATCH enabled', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    fireEvent.click(await screen.findByRole('switch', { name: '启停规则 扩展名:exe' }))
    // 确认弹窗出现，确定后发出 PATCH（测试环境默认英文 locale，OK 按钮文案为 OK）
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(patchCalls).toHaveLength(1))
    expect(patchCalls[0].url).toContain('/api-security/file-compliance-rules/r1')
    expect(patchCalls[0].body).toEqual({ enabled: false })
  })

  it('删除：确认弹窗确认后 DELETE', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read', 'api_data.manage']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    const row = (await screen.findByText('exe')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /删\s*除/ }))
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定|^OK$/ }))

    await waitFor(() => expect(deleteUrls).toHaveLength(1))
    expect(deleteUrls[0]).toContain('/api-security/file-compliance-rules/r1')
  })

  it('无 api_data.manage 权限：不显示新建与行内操作，启用开关禁用', async () => {
    useAuthStore.setState({
      user: makeUser(['api_data.read']),
      csrfToken: null,
      initialized: true,
    })
    renderPage()

    await screen.findByText('exe')
    expect(screen.queryByRole('button', { name: /新建规则/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编\s*辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删\s*除/ })).not.toBeInTheDocument()
    expect(screen.getByRole('switch', { name: '启停规则 扩展名:exe' })).toBeDisabled()
  })
})
