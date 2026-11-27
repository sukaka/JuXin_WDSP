import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'
import BlockPagesPage from '../BlockPagesPage'
import { useAuthStore } from '../../../stores/auth'
import {
  AUDIT_MODULE_LABELS,
  PERMISSION_MODULE_LABELS,
  PUBLISH_FAILURE_CODE_LABELS,
} from '../../../utils/i18nLabels'
import { DEFAULT_VISUAL_CONFIG, type BlockPageBindingItem, type BlockPageItem } from '../../../api/blockPages'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'secops',
    display_name: '运维管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '运维管理员' }],
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

const BUILTIN_PAGE: BlockPageItem = {
  id: '11111111-2222-4333-8444-555555550001',
  name: '经典暗色安全拦截页',
  description: '深空蓝暗色样式',
  editor_mode: 'VISUAL',
  theme: 'classic_dark',
  visual_config: DEFAULT_VISUAL_CONFIG,
  html_content: '',
  rendered_html: '<!DOCTYPE html><html><body><h1>经典暗色</h1></body></html>',
  status_code: 0,
  json_code: '',
  json_message: '',
  version: 2,
  is_builtin: true,
  binding_count: 1,
  created_by: 'system',
  updated_by: 'secops',
  created_at: '2026-11-26T10:00:00Z',
  updated_at: '2026-11-26T12:00:00Z',
}

const CUSTOM_PAGE: BlockPageItem = {
  id: '22222222-2222-4333-8444-555555550002',
  name: '电商大促限流页',
  description: '自定义 HTML/CSS 限速模板',
  editor_mode: 'HTML',
  theme: 'amber_limit',
  visual_config: DEFAULT_VISUAL_CONFIG,
  html_content: '<html><body><h1>活动火爆请稍候</h1></body></html>',
  rendered_html: '<!DOCTYPE html><html><body><h1>活动火爆请稍候</h1></body></html>',
  status_code: 429,
  json_code: 'promo_rate_limit',
  json_message: '活动火爆，请稍后重试',
  version: 1,
  is_builtin: false,
  binding_count: 0,
  created_by: 'secops',
  updated_by: 'secops',
  created_at: '2026-11-26T11:00:00Z',
  updated_at: '2026-11-26T11:00:00Z',
}

const SAMPLE_BINDING: BlockPageBindingItem = {
  id: '33333333-2222-4333-8444-555555550003',
  application_id: null,
  scene: 'WAF',
  block_page_id: BUILTIN_PAGE.id,
  block_page_name: BUILTIN_PAGE.name,
  block_page_latest_version: 2,
  pinned_version: 1,
  effective_version: 1,
  enabled: true,
  updated_by: 'secops',
  created_at: '2026-11-26T12:00:00Z',
  updated_at: '2026-11-26T12:00:00Z',
}

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AntdApp>
          <BlockPagesPage />
        </AntdApp>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

function createFetchMock() {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url
    const method = (init?.method ?? 'GET').toUpperCase()

    if (url.includes('/api/v1/block-pages/bindings') && method === 'GET') {
      return jsonResponse(200, { code: 'SUCCESS', data: { items: [SAMPLE_BINDING] } })
    }
    if (url.includes('/api/v1/block-pages/preview') && method === 'POST') {
      return jsonResponse(200, {
        code: 'SUCCESS',
        data: {
          rendered_html: '<!DOCTYPE html><html><body><h1>安全预览</h1></body></html>',
          sanitized_template_html: '<!DOCTYPE html><html><body><h1>{{request_id}}</h1></body></html>',
          warnings: [],
          byte_size: 120,
          max_bytes: 65536,
          effective_status_code: 403,
        },
      })
    }
    if (url.includes(`/api/v1/block-pages/${BUILTIN_PAGE.id}/rollback`) && method === 'POST') {
      return jsonResponse(200, {
        code: 'SUCCESS',
        data: {
          block_page: { ...BUILTIN_PAGE, version: 3 },
          version: {
            id: 'v3',
            block_page_id: BUILTIN_PAGE.id,
            version: 3,
            editor_mode: 'VISUAL',
            theme: 'classic_dark',
            visual_config: DEFAULT_VISUAL_CONFIG,
            html_content: '',
            rendered_html: BUILTIN_PAGE.rendered_html,
            status_code: 0,
            json_code: '',
            json_message: '',
            change_note: '回滚至 v1',
            created_by: 'secops',
            created_at: '2026-11-26T13:00:00Z',
          },
        },
      })
    }
    if (url.includes(`/api/v1/block-pages/${BUILTIN_PAGE.id}`) && method === 'GET') {
      return jsonResponse(200, {
        code: 'SUCCESS',
        data: {
          block_page: BUILTIN_PAGE,
          versions: [
            {
              id: 'v2',
              block_page_id: BUILTIN_PAGE.id,
              version: 2,
              editor_mode: 'VISUAL',
              theme: 'classic_dark',
              visual_config: DEFAULT_VISUAL_CONFIG,
              html_content: '',
              rendered_html: BUILTIN_PAGE.rendered_html,
              status_code: 0,
              json_code: '',
              json_message: '',
              change_note: '第二版调整说明',
              created_by: 'secops',
              created_at: '2026-11-26T12:00:00Z',
            },
            {
              id: 'v1',
              block_page_id: BUILTIN_PAGE.id,
              version: 1,
              editor_mode: 'VISUAL',
              theme: 'classic_dark',
              visual_config: DEFAULT_VISUAL_CONFIG,
              html_content: '',
              rendered_html: BUILTIN_PAGE.rendered_html,
              status_code: 0,
              json_code: '',
              json_message: '',
              change_note: '系统内置初始版本',
              created_by: 'system',
              created_at: '2026-11-26T10:00:00Z',
            },
          ],
          bindings: [SAMPLE_BINDING],
        },
      })
    }
    if (url.includes('/api/v1/block-pages') && method === 'GET') {
      return jsonResponse(200, {
        code: 'SUCCESS',
        data: {
          items: [BUILTIN_PAGE, CUSTOM_PAGE],
          total: 2,
          page: 1,
          page_size: 20,
          themes: [],
          placeholders: [],
          scenes: [],
        },
      })
    }
    if (url.includes('/api/v1/applications') && method === 'GET') {
      return jsonResponse(200, {
        code: 'SUCCESS',
        data: { items: [], total: 0, page: 1, page_size: 200 },
      })
    }
    return jsonResponse(200, { code: 'SUCCESS', data: {} })
  })
}

describe('BlockPagesPage · 自定义拦截页面与多版本管理', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['block_pages.read', 'block_pages.manage']),
      initialized: true,
    })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('渲染模板列表、版本标签与生效绑定标签，并支持查看版本历史与沙箱预览', async () => {
    const fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)

    renderPage()

    expect(await screen.findByText('经典暗色安全拦截页')).toBeInTheDocument()
    expect(screen.getByText('电商大促限流页')).toBeInTheDocument()
    expect(screen.getByText('v2')).toBeInTheDocument()
    expect(screen.getByText('HTTP 429')).toBeInTheDocument()

    // 打开版本历史抽屉，展示不可变历史版本与沙箱 iframe 预览
    const historyButtons = screen.getAllByRole('button', { name: /版本历史/ })
    fireEvent.click(historyButtons[0])

    expect(await screen.findByText('第二版调整说明')).toBeInTheDocument()
    expect(screen.getByText('系统内置初始版本')).toBeInTheDocument()
    const iframe = await screen.findByTitle('历史版本 v2 预览')
    expect(iframe).toHaveAttribute('sandbox', '')
  })

  it('切换到「生效绑定策略」页签展示锁定版本与全局/场景映射', async () => {
    vi.stubGlobal('fetch', createFetchMock())
    renderPage()

    await screen.findByText('经典暗色安全拦截页')
    fireEvent.click(screen.getByRole('tab', { name: /生效绑定策略/ }))

    expect(await screen.findByText('锁定 v1')).toBeInTheDocument()
    expect(screen.getByText('全局默认')).toBeInTheDocument()
    expect(screen.getByText('WAF 攻击拦截')).toBeInTheDocument()
  })

  it('只读权限（仅 block_pages.read）隐藏新建、编辑、删除与绑定按钮，不请求应用列表', async () => {
    useAuthStore.setState({
      user: makeUser(['block_pages.read']),
      initialized: true,
    })
    const fetchMock = createFetchMock()
    vi.stubGlobal('fetch', fetchMock)

    renderPage()

    await screen.findByText('经典暗色安全拦截页')
    expect(screen.queryByRole('button', { name: /新建拦截页/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /编辑/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /删除/ })).not.toBeInTheDocument()

    await waitFor(() => {
      const calledApps = fetchMock.mock.calls.some(([u]) => String(u).includes('/api/v1/applications'))
      expect(calledApps).toBe(false)
    })
  })

  it('i18nLabels 覆盖 block_pages 权限模块、审计模块与发布快照错误码', () => {
    expect(PERMISSION_MODULE_LABELS.block_pages).toBe('拦截页面')
    expect(AUDIT_MODULE_LABELS.block_pages).toBe('拦截页面')
    expect(PUBLISH_FAILURE_CODE_LABELS.BLOCK_PAGES_SNAPSHOT_FAILED).toBe('自定义拦截页快照构建失败')
  })
})
