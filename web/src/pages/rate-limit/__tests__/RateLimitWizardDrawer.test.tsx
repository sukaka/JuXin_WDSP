import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import RateLimitWizardDrawer from '../RateLimitWizardDrawer'
import type { PolicyFormValues } from '../wizard'
import type { ApplicationItem, RateLimitPolicyItem } from '../../../types'

const APPS = [
  {
    id: 'app-1',
    code: 'mall',
    name: '商城',
  },
] as unknown as ApplicationItem[]

function makeRecord(overrides: Partial<RateLimitPolicyItem> = {}): RateLimitPolicyItem {
  return {
    id: 'p1',
    name: '登录防爆破',
    description: '登录接口保护',
    scope_type: 'URI',
    application_id: 'app-1',
    uri_match_type: 'PREFIX',
    uri_pattern: '/api/login',
    dimension: 'CLIENT_IP_AND_URI',
    algorithm: 'SLIDING_WINDOW',
    requests_limit: 30,
    window_seconds: 120,
    burst_capacity: 50,
    action: 'TEMP_BLOCK',
    block_duration_seconds: 600,
    status: 'ACTIVE',
    observe_only: false,
    priority: 10,
    effective_from: null,
    effective_until: null,
    created_at: '2026-09-01T00:00:00Z',
    updated_at: '2026-09-01T00:00:00Z',
    version: 3,
    ...overrides,
  }
}

function renderWizard(props: {
  editing?: RateLimitPolicyItem | null
  onSubmit?: (values: PolicyFormValues) => void
}) {
  const onSubmit = props.onSubmit ?? vi.fn()
  const utils = render(
    <RateLimitWizardDrawer
      open
      editing={props.editing ?? null}
      saving={false}
      apps={APPS}
      appsLoading={false}
      onClose={() => {}}
      onSubmit={onSubmit}
    />,
  )
  return { onSubmit, ...utils }
}

function goNext() {
  fireEvent.click(screen.getByRole('button', { name: '下一步' }))
}

describe('RateLimitWizardDrawer CC 分步向导', () => {
  it('首步校验未通过时停留当前步，填写名称后可进入下一步', async () => {
    renderWizard({})
    // 阈值步骤初始隐藏
    expect(screen.getByText('统计维度')).not.toBeVisible()

    goNext()
    expect(await screen.findByText('请输入策略名称')).toBeInTheDocument()
    expect(screen.getByText('统计维度')).not.toBeVisible()

    fireEvent.change(screen.getByPlaceholderText('如：登录 API 防爆破'), {
      target: { value: '新策略' },
    })
    goNext()
    await waitFor(() => expect(screen.getByText('统计维度')).toBeVisible())
  })

  it('可依次走完整向导并在末步展示摘要后提交', async () => {
    const { onSubmit } = renderWizard({})
    fireEvent.change(screen.getByPlaceholderText('如：登录 API 防爆破'), {
      target: { value: '新策略' },
    })
    goNext()
    await waitFor(() => expect(screen.getByText('统计维度')).toBeVisible())
    goNext()
    await waitFor(() => expect(screen.getByText('超阈值动作')).toBeVisible())
    goNext()

    expect(await screen.findByText('请核对以下配置摘要，确认无误后提交')).toBeInTheDocument()
    expect(screen.getAllByText('新策略').length).toBeGreaterThan(0)
    expect(screen.getByText('100 次 / 60 秒，突发容量 100')).toBeInTheDocument()
    // “拒绝(429)” 同时出现在隐藏的动作选择框与摘要中
    expect(screen.getAllByText('拒绝(429)').length).toBeGreaterThan(0)

    fireEvent.click(screen.getByRole('button', { name: '创 建' }))
    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          name: '新策略',
          scope_type: 'GLOBAL',
          requests_limit: 100,
          window_seconds: 60,
          action: 'REJECT',
        }),
      ),
    )
  })

  it('编辑态正确回填各步字段并在摘要中展示', async () => {
    renderWizard({ editing: makeRecord() })
    await waitFor(() =>
      expect(screen.getByPlaceholderText('如：登录 API 防爆破')).toHaveValue('登录防爆破'),
    )

    goNext()
    await waitFor(() => expect(screen.getByText('统计维度')).toBeVisible())
    goNext()
    await waitFor(() => expect(screen.getByText('超阈值动作')).toBeVisible())
    // 临时封禁时长回填
    expect(screen.getByLabelText('临时封禁时长（秒）')).toHaveDisplayValue('600')
    goNext()

    expect((await screen.findAllByText('登录防爆破')).length).toBeGreaterThan(0)
    expect(screen.getByText('应用+路径：商城（mall）')).toBeInTheDocument()
    expect(screen.getByText('前缀匹配：/api/login')).toBeInTheDocument()
    expect(screen.getByText('临时封禁（600 秒）')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '保 存' })).toBeInTheDocument()
  })
})
