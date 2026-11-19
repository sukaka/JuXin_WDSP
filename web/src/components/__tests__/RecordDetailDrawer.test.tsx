/* ==================== RecordDetailDrawer 通用行详情抽屉测试 ==================== */

import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import RecordDetailDrawer from '../RecordDetailDrawer'
import {
  UPSTREAM_DETAIL_FIELD_LABELS,
  UPSTREAM_DETAIL_VALUE_LABELS,
} from '../../pages/applications/detail/upstreamDetail'

describe('RecordDetailDrawer', () => {
  it('按字段渲染全部键值，内置通用中文字段/枚举兜底且空值/布尔/对象按口径展示', () => {
    render(
      <RecordDetailDrawer
        open
        title="用户详情"
        record={{
          username: 'alice',
          enabled: true,
          status: 'ACTIVE',
          deleted_at: null,
          created_at: '2026-09-01T10:00:00Z',
          custom_raw_field: 'raw-val',
          extra: { role: 'admin' },
        }}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('用户详情')).toBeInTheDocument()
    expect(screen.getByText('用户名')).toBeInTheDocument()
    expect(screen.queryByText('username')).not.toBeInTheDocument()
    expect(screen.getByText('是否启用')).toBeInTheDocument()
    expect(screen.getByText('状态')).toBeInTheDocument()
    expect(screen.getByText('启用')).toBeInTheDocument()
    expect(screen.getByText('创建时间')).toBeInTheDocument()
    expect(screen.getByText('custom_raw_field')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('是')).toBeInTheDocument()
    expect(screen.getAllByText('-').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/"role": "admin"/)).toBeInTheDocument()
  })

  it('调用方显式 fieldLabels/valueLabels 优先于内置兜底字典', () => {
    render(
      <RecordDetailDrawer
        open
        title="覆盖优先级测试"
        record={{ status: 'ACTIVE', username: 'bob' }}
        fieldLabels={{ username: '自定义账号名' }}
        valueLabels={{ status: { ACTIVE: '自定义激活态' } }}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('自定义账号名')).toBeInTheDocument()
    expect(screen.getByText('自定义激活态')).toBeInTheDocument()
    expect(screen.queryByText('用户名')).not.toBeInTheDocument()
  })

  it('record 为 null 时不渲染字段', () => {
    render(<RecordDetailDrawer open title="详情" record={null} onClose={() => {}} />)
    expect(screen.queryByText('用户名')).not.toBeInTheDocument()
  })

  it('关闭回调触发', async () => {
    const onClose = vi.fn()
    render(<RecordDetailDrawer open title="详情" record={{ a: 1 }} onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: /close/i }))
    expect(onClose).toHaveBeenCalled()
  })
})


describe('RecordDetailDrawer 中文业务映射', () => {
  it('源站详情使用中文字段与状态，保留技术值和现有布尔/时间格式', () => {
    render(
      <RecordDetailDrawer
        open
        title="源站详情"
        record={{
          status: 'ACTIVE',
          health_check_method: 'GET',
          health_check_path: '/news',
          health_check_enabled: true,
          expected_status_codes: '200',
          created_at: '2026-11-18T16:08:07Z',
        }}
        fieldLabels={UPSTREAM_DETAIL_FIELD_LABELS}
        valueLabels={UPSTREAM_DETAIL_VALUE_LABELS}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('状态')).toBeInTheDocument()
    expect(screen.getByText('启用')).toBeInTheDocument()
    expect(screen.getByText('健康检查方法')).toBeInTheDocument()
    expect(screen.getByText('健康检查路径')).toBeInTheDocument()
    expect(screen.getByText('启用主动健康检查')).toBeInTheDocument()
    expect(screen.getByText('预期 HTTP 状态码')).toBeInTheDocument()
    expect(screen.getByText('GET')).toBeInTheDocument()
    expect(screen.getByText('/news')).toBeInTheDocument()
    expect(screen.getByText('是')).toBeInTheDocument()
    expect(screen.queryByText('ACTIVE')).not.toBeInTheDocument()
    expect(screen.queryByText('health_check_method')).not.toBeInTheDocument()
  })
})
