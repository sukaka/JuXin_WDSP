/* ==================== RecordDetailDrawer 通用行详情抽屉测试 ==================== */

import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import RecordDetailDrawer from '../RecordDetailDrawer'

describe('RecordDetailDrawer', () => {
  it('按字段渲染全部键值，空值/布尔/对象按口径展示', () => {
    render(
      <RecordDetailDrawer
        open
        title="用户详情"
        record={{
          username: 'alice',
          enabled: true,
          deleted_at: null,
          created_at: '2026-09-01T10:00:00Z',
          extra: { role: 'admin' },
        }}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('用户详情')).toBeInTheDocument()
    expect(screen.getByText('username')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText('是')).toBeInTheDocument()
    expect(screen.getAllByText('-').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/"role": "admin"/)).toBeInTheDocument()
  })

  it('record 为 null 时不渲染字段', () => {
    render(<RecordDetailDrawer open title="详情" record={null} onClose={() => {}} />)
    expect(screen.queryByText('username')).not.toBeInTheDocument()
  })

  it('关闭回调触发', async () => {
    const onClose = vi.fn()
    render(<RecordDetailDrawer open title="详情" record={{ a: 1 }} onClose={onClose} />)
    fireEvent.click(screen.getByRole('button', { name: /close/i }))
    expect(onClose).toHaveBeenCalled()
  })
})
