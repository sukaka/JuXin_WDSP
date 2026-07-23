import { beforeEach, describe, expect, it } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import SmartTable from '../SmartTable'

interface Row {
  id: string
  name: string
  status: string
}

const columns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '状态', dataIndex: 'status', key: 'status', width: 100 },
]

const data: Row[] = [{ id: '1', name: 'alpha', status: 'ON' }]

describe('SmartTable', () => {
  beforeEach(() => {
    localStorage.clear()
  })

  it('渲染全部列与数据', () => {
    render(<SmartTable<Row> rowKey="id" columns={columns} dataSource={data} pagination={false} />)
    expect(screen.getByText('名称')).toBeInTheDocument()
    expect(screen.getByText('状态')).toBeInTheDocument()
    expect(screen.getByText('alpha')).toBeInTheDocument()
  })

  it('列设置取消勾选后隐藏该列，并持久化到 localStorage', async () => {
    render(
      <SmartTable<Row> rowKey="id" columns={columns} dataSource={data} pagination={false} storageKey="t-hide" />,
    )
    fireEvent.click(screen.getByRole('button', { name: /列设置/ }))
    const popover = await screen.findByText('重置列宽与显隐')
    const box = popover.parentElement!.parentElement!
    fireEvent.click(within(box as HTMLElement).getByLabelText('状态'))
    const table = document.querySelector('table')!
    expect(within(table).queryByText('状态')).not.toBeInTheDocument()
    expect(within(table).getByText('名称')).toBeInTheDocument()
    const saved = JSON.parse(localStorage.getItem('smart-table:t-hide')!)
    expect(saved.h).toContain('status')
  })

  it('重置后恢复全部列', async () => {
    render(
      <SmartTable<Row> rowKey="id" columns={columns} dataSource={data} pagination={false} storageKey="t-reset" />,
    )
    fireEvent.click(screen.getByRole('button', { name: /列设置/ }))
    let box = (await screen.findByText('重置列宽与显隐')).parentElement!.parentElement as HTMLElement
    fireEvent.click(within(box).getByLabelText('状态'))
    const table = document.querySelector('table')!
    expect(within(table).queryByText('状态')).not.toBeInTheDocument()
    fireEvent.click(screen.getByText('重置列宽与显隐'))
    expect(within(table).getByText('状态')).toBeInTheDocument()
    const saved = JSON.parse(localStorage.getItem('smart-table:t-reset')!)
    expect(saved.h).toHaveLength(0)
    expect(saved.w).toEqual({})
  })

  it('拖拽手柄调整列宽并持久化', () => {
    render(
      <SmartTable<Row> rowKey="id" columns={columns} dataSource={data} pagination={false} storageKey="t-width" />,
    )
    const handles = screen.getAllByLabelText('拖拽调整列宽')
    fireEvent.mouseDown(handles[0], { clientX: 100 })
    fireEvent.mouseMove(document, { clientX: 160 })
    fireEvent.mouseUp(document)
    const saved = JSON.parse(localStorage.getItem('smart-table:t-width')!)
    // 初始宽 120，拖动 +60 → 180
    expect(saved.w.name).toBe(180)
    // 未拖动的列不落宽
    expect(saved.w.status).toBeUndefined()
  })

  it('载入时恢复上次的显隐与列宽', () => {
    localStorage.setItem('smart-table:t-restore', JSON.stringify({ w: { name: 200 }, h: ['status'] }))
    render(
      <SmartTable<Row> rowKey="id" columns={columns} dataSource={data} pagination={false} storageKey="t-restore" />,
    )
    const table = document.querySelector('table')!
    expect(within(table).queryByText('状态')).not.toBeInTheDocument()
    expect(within(table).getByText('名称')).toBeInTheDocument()
  })
})
