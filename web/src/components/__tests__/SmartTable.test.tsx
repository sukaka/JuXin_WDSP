import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { Tooltip } from 'antd'
import SmartTable, { extractNodeText } from '../SmartTable'

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
    const box = (await screen.findByText('重置列宽与显隐')).parentElement!.parentElement as HTMLElement
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

  it('无初始宽度的列起拖时优先以表头真实渲染宽度为基准，并随列宽撑开同步扩大横向滚动宽度', () => {
    render(
      <SmartTable<Row>
        rowKey="id"
        columns={columns}
        dataSource={data}
        pagination={false}
        scroll={{ x: 500 }}
        storageKey="t-measured-width"
      />,
    )
    const handles = screen.getAllByLabelText('拖拽调整列宽')
    const firstTh = handles[0].closest('th') as HTMLTableCellElement
    vi.spyOn(firstTh, 'getBoundingClientRect').mockReturnValue({
      width: 480,
      height: 40,
      top: 0,
      left: 0,
      right: 480,
      bottom: 40,
      x: 0,
      y: 0,
      toJSON: () => ({}),
    })
    fireEvent.mouseDown(handles[0], { clientX: 200 })
    fireEvent.mouseMove(document, { clientX: 240 })
    fireEvent.mouseUp(document)
    const saved = JSON.parse(localStorage.getItem('smart-table:t-measured-width')!)
    // 以实测 480 为起点拖动 +40 → 520（不再回弹到 120）
    expect(saved.w.name).toBe(520)
    // 总列宽 520 + 100 = 620 > 初始 scroll.x(500)，表格宽度同步扩至 620px
    const table = document.querySelector('table') as HTMLTableElement
    expect(table.style.width).toBe('620px')
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

  it('列设置从 JSX 表头提取中文文本，不回退为原始英文 dataIndex', async () => {
    const jsxColumns = [
      {
        title: (
          <span>
            应用名称
            <Tooltip title="说明提示">
              <span />
            </Tooltip>
          </span>
        ),
        dataIndex: 'name',
        key: 'name',
      },
      {
        title: <span>运行状态</span>,
        dataIndex: 'status',
        key: 'status',
      },
    ]
    expect(extractNodeText(<span>风险等级</span>)).toBe('风险等级')
    expect(extractNodeText(['请求', ' ', <strong>次数</strong>])).toBe('请求 次数')
    render(<SmartTable<Row> rowKey="id" columns={jsxColumns} dataSource={data} pagination={false} />)
    fireEvent.click(screen.getByRole('button', { name: /列设置/ }))
    const box = (await screen.findByText('重置列宽与显隐')).parentElement!.parentElement as HTMLElement
    expect(within(box).getByLabelText('应用名称')).toBeInTheDocument()
    expect(within(box).getByLabelText('运行状态')).toBeInTheDocument()
    expect(within(box).queryByText('name')).not.toBeInTheDocument()
    expect(within(box).queryByText('status')).not.toBeInTheDocument()
  })

  it('默认在表格右上角展示刷新与自动刷新控件，hideRefresh 时隐藏', () => {
    const onRefresh = vi.fn()
    const { rerender } = render(
      <SmartTable<Row>
        rowKey="id"
        columns={columns}
        dataSource={data}
        pagination={false}
        onRefresh={onRefresh}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: '刷新列表' }))
    expect(onRefresh).toHaveBeenCalledTimes(1)
    expect(screen.getByRole('button', { name: '自动刷新' })).toBeInTheDocument()

    rerender(
      <SmartTable<Row>
        rowKey="id"
        columns={columns}
        dataSource={data}
        pagination={false}
        hideRefresh
      />,
    )
    expect(screen.queryByRole('button', { name: '刷新列表' })).not.toBeInTheDocument()
  })

  it('defaultHiddenKeys 首次默认隐藏指定列，列设置勾选后显示，重置恢复默认隐藏', async () => {
    const { unmount } = render(
      <SmartTable<Row>
        rowKey="id"
        columns={columns}
        dataSource={data}
        pagination={false}
        storageKey="t-default-hidden"
        defaultHiddenKeys={['status']}
      />,
    )
    const table = document.querySelector('table')!
    expect(within(table).getByText('名称')).toBeInTheDocument()
    expect(within(table).queryByText('状态')).not.toBeInTheDocument()

    // 在列设置中勾选显示，并持久化
    fireEvent.click(screen.getByRole('button', { name: /列设置/ }))
    const box = (await screen.findByText('重置列宽与显隐')).parentElement!.parentElement as HTMLElement
    fireEvent.click(within(box).getByLabelText('状态'))
    expect(within(table).getByText('状态')).toBeInTheDocument()
    expect(JSON.parse(localStorage.getItem('smart-table:t-default-hidden')!).h).toEqual([])

    // 重新挂载后仍保持用户勾选显示
    unmount()
    render(
      <SmartTable<Row>
        rowKey="id"
        columns={columns}
        dataSource={data}
        pagination={false}
        storageKey="t-default-hidden"
        defaultHiddenKeys={['status']}
      />,
    )
    const remountedTable = document.querySelector('table')!
    expect(within(remountedTable).getByText('状态')).toBeInTheDocument()

    // 点击重置后恢复 defaultHiddenKeys
    fireEvent.click(screen.getByRole('button', { name: /列设置/ }))
    fireEvent.click(await screen.findByText('重置列宽与显隐'))
    expect(within(remountedTable).queryByText('状态')).not.toBeInTheDocument()
    expect(JSON.parse(localStorage.getItem('smart-table:t-default-hidden')!).h).toEqual(['status'])
  })
})
