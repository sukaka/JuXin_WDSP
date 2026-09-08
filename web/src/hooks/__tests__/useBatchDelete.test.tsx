import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, Table } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import useBatchDelete from '../useBatchDelete'
import { ApiError } from '../../api/client'

interface Row {
  id: string
  name: string
}

const rows: Row[] = [
  { id: 'r1', name: '第一项' },
  { id: 'r2', name: '第二项' },
  { id: 'r3', name: '第三项' },
]

function Harness({ remove, canDelete }: { remove: (id: string) => Promise<unknown>; canDelete: boolean }) {
  const { rowSelection, batchDeleteButton } = useBatchDelete<Row>({
    remove,
    invalidateKeys: [['rows']],
    entityName: '测试项',
    canDelete,
  })
  return (
    <>
      {batchDeleteButton}
      <Table<Row>
        rowKey="id"
        rowSelection={rowSelection}
        dataSource={rows}
        columns={[{ title: '名称', dataIndex: 'name' }]}
        pagination={false}
      />
    </>
  )
}

function renderHarness(remove: (id: string) => Promise<unknown>, canDelete = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const invalidateSpy = vi.spyOn(qc, 'invalidateQueries')
  render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <Harness remove={remove} canDelete={canDelete} />
      </AntdApp>
    </QueryClientProvider>,
  )
  return { invalidateSpy }
}

/** 勾选前两行（跳过表头全选框） */
function selectFirstTwoRows() {
  const checkboxes = screen.getAllByRole('checkbox')
  fireEvent.click(checkboxes[1])
  fireEvent.click(checkboxes[2])
}

/** 确认弹窗中点击「删除」（antd 两字按钮自动插空格；锚定防误配「批量删除」按钮） */
async function confirmDelete() {
  const okBtn = await screen.findByRole('button', { name: /^删\s*除$/ })
  fireEvent.click(okBtn)
}

describe('useBatchDelete', () => {
  it('canDelete=false 时不渲染勾选列与批量删除按钮', () => {
    renderHarness(vi.fn().mockResolvedValue({}), false)
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /批量删除/ })).not.toBeInTheDocument()
  })

  it('未勾选时按钮禁用；勾选后显示条数', () => {
    renderHarness(vi.fn().mockResolvedValue({}))
    const btn = screen.getByRole('button', { name: /批量删除/ })
    expect(btn).toBeDisabled()
    selectFirstTwoRows()
    expect(screen.getByRole('button', { name: /批量删除（2）/ })).toBeEnabled()
  })

  it('全部删除成功：逐条调用、成功提示、失效查询并清空选择', async () => {
    const remove = vi.fn().mockResolvedValue({})
    const { invalidateSpy } = renderHarness(remove)
    selectFirstTwoRows()
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    await confirmDelete()
    await screen.findByText('已删除 2 条测试项')
    expect(remove.mock.calls.map((c) => c[0]).sort()).toEqual(['r1', 'r2'])
    expect(invalidateSpy).toHaveBeenCalledWith({ queryKey: ['rows'] })
    // 清空选择：按钮回到禁用且不带计数
    await waitFor(() => expect(screen.getByRole('button', { name: /^批量删除$/ })).toBeDisabled())
  })

  it('部分失败：汇总成功/失败条数并附首条原因', async () => {
    const remove = vi
      .fn()
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(new ApiError('记录被引用，无法删除', 'CONFLICT', 409))
    renderHarness(remove)
    selectFirstTwoRows()
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    await confirmDelete()
    await screen.findByText(/已删除 1 条，1 条失败：记录被引用，无法删除/)
  })

  it('全部失败：错误提示且不伪装成功', async () => {
    const remove = vi.fn().mockRejectedValue(new ApiError('服务器内部错误', 'INTERNAL_ERROR', 500))
    renderHarness(remove)
    selectFirstTwoRows()
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    await confirmDelete()
    await screen.findByText(/删除失败：服务器内部错误/)
  })

  it('removeMany 批量接口：一次调用全部 ID；接口错误如实提示', async () => {
    const removeMany = vi.fn().mockResolvedValue({ deleted: 2 })
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    function BatchHarness() {
      const { rowSelection, batchDeleteButton } = useBatchDelete<Row>({
        removeMany,
        invalidateKeys: [['rows']],
        entityName: '测试项',
        canDelete: true,
      })
      return (
        <>
          {batchDeleteButton}
          <Table<Row>
            rowKey="id"
            rowSelection={rowSelection}
            dataSource={rows}
            columns={[{ title: '名称', dataIndex: 'name' }]}
            pagination={false}
          />
        </>
      )
    }
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <BatchHarness />
        </AntdApp>
      </QueryClientProvider>,
    )
    selectFirstTwoRows()
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    await confirmDelete()
    await screen.findByText('已删除 2 条测试项')
    expect(removeMany).toHaveBeenCalledTimes(1)
    expect(removeMany.mock.calls[0][0].sort()).toEqual(['r1', 'r2'])
  })

  it('rowDisabled：禁用行勾选框不可选，表头全选跳过禁用行', async () => {
    const remove = vi.fn().mockResolvedValue({})
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    function DisabledHarness() {
      const { rowSelection, batchDeleteButton } = useBatchDelete<Row>({
        remove,
        invalidateKeys: [['rows']],
        entityName: '测试项',
        canDelete: true,
        rowDisabled: (record) => record.id === 'r2',
      })
      return (
        <>
          {batchDeleteButton}
          <Table<Row>
            rowKey="id"
            rowSelection={rowSelection}
            dataSource={rows}
            columns={[{ title: '名称', dataIndex: 'name' }]}
            pagination={false}
          />
        </>
      )
    }
    render(
      <QueryClientProvider client={qc}>
        <AntdApp>
          <DisabledHarness />
        </AntdApp>
      </QueryClientProvider>,
    )
    const checkboxes = screen.getAllByRole('checkbox')
    // 表头全选 + 3 行；r2 行勾选框禁用
    expect(checkboxes).toHaveLength(4)
    expect(checkboxes[2]).toBeDisabled()
    expect(checkboxes[1]).toBeEnabled()
    expect(checkboxes[3]).toBeEnabled()
    // 表头全选：仅勾选未禁用的 r1/r3
    fireEvent.click(checkboxes[0])
    fireEvent.click(screen.getByRole('button', { name: /批量删除（2）/ }))
    await confirmDelete()
    await screen.findByText('已删除 2 条测试项')
    expect(remove.mock.calls.map((c) => c[0]).sort()).toEqual(['r1', 'r3'])
  })
})
