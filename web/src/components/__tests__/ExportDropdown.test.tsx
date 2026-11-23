import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import ExportDropdown, { MAX_EXPORT_SELECTED } from '../ExportDropdown'

function renderWithApp(ui: React.ReactElement) {
  return render(<AntdApp>{ui}</AntdApp>)
}

describe('ExportDropdown', () => {
  it('悬停导出按钮不弹出提示遮挡菜单，点击才展开，可选 tooltip 独立渲染在帮助图标上', async () => {
    const onExportFiltered = vi.fn()
    const onExportAll = vi.fn()
    renderWithApp(
      <ExportDropdown
        tooltip="最多导出 10000 条"
        onExportFiltered={onExportFiltered}
        onExportAll={onExportAll}
      />,
    )

    const exportBtn = screen.getByRole('button', { name: /导\s*出/ })
    // 悬停导出按钮本身不会触发菜单也不弹出 tooltip（避免遮挡下拉菜单）
    fireEvent.mouseEnter(exportBtn)
    expect(screen.queryByText('最多导出 10000 条')).not.toBeInTheDocument()
    expect(screen.queryByText('导出筛选结果')).not.toBeInTheDocument()

    // 悬停独立的「导出说明」图标才显示 tooltip
    const helpIcon = screen.getByLabelText('导出说明')
    fireEvent.mouseEnter(helpIcon)
    expect(await screen.findByText('最多导出 10000 条')).toBeInTheDocument()

    // 点击按钮展开下拉菜单
    fireEvent.click(exportBtn)
    fireEvent.click(await screen.findByText('导出筛选结果'))
    expect(onExportFiltered).toHaveBeenCalledTimes(1)
    expect(onExportAll).not.toHaveBeenCalled()
  })

  it('未勾选时「导出已选」禁用且不会触发回调（已选的内容才导出）', async () => {
    const onExportSelected = vi.fn()
    const onExportFiltered = vi.fn()
    const onExportAll = vi.fn()
    renderWithApp(
      <ExportDropdown
        selectedCount={0}
        onExportSelected={onExportSelected}
        onExportFiltered={onExportFiltered}
        onExportAll={onExportAll}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: /导\s*出/ }))
    const disabledLabel = await screen.findByText('导出已选（请先勾选）')
    const menuItem = disabledLabel.closest('li')
    expect(menuItem).toHaveAttribute('aria-disabled', 'true')
    fireEvent.click(disabledLabel)
    expect(onExportSelected).not.toHaveBeenCalled()
    expect(onExportFiltered).not.toHaveBeenCalled()

    // 点击导出全部正常工作
    fireEvent.click(screen.getByText('导出全部'))
    expect(onExportAll).toHaveBeenCalledTimes(1)
  })

  it('勾选记录后支持「导出已选（N）」与「清空」按钮', async () => {
    const onExportSelected = vi.fn()
    const onClearSelection = vi.fn()
    renderWithApp(
      <ExportDropdown
        selectedCount={3}
        onClearSelection={onClearSelection}
        onExportSelected={onExportSelected}
        onExportFiltered={vi.fn()}
        onExportAll={vi.fn()}
      />,
    )

    expect(screen.getByText('已选 3 条')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /清\s*空/ }))
    expect(onClearSelection).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByRole('button', { name: /导\s*出/ }))
    fireEvent.click(await screen.findByText('导出已选（3）'))
    expect(onExportSelected).toHaveBeenCalledTimes(1)
  })

  it('勾选条数超过上限时拦住并提示，不发起非法导出', async () => {
    const onExportSelected = vi.fn()
    renderWithApp(
      <ExportDropdown
        selectedCount={MAX_EXPORT_SELECTED + 1}
        onExportSelected={onExportSelected}
        onExportFiltered={vi.fn()}
      />,
    )

    fireEvent.click(screen.getByRole('button', { name: /导\s*出/ }))
    fireEvent.click(await screen.findByText(`导出已选（${MAX_EXPORT_SELECTED + 1}）`))
    expect(onExportSelected).not.toHaveBeenCalled()
    expect(
      await screen.findByText(new RegExp(`单次选择导出最多支持 ${MAX_EXPORT_SELECTED} 条`)),
    ).toBeInTheDocument()
  })
})
