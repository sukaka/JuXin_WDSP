import { useState, type Key } from 'react'
import type { TableProps } from 'antd'

/**
 * useExportSelection：列表页「勾选行 + 选择导出」轻量状态封装。
 * - enabled=false（无导出权限）时 rowSelection 返回 undefined，不展示复选框列；
 * - preserveSelectedRowKeys=true，翻页或刷新时保留已勾选项；
 * - 配合 ExportDropdown 实现「导出已选 / 导出筛选结果 / 导出全部」统一交互。
 */
export interface UseExportSelectionResult<T extends object> {
  selectedIds: string[]
  selectedCount: number
  clearSelection: () => void
  rowSelection: TableProps<T>['rowSelection']
}

export default function useExportSelection<T extends object>(
  enabled: boolean,
): UseExportSelectionResult<T> {
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([])

  const clearSelection = () => setSelectedRowKeys([])

  return {
    selectedIds: selectedRowKeys.map(String),
    selectedCount: selectedRowKeys.length,
    clearSelection,
    rowSelection: enabled
      ? {
          selectedRowKeys,
          onChange: setSelectedRowKeys,
          preserveSelectedRowKeys: true,
        }
      : undefined,
  }
}
