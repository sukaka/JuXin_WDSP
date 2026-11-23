import { useState, type Key, type ReactNode } from 'react'
import { App as AntdApp, Button } from 'antd'
import type { TableProps } from 'antd'
import { useQueryClient } from '@tanstack/react-query'
import { ApiError } from '../api/client'

/**
 * useBatchDelete：全站列表统一的「勾选 + 批量删除」能力（不引入新依赖）。
 * - rowSelection 传给 SmartTable / antd Table：表头全选当前页，preserveSelectedRowKeys 跨页保留勾选；
 *   可选 rowDisabled 按行禁用勾选（透传 getCheckboxProps，全选自动跳过禁用行），
 *   用于系统内置/无权限/当前会话等不可删行；
 * - batchDeleteButton 渲染到筛选工具栏：二次确认后执行删除（removeMany 批量接口一次调用，
 *   或 remove 单删接口 Promise.allSettled 逐条 fan-out 并汇总成功/失败，失败附首条原因不静默），
 *   成功后失效查询并清空选择；
 * - canDelete=false 时两者都不产出（无权限用户看不到勾选列与按钮）。
 */
export interface UseBatchDeleteOptionsBase<T extends object> {
  /** 删除成功后失效的 TanStack Query 查询键 */
  invalidateKeys: unknown[][]
  /** 实体中文名（确认与结果文案，如「敏感字段」） */
  entityName: string
  /** 删除权限（沿用该页单删按钮的权限码） */
  canDelete: boolean
  /** 行级禁用（可选）：返回 true 的行不可勾选（透传 antd getCheckboxProps），与行内单删的显隐口径保持一致 */
  rowDisabled?: (record: T) => boolean
}

/** 删除策略二选一：remove 逐条 fan-out（后端仅单删接口）；removeMany 一次调用（后端批量接口） */
export type UseBatchDeleteOptions<T extends object> = UseBatchDeleteOptionsBase<T> &
  (
    | { remove: (id: string) => Promise<unknown>; removeMany?: never }
    | { removeMany: (ids: string[]) => Promise<unknown>; remove?: never }
  )

export interface UseBatchDeleteResult<T extends object> {
  rowSelection: TableProps<T>['rowSelection']
  batchDeleteButton: ReactNode
  selectedRowKeys: string[]
  selectedCount: number
  clearSelection: () => void
}

export default function useBatchDelete<T extends object>({
  remove,
  removeMany,
  invalidateKeys,
  entityName,
  canDelete,
  rowDisabled,
}: UseBatchDeleteOptions<T>): UseBatchDeleteResult<T> {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const [selectedRowKeys, setSelectedRowKeys] = useState<Key[]>([])
  const [pending, setPending] = useState(false)

  const clearSelection = () => setSelectedRowKeys([])

  /** 删除执行：removeMany 走批量接口一次调用；否则 Promise.allSettled 逐条 fan-out 并汇总。
   *  返回 Promise 使确认弹窗保持 loading 至完成（onOk 支持异步）。 */
  const runBatch = async (ids: string[]) => {
    setPending(true)
    try {
      if (removeMany) {
        await removeMany(ids)
        message.success(`已删除 ${ids.length} 条${entityName}`)
      } else {
        const results = await Promise.allSettled(ids.map((id) => remove!(id)))
        const failed = results.filter((r): r is PromiseRejectedResult => r.status === 'rejected')
        const succeeded = results.length - failed.length
        if (failed.length === 0) {
          message.success(`已删除 ${succeeded} 条${entityName}`)
        } else {
          const first = failed[0].reason
          const reason = first instanceof ApiError ? first.message : '操作失败'
          if (succeeded > 0) {
            message.warning(`已删除 ${succeeded} 条，${failed.length} 条失败：${reason}`)
          } else {
            message.error(`删除失败：${reason}`)
          }
        }
      }
      for (const queryKey of invalidateKeys) {
        void qc.invalidateQueries({ queryKey })
      }
      clearSelection()
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '删除失败')
    } finally {
      setPending(false)
    }
  }

  const openConfirm = () => {
    const ids = selectedRowKeys.map(String)
    modal.confirm({
      title: '批量删除确认',
      content: `确定删除选中的 ${ids.length} 条${entityName}吗？删除后不可恢复。`,
      okText: '删除',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () => runBatch(ids),
    })
  }

  return {
    rowSelection: canDelete
      ? {
          selectedRowKeys,
          onChange: setSelectedRowKeys,
          preserveSelectedRowKeys: true,
          ...(rowDisabled
            ? { getCheckboxProps: (record: T) => ({ disabled: rowDisabled(record) }) }
            : {}),
        }
      : undefined,
    batchDeleteButton: canDelete ? (
      <Button danger disabled={selectedRowKeys.length === 0} loading={pending} onClick={openConfirm}>
        批量删除{selectedRowKeys.length > 0 ? `（${selectedRowKeys.length}）` : ''}
      </Button>
    ) : null,
    selectedRowKeys: selectedRowKeys.map(String),
    selectedCount: selectedRowKeys.length,
    clearSelection,
  }
}
