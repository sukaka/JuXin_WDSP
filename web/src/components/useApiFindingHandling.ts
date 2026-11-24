import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Form } from 'antd'
import {
  apiFindingsApi,
  type ApiFinding,
  type ApiFindingHandleAction,
} from '../api/apiSecurity'
import { ApiError } from '../api/client'
import { useAuthStore } from '../stores/auth'
import { hasAnyPermission, hasPermission } from '../utils/permission'
import { formatApiFindingTitle } from '../utils/stage8'

/** 风险发现全部处置动作（confirm/start/ignore/archive 备注可选；resolve/false-positive 走必填弹窗） */
export type FindingAction = ApiFindingHandleAction | 'resolve' | 'false-positive'

/**
 * 按当前状态给出可用处置动作（与 server 端 risk.go 状态机迁移表一一对应；
 * 后端状态机为最终裁决，此处仅做按钮显隐）：
 * NEW → confirm/false-positive/ignore；CONFIRMED → start/resolve/false-positive/ignore；
 * IN_PROGRESS → resolve/false-positive/ignore；RESOLVED/FALSE_POSITIVE/IGNORED → archive；ARCHIVED 终态无动作。
 */
export function availableFindingActions(status: string): FindingAction[] {
  switch ((status || '').toUpperCase()) {
    case 'NEW':
      return ['confirm', 'false-positive', 'ignore']
    case 'CONFIRMED':
      return ['start', 'resolve', 'false-positive', 'ignore']
    case 'IN_PROGRESS':
      return ['resolve', 'false-positive', 'ignore']
    case 'RESOLVED':
    case 'FALSE_POSITIVE':
    case 'IGNORED':
      return ['archive']
    default:
      return []
  }
}

/** 处置动作中文名（按钮与成功提示共用） */
export const FINDING_ACTION_LABEL: Record<FindingAction, string> = {
  confirm: '确认',
  start: '开始处置',
  resolve: '标记解决',
  'false-positive': '标记误报',
  ignore: '忽略',
  archive: '归档',
}

/**
 * 风险发现七态处置状态与交互逻辑（API 风险页 / 影子与僵尸 API 页共用）：
 * 统一封装权限判定、confirm/start/ignore/archive 二次确认与 resolve/false-positive 弹窗提交，
 * 处置成功后统一失效 `['api-findings']` 查询缓存（含列表、汇总与顶部统计卡片）。
 */
export function useApiFindingHandling() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canHandle = hasPermission(permissions, 'api_risk.handle')
  const canViewRisk = hasAnyPermission(permissions, ['api_risk.read', 'api_risk.handle'])

  const [selected, setSelected] = useState<ApiFinding | null>(null)
  const [resolveTarget, setResolveTarget] = useState<ApiFinding | null>(null)
  const [fpTarget, setFpTarget] = useState<ApiFinding | null>(null)
  const [resolveForm] = Form.useForm<{ resolution: string }>()
  const [fpForm] = Form.useForm<{ reason: string }>()

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  /** 处置成功后：失效列表/汇总/计数/详情、关闭抽屉与弹窗 */
  const afterAction = () => {
    void qc.invalidateQueries({ queryKey: ['api-findings'] })
    setSelected(null)
    setResolveTarget(null)
    setFpTarget(null)
  }

  const handleMut = useMutation({
    mutationFn: ({ id, action }: { id: string; action: ApiFindingHandleAction }) =>
      apiFindingsApi.handle(id, action),
    onSuccess: (_r, vars) => {
      message.success(`${FINDING_ACTION_LABEL[vars.action]}成功`)
      afterAction()
    },
    onError,
  })

  const resolveMut = useMutation({
    mutationFn: ({ id, resolution }: { id: string; resolution: string }) =>
      apiFindingsApi.resolve(id, resolution),
    onSuccess: () => {
      message.success('已标记为解决')
      afterAction()
    },
    onError,
  })

  const falsePositiveMut = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      apiFindingsApi.falsePositive(id, reason),
    onSuccess: () => {
      message.success('已标记为误报')
      afterAction()
    },
    onError,
  })

  /** confirm/start/ignore/archive：二次确认后直接提交（备注可选，页面从简不传） */
  const confirmAction = (record: ApiFinding, action: ApiFindingHandleAction) => {
    const displayTitle = formatApiFindingTitle(record.title, {
      findingType: record.finding_type,
      detail: record.detail,
    })
    const textMap: Record<ApiFindingHandleAction, string> = {
      confirm: `确定确认风险「${displayTitle}」吗？确认后表示该风险属实。`,
      start: `确定开始处置风险「${displayTitle}」吗？状态将流转为处理中。`,
      ignore: `确定忽略风险「${displayTitle}」吗？忽略后不再出现在待处置列表。`,
      archive: `确定归档风险「${displayTitle}」吗？归档后该风险转为历史记录。`,
    }
    modal.confirm({
      title: `${FINDING_ACTION_LABEL[action]}确认`,
      content: textMap[action],
      onOk: () => handleMut.mutate({ id: record.id, action }),
    })
  }

  /** 处置动作分发：resolve/false-positive 走必填弹窗，其余二次确认 */
  const runAction = (record: ApiFinding, action: FindingAction) => {
    if (action === 'resolve') {
      setResolveTarget(record)
    } else if (action === 'false-positive') {
      setFpTarget(record)
    } else {
      confirmAction(record, action)
    }
  }

  return {
    canHandle,
    canViewRisk,
    selected,
    setSelected,
    runAction,
    resolveTarget,
    setResolveTarget,
    fpTarget,
    setFpTarget,
    resolveForm,
    fpForm,
    resolveMut,
    falsePositiveMut,
  }
}
