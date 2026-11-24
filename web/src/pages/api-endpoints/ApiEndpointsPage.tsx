import { useEffect, useMemo, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Badge,
  Button,
  Card,
  Checkbox,
  Divider,
  Input,
  InputNumber,
  Modal,
  Select,
  Space,
  Tag,
  Tooltip,
  Tree,
  Typography,
  theme,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import ExportDropdown from '../../components/ExportDropdown'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useExportSelection from '../../hooks/useExportSelection'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { ASSET_VALUE_DIMENSION_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import {
  API_ENDPOINT_STATUS_META,
  API_LEARNING_STATUS_META,
  apiAssetValueReasonLabel,
  buildDirectoryTree,
} from '../../utils/stage8'
import CleanupNoiseModal from './CleanupNoiseModal'
import DiscoveryFilterModal from './DiscoveryFilterModal'
import EndpointDetailDrawer from './EndpointDetailDrawer'

/** 资产状态展示映射（公共映射 + 本地补充 ZOMBIE 僵尸态，见 apiassets 生命周期状态机） */
const ENDPOINT_STATUS_META: Record<string, { color: string; label: string }> = {
  ...API_ENDPOINT_STATUS_META,
  ZOMBIE: { color: 'magenta', label: '僵尸' },
}

/** 资产价值等级（与 server/internal/apiassets 价值评分四档一致） */
const ASSET_VALUE_META: Record<string, { color: string; label: string }> = {
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'gold', label: '中' },
  HIGH: { color: 'orange', label: '高' },
  CRITICAL: { color: 'magenta', label: '严重' },
}

/** 站点过滤：applicationId 与 unassigned 二选一；皆空表示全部 */
interface SiteFilter {
  applicationId?: string
  unassigned?: boolean
}

/** API 接口资产（WDSP / 阶段8）：发现由网关自动上报，页面负责确认与忽略 */
export default function ApiEndpointsPage() {
  const { message, modal } = AntdApp.useApp()
  const { token } = theme.useToken()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const canIgnore = hasPermission(permissions, 'api_asset.ignore')
  const canLearnStart = hasPermission(permissions, 'api_learning.start')
  const canMerge = hasPermission(permissions, 'api_asset.merge')
  const canSplit = hasPermission(permissions, 'api_asset.split')
  const canEdit = hasPermission(permissions, 'api_asset.edit')
  const canExport = hasPermission(permissions, 'api_asset.export')
  const {
    selectedIds,
    selectedCount,
    clearSelection,
    rowSelection,
  } = useExportSelection<ApiEndpointItem>(
    canExport || canConfirm || canIgnore || canLearnStart,
  )

  const [assetStatus, setAssetStatus] = useState<string | undefined>()
  const [learningStatus, setLearningStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [siteFilter, setSiteFilter] = useState<SiteFilter>({})
  const [directoryPath, setDirectoryPath] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detail, setDetail] = useState<ApiEndpointItem | null>(null)
  const [filterModalOpen, setFilterModalOpen] = useState(false)
  const [cleanupModalOpen, setCleanupModalOpen] = useState(false)
  /** 确认资产弹窗（单条/批量共用）：具备 api_learning.start 权限时可选联动自动启动学习 */
  const [confirmDialog, setConfirmDialog] = useState<{
    mode: 'single' | 'batch'
    ids: string[]
    label?: string
  } | null>(null)
  const [confirmAutoStart, setConfirmAutoStart] = useState(false)
  const [confirmAutoStartTouched, setConfirmAutoStartTouched] = useState(false)
  const [confirmSampleTarget, setConfirmSampleTarget] = useState<number | null>(
    100,
  )
  /** 批量启动学习弹窗 */
  const [batchLearnOpen, setBatchLearnOpen] = useState(false)
  const [batchSampleTarget, setBatchSampleTarget] = useState<number | null>(100)
  /** 合并弹窗：mergeSource 为保留方（主接口），mergeTargetId 为待并入接口（并入后删除） */
  const [mergeSource, setMergeSource] = useState<ApiEndpointItem | null>(null)
  const [mergeTargetId, setMergeTargetId] = useState<string | undefined>()
  /** 拆分弹窗：splitSource 为原接口，splitPaths 为按行输入的拆分路径 */
  const [splitSource, setSplitSource] = useState<ApiEndpointItem | null>(null)
  const [splitPaths, setSplitPaths] = useState('')

  const siteSummaryQuery = useQuery({
    queryKey: ['api-endpoints', 'site-summary'],
    queryFn: () => apiEndpointsApi.siteSummary(),
  })

  const directoryTreeQuery = useQuery({
    queryKey: [
      'api-endpoints',
      'directory-tree',
      siteFilter.applicationId,
      siteFilter.unassigned,
    ],
    queryFn: () =>
      apiEndpointsApi.directoryTree({
        application_id: siteFilter.applicationId,
        unassigned: siteFilter.unassigned,
      }),
  })

  const listQuery = useQuery({
    queryKey: [
      'api-endpoints',
      assetStatus,
      learningStatus,
      keyword,
      siteFilter.applicationId,
      siteFilter.unassigned,
      directoryPath,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiEndpointsApi.list({
        asset_status: assetStatus,
        learning_status: learningStatus,
        keyword,
        application_id: siteFilter.applicationId,
        unassigned: siteFilter.unassigned,
        directory_path: directoryPath,
        page,
        page_size: pageSize,
      }),
  })

  /** 确认弹窗打开且具备学习启动权限时，读取系统默认开关（api_learning:auto_start_on_confirm） */
  const learningOptionsQuery = useQuery({
    queryKey: ['api-endpoints', 'learning-options'],
    queryFn: () => apiEndpointsApi.learningOptions(),
    enabled: confirmDialog !== null && canLearnStart,
    retry: false,
  })

  useEffect(() => {
    if (
      confirmDialog !== null &&
      !confirmAutoStartTouched &&
      learningOptionsQuery.data
    ) {
      setConfirmAutoStart(learningOptionsQuery.data.auto_start_on_confirm)
      setConfirmSampleTarget(
        learningOptionsQuery.data.default_sample_target || 100,
      )
    }
  }, [confirmDialog, confirmAutoStartTouched, learningOptionsQuery.data])

  const confirmEndpointsMut = useMutation({
    mutationFn: (vars: {
      mode: 'single' | 'batch'
      ids: string[]
      autoStartLearning?: boolean
      sampleTarget?: number
    }) =>
      apiEndpointsApi.confirm(
        vars.ids,
        vars.autoStartLearning !== undefined
          ? {
              auto_start_learning: vars.autoStartLearning,
              ...(vars.autoStartLearning && vars.sampleTarget !== undefined
                ? { sample_target: vars.sampleTarget }
                : {}),
            }
          : undefined,
      ),
    onSuccess: (r, vars) => {
      const started = r.learning_started ?? 0
      const skipped = r.learning_skipped ?? 0
      const learnFailed = r.learning_failed?.length ?? 0
      if (vars.mode === 'single') {
        if (r.failed && r.failed.length > 0) {
          message.error(r.failed[0].reason || '确认失败')
        } else if (learnFailed > 0) {
          message.warning('已确认，但自动启动学习失败，请到学习中心重试')
        } else if (started > 0) {
          message.success('已确认并启动学习')
        } else if (skipped > 0) {
          message.success('已确认（已在学习中或已完成学习，已跳过启动）')
        } else {
          message.success('已确认')
        }
      } else {
        const parts = [`已批量确认 ${r.confirmed} 个接口`]
        if (started > 0) parts.push(`启动学习 ${started} 个`)
        if (skipped > 0) parts.push(`跳过学习 ${skipped} 个`)
        if (learnFailed > 0) parts.push(`学习启动失败 ${learnFailed} 个`)
        if (r.failed && r.failed.length > 0) {
          parts.push(`确认失败 ${r.failed.length} 个`)
          message.warning(parts.join('，'))
        } else if (learnFailed > 0) {
          message.warning(parts.join('，'))
        } else {
          message.success(parts.join('，'))
        }
        clearSelection()
      }
      setConfirmDialog(null)
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
      void qc.invalidateQueries({ queryKey: ['api-learning'] })
    },
    onError: (e: unknown, vars) =>
      message.error(
        e instanceof ApiError
          ? e.message
          : vars.mode === 'batch'
            ? '批量确认失败'
            : '确认失败',
      ),
  })

  const learningStartBatchMut = useMutation({
    mutationFn: ({
      ids,
      sampleTarget,
    }: {
      ids: string[]
      sampleTarget?: number
    }) => apiEndpointsApi.learningStartBatch(ids, sampleTarget),
    onSuccess: (r) => {
      if (r.failed && r.failed.length > 0) {
        message.warning(
          r.message || `已启动 ${r.started} 个，${r.failed.length} 个失败`,
        )
      } else if (r.started === 0 && r.skipped > 0) {
        message.info(
          r.message || `所选 ${r.skipped} 个接口均已在学习中，已自动跳过`,
        )
      } else {
        message.success(r.message || `已批量启动 ${r.started} 个接口学习`)
      }
      setBatchLearnOpen(false)
      clearSelection()
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
      void qc.invalidateQueries({ queryKey: ['api-learning'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '批量启动学习失败'),
  })

  const ignoreBatchMut = useMutation({
    mutationFn: (ids: string[]) => apiEndpointsApi.ignoreBatch(ids),
    onSuccess: (r) => {
      if (r.failed && r.failed.length > 0) {
        message.warning(`已忽略 ${r.ignored} 个，${r.failed.length} 个失败`)
      } else {
        message.success(`已批量忽略 ${r.ignored} 个接口`)
      }
      clearSelection()
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '批量忽略失败'),
  })

  const ignoreMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.ignore(id),
    onSuccess: (r) => {
      message.success(r.message || '已忽略')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '忽略失败'),
  })

  const deprecateMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.deprecate(id),
    onSuccess: (r) => {
      message.success(r.message || '已标记下线')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '下线失败'),
  })

  const restoreMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.restore(id),
    onSuccess: (r) => {
      message.success(r.message || '已恢复为已确认')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '恢复失败'),
  })

  /** 合并目标候选：仅在合并弹窗打开时加载（取前 100 条，排除保留方自身） */
  const mergeOptionsQuery = useQuery({
    queryKey: ['api-endpoints', 'merge-options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
    enabled: mergeSource !== null,
  })

  const mergeMut = useMutation({
    mutationFn: ({ id, otherId }: { id: string; otherId: string }) =>
      apiEndpointsApi.merge(id, otherId),
    onSuccess: (r) => {
      message.success(r.message || '接口已合并')
      setMergeSource(null)
      setMergeTargetId(undefined)
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '合并失败'),
  })

  const splitMut = useMutation({
    mutationFn: ({ id, paths }: { id: string; paths: string[] }) =>
      apiEndpointsApi.split(id, paths),
    onSuccess: (r) => {
      message.success(r.message || '接口已拆分')
      setSplitSource(null)
      setSplitPaths('')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '拆分失败'),
  })

  const openMerge = (record: ApiEndpointItem) => {
    setMergeSource(record)
    setMergeTargetId(undefined)
  }

  const openSplit = (record: ApiEndpointItem) => {
    setSplitSource(record)
    setSplitPaths('')
  }

  const handleMergeOk = () => {
    if (!mergeSource) return
    if (!mergeTargetId) {
      message.warning('请选择待并入的接口')
      return
    }
    mergeMut.mutate({ id: mergeSource.id, otherId: mergeTargetId })
  }

  const handleSplitOk = () => {
    if (!splitSource) return
    // 按行拆分：去空白行，服务端再做归一化与冲突校验（单次最多 50 个路径）
    const paths = splitPaths
      .split('\n')
      .map((p) => p.trim())
      .filter(Boolean)
    if (paths.length === 0) {
      message.warning('请输入拆分路径（每行一个）')
      return
    }
    if (paths.length > 50) {
      message.warning('单次最多拆分 50 个路径')
      return
    }
    splitMut.mutate({ id: splitSource.id, paths })
  }

  /** 行内操作统一二次确认 */
  const openConfirmDialog = (next: {
    mode: 'single' | 'batch'
    ids: string[]
    label?: string
  }) => {
    setConfirmAutoStartTouched(false)
    setConfirmAutoStart(learningOptionsQuery.data?.auto_start_on_confirm ?? false)
    setConfirmSampleTarget(
      learningOptionsQuery.data?.default_sample_target ?? 100,
    )
    setConfirmDialog(next)
  }

  const confirmEndpoint = (record: ApiEndpointItem) => {
    openConfirmDialog({
      mode: 'single',
      ids: [record.id],
      label: `${record.http_method} ${record.normalized_path}`,
    })
  }

  const ignoreEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定忽略接口「${record.http_method} ${record.normalized_path}」吗？忽略后标记为已忽略，不再进入正式资产管理。`,
      onOk: () => ignoreMut.mutate(record.id),
    })
  }

  const confirmBatchSelected = () => {
    if (selectedCount === 0) return
    openConfirmDialog({
      mode: 'batch',
      ids: [...selectedIds],
    })
  }

  const handleConfirmOk = () => {
    if (!confirmDialog) return
    if (canLearnStart && confirmAutoStart) {
      if (
        typeof confirmSampleTarget !== 'number' ||
        !Number.isInteger(confirmSampleTarget) ||
        confirmSampleTarget < 10 ||
        confirmSampleTarget > 100000
      ) {
        message.warning('样本目标需为 10~100000 之间的整数')
        return
      }
    }
    confirmEndpointsMut.mutate({
      mode: confirmDialog.mode,
      ids: confirmDialog.ids,
      ...(canLearnStart
        ? {
            autoStartLearning: confirmAutoStart,
            sampleTarget: confirmAutoStart
              ? (confirmSampleTarget ?? 100)
              : undefined,
          }
        : {}),
    })
  }

  const openBatchLearn = () => {
    if (selectedCount === 0) return
    setBatchSampleTarget(learningOptionsQuery.data?.default_sample_target ?? 100)
    setBatchLearnOpen(true)
  }

  const handleBatchLearnOk = () => {
    if (selectedCount === 0) return
    if (
      typeof batchSampleTarget !== 'number' ||
      !Number.isInteger(batchSampleTarget) ||
      batchSampleTarget < 10 ||
      batchSampleTarget > 100000
    ) {
      message.warning('样本目标需为 10~100000 之间的整数')
      return
    }
    learningStartBatchMut.mutate({
      ids: [...selectedIds],
      sampleTarget: batchSampleTarget,
    })
  }

  const ignoreBatchSelected = () => {
    if (selectedCount === 0) return
    modal.confirm({
      title: '批量忽略接口',
      content: `确定将已勾选的 ${selectedCount} 个接口标记为已忽略吗？忽略后不再进入正式资产管理。`,
      okText: '确认忽略',
      cancelText: '取消',
      okButtonProps: { danger: true },
      onOk: () => ignoreBatchMut.mutate(selectedIds),
    })
  }

  const deprecateEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '标记下线',
      content: `确定将接口「${record.http_method} ${record.normalized_path}」标记下线吗？下线后若观察窗口内仍有流量将自动转为僵尸态。`,
      onOk: () => deprecateMut.mutate(record.id),
    })
  }

  const restoreEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '恢复接口',
      content: `确定将接口「${record.http_method} ${record.normalized_path}」恢复为已确认吗？恢复后重新进入正式资产管理。`,
      onOk: () => restoreMut.mutate(record.id),
    })
  }

  /** 切换站点过滤：重置目录选择与分页 */
  const selectSite = (filter: SiteFilter) => {
    setSiteFilter(filter)
    setDirectoryPath(undefined)
    setPage(1)
  }

  const clearDirectory = () => {
    setDirectoryPath(undefined)
    setPage(1)
  }

  const siteItems = siteSummaryQuery.data?.items ?? []
  const unassignedCount = siteSummaryQuery.data?.unassigned ?? 0
  const totalCount =
    siteItems.reduce((sum, s) => sum + s.endpoint_count, 0) + unassignedCount
  /** 站点展示名：优先主域名/IP，无域名记录时回退应用名 */
  const siteLabel = (s: {
    application_name: string
    application_domain?: string
  }) => s.application_domain || s.application_name

  const currentSiteName = siteFilter.unassigned
    ? '未归属'
    : siteFilter.applicationId
      ? (() => {
          const s = siteItems.find(
            (x) => x.application_id === siteFilter.applicationId,
          )
          return s ? siteLabel(s) : siteFilter.applicationId
        })()
      : undefined

  const treeData = useMemo(
    () => buildDirectoryTree(directoryTreeQuery.data ?? []),
    [directoryTreeQuery.data],
  )
  const siteKey =
    siteFilter.applicationId ?? (siteFilter.unassigned ? 'unassigned' : 'all')

  const siteItemStyle = (active: boolean): CSSProperties => ({
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    gap: 8,
    padding: '6px 8px',
    cursor: 'pointer',
    borderRadius: token.borderRadius,
    background: active ? token.colorPrimaryBg : undefined,
  })

  const countBadge = (count: number) => (
    <Badge
      count={count}
      size="small"
      showZero
      style={{
        backgroundColor: token.colorFillSecondary,
        color: token.colorText,
      }}
    />
  )

  const columns: ColumnsType<ApiEndpointItem> = [
    { title: '方法', dataIndex: 'http_method', width: 90 },
    {
      title: '路径模板',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '目录',
      dataIndex: 'directory_path',
      width: 160,
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: '站点',
      dataIndex: 'application_domain',
      width: 170,
      ellipsis: true,
      render: (v: string, record) =>
        v || record.application_name ? (
          <Tooltip
            title={
              v && record.application_name && v !== record.application_name
                ? record.application_name
                : undefined
            }
          >
            <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
              {v || record.application_name}
            </Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">未归属</Typography.Text>
        ),
    },
    {
      title: '置信度',
      dataIndex: 'api_confidence',
      width: 90,
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '资产状态',
      dataIndex: 'asset_status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={ENDPOINT_STATUS_META} />,
    },
    {
      title: '学习状态',
      dataIndex: 'learning_status',
      width: 100,
      render: (v: string) => (
        <StatusTag value={v} map={API_LEARNING_STATUS_META} />
      ),
    },
    {
      title: '价值',
      dataIndex: 'asset_value',
      width: 90,
      render: (v: string | undefined, record) => {
        if (!v) return <Typography.Text type="secondary">-</Typography.Text>
        const tag = <StatusTag value={v} map={ASSET_VALUE_META} />
        const explain = record.asset_value_explain
        if (!explain || !explain.dimensions || explain.dimensions.length === 0)
          return tag
        return (
          <Tooltip
            title={
              <div>
                <div style={{ marginBottom: 4 }}>
                  总分 {explain.total}/{explain.max_total}
                </div>
                {explain.dimensions.map((d) => (
                  <div key={d.name}>
                    {ASSET_VALUE_DIMENSION_LABELS[d.name] ?? d.name}：{d.score}/
                    {d.max}（{apiAssetValueReasonLabel(d.reason)}）
                  </div>
                ))}
              </div>
            }
          >
            <span>{tag}</span>
          </Tooltip>
        )
      },
    },
    {
      title: '标签',
      dataIndex: 'tags',
      width: 180,
      render: (tags: string[] | undefined) => {
        const items = tags ?? []
        if (items.length === 0)
          return <Typography.Text type="secondary">-</Typography.Text>
        const shown = items.slice(0, 2)
        return (
          <Space size={4} wrap>
            {shown.map((t) => (
              <Tag
                key={t}
                style={{
                  marginInlineEnd: 0,
                  maxWidth: 120,
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {t}
              </Tag>
            ))}
            {items.length > shown.length && (
              <Tooltip title={items.join('、')}>
                <Typography.Text type="secondary">
                  +{items.length - shown.length}
                </Typography.Text>
              </Tooltip>
            )}
          </Space>
        )
      },
    },
    { title: '命中', dataIndex: 'hit_count', width: 80 },
    {
      title: '最近访问',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 320,
      fixed: 'right',
      render: (_, record) => {
        const showConfirm = canConfirm && record.asset_status === 'DISCOVERED'
        const showIgnore =
          canIgnore &&
          record.asset_status !== 'IGNORED' &&
          record.asset_status !== 'DEPRECATED'
        // 生命周期：仅 DISCOVERED/CONFIRMED 可标记下线，仅 DEPRECATED/ZOMBIE 可恢复（与服务端状态机一致）
        const showDeprecate =
          canEdit &&
          (record.asset_status === 'DISCOVERED' ||
            record.asset_status === 'CONFIRMED')
        const showRestore =
          canEdit &&
          (record.asset_status === 'DEPRECATED' ||
            record.asset_status === 'ZOMBIE')
        return (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => setDetail(record)}>
              详情
            </Button>
            {showConfirm ? (
              <Button
                type="link"
                size="small"
                onClick={() => confirmEndpoint(record)}
              >
                确认
              </Button>
            ) : null}
            {canMerge ? (
              <Button
                type="link"
                size="small"
                onClick={() => openMerge(record)}
              >
                合并
              </Button>
            ) : null}
            {canSplit ? (
              <Button
                type="link"
                size="small"
                onClick={() => openSplit(record)}
              >
                拆分
              </Button>
            ) : null}
            {showDeprecate ? (
              <Button
                type="link"
                size="small"
                onClick={() => deprecateEndpoint(record)}
              >
                下线
              </Button>
            ) : null}
            {showRestore ? (
              <Button
                type="link"
                size="small"
                onClick={() => restoreEndpoint(record)}
              >
                恢复
              </Button>
            ) : null}
            {showIgnore ? (
              <Button
                type="link"
                size="small"
                danger
                onClick={() => ignoreEndpoint(record)}
              >
                忽略
              </Button>
            ) : null}
          </Space>
        )
      },
    },
  ]

  return (
    <div style={{ display: 'flex', gap: 16, alignItems: 'flex-start' }}>
      <div style={{ width: 264, flexShrink: 0 }}>
        <Card title="站点" styles={{ body: { padding: 8 } }}>
          <div
            role="button"
            tabIndex={0}
            style={siteItemStyle(
              !siteFilter.applicationId && !siteFilter.unassigned,
            )}
            onClick={() => selectSite({})}
          >
            <span>全部</span>
            {countBadge(totalCount)}
          </div>
          <div
            role="button"
            tabIndex={0}
            style={siteItemStyle(Boolean(siteFilter.unassigned))}
            onClick={() => selectSite({ unassigned: true })}
          >
            <span>未归属</span>
            {countBadge(unassignedCount)}
          </div>
          {siteItems.map((s) => (
            <div
              key={s.application_id}
              role="button"
              tabIndex={0}
              style={siteItemStyle(
                siteFilter.applicationId === s.application_id,
              )}
              onClick={() => selectSite({ applicationId: s.application_id })}
            >
              <Typography.Text
                ellipsis
                style={{ flex: 1 }}
                title={s.application_name}
              >
                {siteLabel(s)}
              </Typography.Text>
              {countBadge(s.endpoint_count)}
            </div>
          ))}
          <Divider style={{ margin: '8px 0' }} />
          <Typography.Text
            type="secondary"
            style={{ display: 'block', padding: '0 8px 4px' }}
          >
            目录
          </Typography.Text>
          {treeData.length > 0 ? (
            <Tree
              key={siteKey}
              blockNode
              defaultExpandAll
              selectedKeys={directoryPath ? [directoryPath] : []}
              treeData={treeData}
              onSelect={(keys) => {
                setDirectoryPath(keys.length > 0 ? String(keys[0]) : undefined)
                setPage(1)
              }}
            />
          ) : directoryTreeQuery.isLoading ? null : (
            <Typography.Text type="secondary" style={{ padding: '0 8px' }}>
              暂无目录
            </Typography.Text>
          )}
        </Card>
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <Card title="API 接口资产">
          <Typography.Paragraph type="secondary">
            路径自动归一化（如 /users/123 →
            /users/&#123;id&#125;），接口由网关自动发现上报。确认后进入正式资产，可勾选批量启动学习或在确认时自动启动学习；学习模型见「API
            模型版本」。
          </Typography.Paragraph>
          <QueryErrorAlert error={listQuery.error} />
          {currentSiteName !== undefined || directoryPath ? (
            <Space style={{ marginBottom: 16 }} wrap>
              {currentSiteName !== undefined ? (
                <Tag closable onClose={() => selectSite({})}>
                  站点：{currentSiteName}
                </Tag>
              ) : null}
              {directoryPath ? (
                <Tag closable onClose={clearDirectory}>
                  目录：{directoryPath}
                </Tag>
              ) : null}
            </Space>
          ) : null}
          <Space style={{ marginBottom: 16 }} wrap>
            <Select
              placeholder="资产状态"
              allowClear
              style={{ width: 140 }}
              value={assetStatus}
              options={Object.entries(ENDPOINT_STATUS_META).map(
                ([value, meta]) => ({
                  value,
                  label: meta.label,
                }),
              )}
              onChange={(v) => {
                setAssetStatus(v)
                setPage(1)
              }}
            />
            <Select
              placeholder="学习状态"
              allowClear
              style={{ width: 140 }}
              value={learningStatus}
              options={Object.entries(API_LEARNING_STATUS_META).map(
                ([value, meta]) => ({
                  value,
                  label: meta.label,
                }),
              )}
              onChange={(v) => {
                setLearningStatus(v)
                setPage(1)
              }}
            />
            <Input.Search
              placeholder="路径 / 接口键"
              allowClear
              style={{ width: 220 }}
              onSearch={(v) => {
                setKeyword(v || undefined)
                setPage(1)
              }}
            />
            <Button onClick={() => setFilterModalOpen(true)}>
              发现过滤规则
            </Button>
            {canIgnore ? (
              <Button onClick={() => setCleanupModalOpen(true)}>
                清理静态/非API噪声
              </Button>
            ) : null}
            {canExport ? (
              <ExportDropdown
                label="导出清单"
                selectedCount={selectedCount}
                onClearSelection={clearSelection}
                onExportSelected={() =>
                  window.open(
                    apiEndpointsApi.listExportUrl({ ids: selectedIds.join(',') }),
                    '_blank',
                  )
                }
                onExportFiltered={() =>
                  window.open(
                    apiEndpointsApi.listExportUrl({
                      asset_status: assetStatus,
                      learning_status: learningStatus,
                      keyword,
                      application_id: siteFilter.applicationId,
                      unassigned: siteFilter.unassigned,
                      directory_path: directoryPath,
                    }),
                    '_blank',
                  )
                }
                onExportAll={() => window.open(apiEndpointsApi.listExportUrl({}), '_blank')}
              />
            ) : null}
          </Space>
          {selectedCount > 0 && (canConfirm || canIgnore || canLearnStart) ? (
            <Space
              style={{
                marginBottom: 12,
                padding: '6px 12px',
                borderRadius: token.borderRadius,
                background: token.colorFillAlter,
                width: '100%',
                justifyContent: 'space-between',
              }}
              wrap
            >
              <Typography.Text>
                已选择 <Typography.Text strong>{selectedCount}</Typography.Text> 个接口
              </Typography.Text>
              <Space>
                {canConfirm ? (
                  <Button
                    size="small"
                    type="primary"
                    loading={
                      confirmEndpointsMut.isPending &&
                      confirmDialog?.mode === 'batch'
                    }
                    onClick={confirmBatchSelected}
                  >
                    批量确认
                  </Button>
                ) : null}
                {canLearnStart ? (
                  <Button
                    size="small"
                    loading={learningStartBatchMut.isPending}
                    onClick={openBatchLearn}
                  >
                    批量启动学习
                  </Button>
                ) : null}
                {canIgnore ? (
                  <Button
                    size="small"
                    danger
                    loading={ignoreBatchMut.isPending}
                    onClick={ignoreBatchSelected}
                  >
                    批量忽略
                  </Button>
                ) : null}
                <Button size="small" onClick={clearSelection}>
                  取消选择
                </Button>
              </Space>
            </Space>
          ) : null}
          <SmartTable<ApiEndpointItem>
            storageKey="api-endpoints"
            rowKey="id"
            rowSelection={rowSelection}
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items ?? []}
            scroll={{ x: 1600 }}
            onRow={(record) => ({
              onDoubleClick: () => setDetail(record),
              style: { cursor: 'pointer' },
            })}
            pagination={{
              current: page,
              pageSize,
              total: listQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setPage(p)
                setPageSize(ps)
              },
            }}
          />
        </Card>
      </div>
      <EndpointDetailDrawer endpoint={detail} onClose={() => setDetail(null)} />
      <DiscoveryFilterModal
        open={filterModalOpen}
        canEdit={canEdit}
        onClose={() => setFilterModalOpen(false)}
      />
      <CleanupNoiseModal
        open={cleanupModalOpen}
        applicationId={siteFilter.applicationId}
        applicationName={currentSiteName}
        onClose={() => setCleanupModalOpen(false)}
      />

      <Modal
        title={confirmDialog?.mode === 'batch' ? '批量确认接口' : '操作确认'}
        open={confirmDialog !== null}
        onCancel={() => setConfirmDialog(null)}
        onOk={handleConfirmOk}
        okText="确定"
        okButtonProps={{ loading: confirmEndpointsMut.isPending }}
        cancelText="取消"
        destroyOnHidden
      >
        <Space orientation="vertical" size={12} style={{ width: '100%' }}>
          <Typography.Text>
            {confirmDialog?.mode === 'batch'
              ? `确定将已勾选的 ${confirmDialog.ids.length} 个接口确认为正式 API 资产吗？确认后进入正式资产管理。`
              : `确定将接口「${confirmDialog?.label ?? '-'}」确认为正式 API 资产吗？确认后进入正式资产管理。`}
          </Typography.Text>
          {canLearnStart ? (
            <>
              <Checkbox
                checked={confirmAutoStart}
                onChange={(e) => {
                  setConfirmAutoStartTouched(true)
                  setConfirmAutoStart(e.target.checked)
                }}
              >
                确认后自动启动模型学习
              </Checkbox>
              {confirmAutoStart ? (
                <Space orientation="vertical" size={6} style={{ width: '100%' }}>
                  <span>
                    样本目标：
                    <InputNumber
                      min={10}
                      max={100000}
                      precision={0}
                      value={confirmSampleTarget}
                      onChange={(v) =>
                        setConfirmSampleTarget(typeof v === 'number' ? v : null)
                      }
                    />
                  </span>
                  <Typography.Text type="secondary">
                    学习中或已完成学习的接口将自动跳过；有效样本达到目标后仅生成候选模型，仍需人工审核确认后才生效。
                  </Typography.Text>
                </Space>
              ) : null}
            </>
          ) : null}
        </Space>
      </Modal>

      <Modal
        title="批量启动学习"
        open={batchLearnOpen}
        onCancel={() => setBatchLearnOpen(false)}
        onOk={handleBatchLearnOk}
        okText="启动学习"
        okButtonProps={{ loading: learningStartBatchMut.isPending }}
        cancelText="取消"
        destroyOnHidden
      >
        <Space orientation="vertical" size={10} style={{ width: '100%' }}>
          <Typography.Text>
            确定为已勾选的 <Typography.Text strong>{selectedCount}</Typography.Text>{' '}
            个接口启动模型学习吗？
          </Typography.Text>
          <span>
            样本目标：
            <InputNumber
              min={10}
              max={100000}
              precision={0}
              value={batchSampleTarget}
              onChange={(v) =>
                setBatchSampleTarget(typeof v === 'number' ? v : null)
              }
            />
          </span>
          <Typography.Text type="secondary">
            已在学习中的接口将自动跳过；有效样本达到目标后自动完成学习并生成模型候选（候选仍需人工审核确认后才生效）。
          </Typography.Text>
        </Space>
      </Modal>

      <Modal
        title="合并接口"
        open={mergeSource !== null}
        onCancel={() => setMergeSource(null)}
        onOk={handleMergeOk}
        okText="合并"
        okButtonProps={{
          danger: true,
          loading: mergeMut.isPending,
          disabled: !mergeTargetId,
        }}
        cancelText="取消"
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          将待并入接口合并进保留方：命中数累加、历史接口键归档为别名，待并入接口随后删除。该操作不可撤销。
        </Typography.Paragraph>
        <Typography.Paragraph>
          保留方：
          <Typography.Text code>{mergeSource?.endpoint_key}</Typography.Text>
        </Typography.Paragraph>
        <Select
          placeholder="选择待并入的接口"
          showSearch
          optionFilterProp="label"
          style={{ width: '100%' }}
          loading={mergeOptionsQuery.isLoading}
          value={mergeTargetId}
          options={(mergeOptionsQuery.data?.items ?? [])
            .filter((e) => e.id !== mergeSource?.id)
            .map((e) => ({ value: e.id, label: e.endpoint_key }))}
          onChange={(v) => setMergeTargetId(v)}
        />
      </Modal>

      <Modal
        title="拆分接口"
        open={splitSource !== null}
        onCancel={() => setSplitSource(null)}
        onOk={handleSplitOk}
        okText="拆分"
        okButtonProps={{ loading: splitMut.isPending }}
        cancelText="取消"
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          按路径段从原接口拆出新接口（每行一个路径，服务端自动归一化；新接口继承方法与站点归属，状态为已发现）。
        </Typography.Paragraph>
        <Typography.Paragraph>
          原接口：
          <Typography.Text code>{splitSource?.endpoint_key}</Typography.Text>
        </Typography.Paragraph>
        <Input.TextArea
          rows={4}
          style={{ fontFamily: 'monospace' }}
          placeholder={'/v1/users/{id}\n/v1/users/{id}/orders'}
          value={splitPaths}
          onChange={(e) => setSplitPaths(e.target.value)}
        />
      </Modal>
    </div>
  )
}
