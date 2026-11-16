import { useMemo, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Badge,
  Button,
  Card,
  Divider,
  Input,
  Modal,
  Select,
  Space,
  Tag,
  Tooltip,
  Tree,
  Typography,
  theme,
} from 'antd'
import { DownloadOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  API_ENDPOINT_STATUS_META,
  API_LEARNING_STATUS_META,
  apiAssetValueReasonLabel,
  buildDirectoryTree,
} from '../../utils/stage8'
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

/** 资产价值评分九维中文名（asset_value_explain.dimensions[].name） */
const ASSET_VALUE_DIMENSION_LABELS: Record<string, string> = {
  business_sensitivity: '业务敏感度',
  data_sensitivity: '数据敏感度',
  internet_exposure: '公网暴露',
  privilege: '权限等级',
  write_capability: '写能力',
  admin_capability: '管理能力',
  transaction_capability: '交易能力',
  dependency_degree: '依赖度',
  traffic_scale: '流量规模',
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
  const canMerge = hasPermission(permissions, 'api_asset.merge')
  const canSplit = hasPermission(permissions, 'api_asset.split')
  const canEdit = hasPermission(permissions, 'api_asset.edit')
  const canExport = hasPermission(permissions, 'api_asset.export')

  const [assetStatus, setAssetStatus] = useState<string | undefined>()
  const [learningStatus, setLearningStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [siteFilter, setSiteFilter] = useState<SiteFilter>({})
  const [directoryPath, setDirectoryPath] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detail, setDetail] = useState<ApiEndpointItem | null>(null)
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

  const confirmMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.confirm([id]),
    onSuccess: (r) => {
      if (r.failed && r.failed.length > 0) {
        message.error(r.failed[0].reason || '确认失败')
      } else {
        message.success('已确认')
      }
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '确认失败'),
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
  const confirmEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定将接口「${record.http_method} ${record.normalized_path}」确认为正式 API 资产吗？确认后进入正式资产管理。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const ignoreEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定忽略接口「${record.http_method} ${record.normalized_path}」吗？忽略后标记为已忽略，不再进入正式资产管理。`,
      onOk: () => ignoreMut.mutate(record.id),
    })
  }

  const deprecateEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '标记下线',
      content: `确定将接口「${record.http_method} ${record.normalized_path}」标记下线（DEPRECATED）吗？下线后若观察窗口内仍有流量将自动转为僵尸态。`,
      onOk: () => deprecateMut.mutate(record.id),
    })
  }

  const restoreEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '恢复接口',
      content: `确定将接口「${record.http_method} ${record.normalized_path}」恢复为已确认（CONFIRMED）吗？恢复后重新进入正式资产管理。`,
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
            /users/&#123;id&#125;），接口由网关自动发现上报。确认后进入正式资产；学习模型见「API
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
            {canExport ? (
              <Button
                icon={<DownloadOutlined />}
                onClick={() =>
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
              >
                导出清单
              </Button>
            ) : null}
          </Space>
          <SmartTable<ApiEndpointItem>
            storageKey="api-endpoints"
            rowKey="id"
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
