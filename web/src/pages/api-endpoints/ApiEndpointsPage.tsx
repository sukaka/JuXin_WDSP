import { useMemo, useState, type CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Badge,
  Button,
  Card,
  Divider,
  Input,
  Select,
  Space,
  Tag,
  Tree,
  Typography,
  theme,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_ENDPOINT_STATUS_META, API_LEARNING_STATUS_META, buildDirectoryTree } from '../../utils/stage8'

/** 站点过滤：applicationId 与 unassigned 二选一；皆空表示全部 */
interface SiteFilter {
  applicationId?: string
  unassigned?: boolean
}

/** API 端点资产（WDSP / 阶段8）：发现由网关自动上报，页面负责确认与忽略 */
export default function ApiEndpointsPage() {
  const { message, modal } = AntdApp.useApp()
  const { token } = theme.useToken()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const canIgnore = hasPermission(permissions, 'api_asset.ignore')

  const [assetStatus, setAssetStatus] = useState<string | undefined>()
  const [learningStatus, setLearningStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [siteFilter, setSiteFilter] = useState<SiteFilter>({})
  const [directoryPath, setDirectoryPath] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const siteSummaryQuery = useQuery({
    queryKey: ['api-endpoints', 'site-summary'],
    queryFn: () => apiEndpointsApi.siteSummary(),
  })

  const directoryTreeQuery = useQuery({
    queryKey: ['api-endpoints', 'directory-tree', siteFilter.applicationId, siteFilter.unassigned],
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
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '确认失败'),
  })

  const ignoreMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.ignore(id),
    onSuccess: (r) => {
      message.success(r.message || '已忽略')
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '忽略失败'),
  })

  /** 行内操作统一二次确认 */
  const confirmEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定将端点「${record.http_method} ${record.normalized_path}」确认为正式接口资产吗？确认后进入正式资产管理。`,
      onOk: () => confirmMut.mutate(record.id),
    })
  }

  const ignoreEndpoint = (record: ApiEndpointItem) => {
    modal.confirm({
      title: '操作确认',
      content: `确定忽略端点「${record.http_method} ${record.normalized_path}」吗？忽略后标记为已忽略，不再进入正式资产管理。`,
      onOk: () => ignoreMut.mutate(record.id),
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
  const totalCount = siteItems.reduce((sum, s) => sum + s.endpoint_count, 0) + unassignedCount
  const currentSiteName = siteFilter.unassigned
    ? '未归属'
    : siteFilter.applicationId
      ? (siteItems.find((s) => s.application_id === siteFilter.applicationId)?.application_name ??
        siteFilter.applicationId)
      : undefined

  const treeData = useMemo(() => buildDirectoryTree(directoryTreeQuery.data ?? []), [directoryTreeQuery.data])
  const siteKey = siteFilter.applicationId ?? (siteFilter.unassigned ? 'unassigned' : 'all')

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
      style={{ backgroundColor: token.colorFillSecondary, color: token.colorText }}
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
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '站点',
      dataIndex: 'application_name',
      width: 140,
      ellipsis: true,
      render: (v: string) => (v ? v : <Typography.Text type="secondary">未归属</Typography.Text>),
    },
    {
      title: '置信度',
      dataIndex: 'api_confidence',
      width: 90,
      align: 'right',
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '资产状态',
      dataIndex: 'asset_status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_ENDPOINT_STATUS_META} />,
    },
    {
      title: '学习状态',
      dataIndex: 'learning_status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_LEARNING_STATUS_META} />,
    },
    { title: '命中', dataIndex: 'hit_count', width: 80, align: 'right' },
    {
      title: '最近访问',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 130,
      fixed: 'right',
      render: (_, record) => {
        const showConfirm = canConfirm && record.asset_status === 'DISCOVERED'
        const showIgnore = canIgnore && record.asset_status !== 'IGNORED' && record.asset_status !== 'DEPRECATED'
        if (!showConfirm && !showIgnore) return null
        return (
          <Space size={0}>
            {showConfirm ? (
              <Button type="link" size="small" onClick={() => confirmEndpoint(record)}>
                确认
              </Button>
            ) : null}
            {showIgnore ? (
              <Button type="link" size="small" danger onClick={() => ignoreEndpoint(record)}>
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
            style={siteItemStyle(!siteFilter.applicationId && !siteFilter.unassigned)}
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
              style={siteItemStyle(siteFilter.applicationId === s.application_id)}
              onClick={() => selectSite({ applicationId: s.application_id })}
            >
              <Typography.Text ellipsis style={{ flex: 1 }}>
                {s.application_name}
              </Typography.Text>
              {countBadge(s.endpoint_count)}
            </div>
          ))}
          <Divider style={{ margin: '8px 0' }} />
          <Typography.Text type="secondary" style={{ display: 'block', padding: '0 8px 4px' }}>
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
        <Card title="接口端点资产">
          <Typography.Paragraph type="secondary">
            路径自动归一化（如 /users/123 → /users/&#123;id&#125;），端点由网关自动发现上报。确认后进入正式资产；学习模型见「接口
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
              options={Object.entries(API_ENDPOINT_STATUS_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
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
              options={Object.entries(API_LEARNING_STATUS_META).map(([value, meta]) => ({
                value,
                label: meta.label,
              }))}
              onChange={(v) => {
                setLearningStatus(v)
                setPage(1)
              }}
            />
            <Input.Search
              placeholder="路径 / 端点键"
              allowClear
              style={{ width: 220 }}
              onSearch={(v) => {
                setKeyword(v || undefined)
                setPage(1)
              }}
            />
          </Space>
          <SmartTable<ApiEndpointItem>
            storageKey="api-endpoints"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items ?? []}
            scroll={{ x: 1500 }}
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
    </div>
  )
}
