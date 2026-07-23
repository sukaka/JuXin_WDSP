import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Input, Select, Space, Table, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_ENDPOINT_STATUS_META, API_LEARNING_STATUS_META } from '../../utils/stage8'

/** API 端点资产（WDSP / 阶段8）：发现由网关自动上报，页面负责确认与忽略 */
export default function ApiEndpointsPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const canIgnore = hasPermission(permissions, 'api_asset.ignore')

  const [assetStatus, setAssetStatus] = useState<string | undefined>()
  const [learningStatus, setLearningStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const listQuery = useQuery({
    queryKey: ['api-endpoints', assetStatus, learningStatus, keyword, page, pageSize],
    queryFn: () =>
      apiEndpointsApi.list({
        asset_status: assetStatus,
        learning_status: learningStatus,
        keyword,
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

  const columns: ColumnsType<ApiEndpointItem> = [
    { title: '方法', dataIndex: 'http_method', width: 90 },
    {
      title: '路径模板',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
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
    <Card title="接口端点资产">
      <Typography.Paragraph type="secondary">
        路径自动归一化（如 /users/123 → /users/&#123;id&#125;），端点由网关自动发现上报。确认后进入正式资产；学习模型见「接口
        模型版本」。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
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
      <Table<ApiEndpointItem>
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
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
  )
}
