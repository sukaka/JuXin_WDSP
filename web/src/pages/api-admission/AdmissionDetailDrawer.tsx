import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Drawer,
  Popconfirm,
  Space,
  Table,
  Tabs,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAdmissionApi } from '../../api/apiAdmission'
import { apiEndpointsApi, type ApiEndpointItem } from '../../api/apiAssets'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import type { ApiAdmissionDeniedItem, ApplicationItem } from '../../types'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'
import PublishHint from './PublishHint'

/** 资产状态展示映射（公共映射 + 本地补充 ZOMBIE 僵尸态，与 api-endpoints 页一致） */
const ENDPOINT_STATUS_META: Record<string, { color: string; label: string }> = {
  ...API_ENDPOINT_STATUS_META,
  ZOMBIE: { color: 'magenta', label: '僵尸' },
}

/** 确认/忽略复用 api-endpoints 页同一组接口与权限点；成功后失效相关查询并提示发布 */
function useEndpointActions() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['api-admission'] })
    void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
  }
  const confirmMut = useMutation({
    mutationFn: (ids: string[]) => apiEndpointsApi.confirm(ids),
    onSuccess: (r) => {
      if (r.failed && r.failed.length > 0) {
        message.error(r.failed[0].reason || '确认失败')
      } else {
        message.success({ content: <PublishHint prefix="已确认" />, duration: 6 })
      }
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '确认失败'),
  })
  const ignoreMut = useMutation({
    mutationFn: (id: string) => apiEndpointsApi.ignore(id),
    onSuccess: (r) => {
      message.success({ content: <PublishHint prefix={r.message || '已忽略'} />, duration: 6 })
      invalidate()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '忽略失败'),
  })
  return { confirmMut, ignoreMut }
}

/** 准入拦截 Tab：窗口内 PROTECT 被 403 的端点聚合（服务端分页）；行操作确认放行/忽略 */
function DeniedTab({ app, hitsWindowHours }: { app: ApplicationItem; hitsWindowHours: number }) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const canIgnore = hasPermission(permissions, 'api_asset.ignore')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const { confirmMut, ignoreMut } = useEndpointActions()

  const deniedQuery = useQuery({
    queryKey: ['api-admission', 'denied', app.id, hitsWindowHours, page, pageSize],
    queryFn: () =>
      apiAdmissionApi.denied({
        application_id: app.id,
        hits_window: hitsWindowHours,
        page,
        page_size: pageSize,
      }),
  })

  // 拦截项不含资产 id（冻结契约），按 endpoint_key 关联资产清单取得确认/忽略所需 id
  const endpointsQuery = useQuery({
    queryKey: ['api-admission', 'app-endpoint-keys', app.id],
    queryFn: () => apiEndpointsApi.list({ application_id: app.id, page: 1, page_size: 200 }),
  })
  const idByKey = useMemo(
    () => new Map((endpointsQuery.data?.items ?? []).map((e) => [e.endpoint_key, e.id])),
    [endpointsQuery.data],
  )

  const columns: ColumnsType<ApiAdmissionDeniedItem> = [
    { title: '方法', dataIndex: 'http_method', width: 70 },
    {
      title: '路径',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'asset_status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENDPOINT_STATUS_META} />,
    },
    { title: '拦截次数', dataIndex: 'denied_count', width: 90 },
    {
      title: '最近拦截',
      dataIndex: 'last_denied_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '样本 IP',
      dataIndex: 'sample_client_ips',
      width: 160,
      render: (ips: string[]) =>
        ips.length > 0 ? <Typography.Text code>{ips.join('、')}</Typography.Text> : '-',
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      render: (_, record) => {
        const id = idByKey.get(record.endpoint_key)
        if (!id) {
          return (
            <Tooltip title="未在资产清单匹配到该接口，请到 API 接口资产页处理">
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                待资产匹配
              </Typography.Text>
            </Tooltip>
          )
        }
        return (
          <Space size={0}>
            {canConfirm ? (
              <Popconfirm
                title="确认放行"
                description={`将「${record.endpoint_key}」转为已确认，发布后放行其访问。`}
                okText="确定"
                cancelText="取消"
                onConfirm={() => confirmMut.mutate([id])}
              >
                <Button type="link" size="small">
                  确认放行
                </Button>
              </Popconfirm>
            ) : null}
            {canIgnore ? (
              <Popconfirm
                title="忽略接口"
                description={`忽略「${record.endpoint_key}」？忽略后防护模式下将持续拒绝其访问。`}
                okText="确定"
                cancelText="取消"
                onConfirm={() => ignoreMut.mutate(id)}
              >
                <Button type="link" size="small" danger>
                  忽略
                </Button>
              </Popconfirm>
            ) : null}
          </Space>
        )
      },
    },
  ]

  return (
    <>
      <QueryErrorAlert error={deniedQuery.error} message="加载准入拦截列表失败" />
      <Table<ApiAdmissionDeniedItem>
        rowKey="endpoint_key"
        size="small"
        loading={deniedQuery.isLoading}
        columns={columns}
        dataSource={deniedQuery.data?.items ?? []}
        locale={{ emptyText: '窗口内无准入拦截记录' }}
        pagination={{
          current: page,
          pageSize,
          total: deniedQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />
    </>
  )
}

/** 未确认端点 Tab：资产接口 DISCOVERED 过滤（行自带 id，确认/忽略同资产页口径） */
function UnconfirmedTab({ app }: { app: ApplicationItem }) {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canConfirm = hasPermission(permissions, 'api_asset.confirm')
  const canIgnore = hasPermission(permissions, 'api_asset.ignore')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const { confirmMut, ignoreMut } = useEndpointActions()

  const listQuery = useQuery({
    queryKey: ['api-endpoints', 'admission-unconfirmed', app.id, page, pageSize],
    queryFn: () =>
      apiEndpointsApi.list({
        application_id: app.id,
        asset_status: 'DISCOVERED',
        page,
        page_size: pageSize,
      }),
  })

  const columns: ColumnsType<ApiEndpointItem> = [
    { title: '方法', dataIndex: 'http_method', width: 70 },
    {
      title: '路径模板',
      dataIndex: 'normalized_path',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '状态',
      dataIndex: 'asset_status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ENDPOINT_STATUS_META} />,
    },
    { title: '命中', dataIndex: 'hit_count', width: 80 },
    {
      title: '最近访问',
      dataIndex: 'last_seen_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      render: (_, record) => (
        <Space size={0}>
          {canConfirm ? (
            <Popconfirm
              title="确认放行"
              description={`将「${record.endpoint_key}」转为已确认，发布后放行其访问。`}
              okText="确定"
              cancelText="取消"
              onConfirm={() => confirmMut.mutate([record.id])}
            >
              <Button type="link" size="small">
                确认放行
              </Button>
            </Popconfirm>
          ) : null}
          {canIgnore ? (
            <Popconfirm
              title="忽略接口"
              description={`忽略「${record.endpoint_key}」？忽略后防护模式下将持续拒绝其访问。`}
              okText="确定"
              cancelText="取消"
              onConfirm={() => ignoreMut.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                忽略
              </Button>
            </Popconfirm>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <>
      <QueryErrorAlert error={listQuery.error} message="加载未确认端点失败" />
      <Table<ApiEndpointItem>
        rowKey="id"
        size="small"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        locale={{ emptyText: '暂无未确认端点' }}
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
    </>
  )
}

/** 准入详情抽屉（每应用）：准入拦截 + 未确认端点两个 Tab */
export default function AdmissionDetailDrawer({
  app,
  hitsWindowHours,
  onClose,
}: {
  app: ApplicationItem
  hitsWindowHours: number
  onClose: () => void
}) {
  return (
    <Drawer title={`准入详情：${app.name}（${app.code}）`} open onClose={onClose} width={1024}>
      <Tabs
        items={[
          {
            key: 'denied',
            label: '准入拦截',
            children: <DeniedTab app={app} hitsWindowHours={hitsWindowHours} />,
          },
          {
            key: 'unconfirmed',
            label: '未确认端点',
            children: <UnconfirmedTab app={app} />,
          },
        ]}
      />
    </Drawer>
  )
}
