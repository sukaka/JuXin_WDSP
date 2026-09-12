import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { App as AntdApp, Button, Card, Drawer, Select, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi } from '../../api/apiAssets'
import {
  apiRuntimePoliciesApi,
  API_RUNTIME_POLICY_STATUS_META,
  type ApiRuntimePolicy,
} from '../../api/apiRuntime'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'

/** 仅 ACTIVE / FAILED 状态的策略允许回滚（与 server 端 CreateRollbackDraft 语义一致） */
const canRollbackStatus = (s: string) => s === 'ACTIVE' || s === 'FAILED'

/**
 * 端点级运行时策略版本：FORMAL 模型冻结时编译产生，随整站发布联动生效；
 * 发布失败或生效异常时可回滚到上一已知良好版本（克隆其编译内容并重触发整站发布）。
 */
export default function ApiRuntimePoliciesPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRollback = hasPermission(permissions, 'api_model.activate')

  const [searchParams] = useSearchParams()
  /** 端点过滤：支持 ?endpoint_id= 预填（供其他页面跳转溯源） */
  const [endpointId, setEndpointId] = useState<string | undefined>(
    searchParams.get('endpoint_id') ?? undefined,
  )
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  /** 溯源抽屉：查看来源模型版本编译产生的全部策略 */
  const [traceSource, setTraceSource] = useState<ApiRuntimePolicy | null>(null)
  /** 双击行查看策略详情 */
  const [detailRecord, setDetailRecord] = useState<ApiRuntimePolicy | null>(null)

  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  const listQuery = useQuery({
    queryKey: ['api-runtime-policies', endpointId, status, page, pageSize],
    queryFn: () => apiRuntimePoliciesApi.list({ endpoint_id: endpointId, status, page, page_size: pageSize }),
  })

  /** 模型 → 策略溯源：与所选策略同源（同一模型版本编译）的全部策略 */
  const traceQuery = useQuery({
    queryKey: ['api-model-runtime', traceSource?.source_model_version_id],
    queryFn: () => apiRuntimePoliciesApi.listByModel(traceSource?.source_model_version_id as string),
    enabled: !!traceSource,
  })

  const rollbackMut = useMutation({
    mutationFn: (id: string) => apiRuntimePoliciesApi.rollback(id),
    onSuccess: (r) => {
      message.success(r.message || '已回退到上一已知良好版本并重新触发发布')
      void qc.invalidateQueries({ queryKey: ['api-runtime-policies'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '回滚失败'),
  })

  const confirmRollback = (record: ApiRuntimePolicy) => {
    modal.confirm({
      title: '回滚运行时策略',
      content: `确定将接口「${record.endpoint_key}」回退到上一已知良好版本吗？将克隆其编译内容创建新策略（当前为 ${record.runtime_version}），并重新触发整站发布。`,
      okText: '确认回滚',
      okType: 'danger',
      onOk: () => rollbackMut.mutateAsync(record.id),
    })
  }

  const columns: ColumnsType<ApiRuntimePolicy> = [
    {
      title: '接口键',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '运行时版本',
      dataIndex: 'runtime_version',
      width: 110,
      render: (v: string, record) => (
        <Tooltip title={`编译器 ${record.compiler_version}`}>
          <Typography.Text strong>{v}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string, record) =>
        record.error ? (
          <Tooltip title={`失败原因：${record.error}`}>
            <StatusTag value={v} map={API_RUNTIME_POLICY_STATUS_META} />
          </Tooltip>
        ) : (
          <StatusTag value={v} map={API_RUNTIME_POLICY_STATUS_META} />
        ),
    },
    {
      title: '内容哈希',
      dataIndex: 'content_hash',
      width: 150,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-'),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '生效时间',
      dataIndex: 'activated_at',
      width: 170,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setTraceSource(record)}>
            溯源
          </Button>
          {canRollback && canRollbackStatus(record.status) ? (
            <Button type="link" size="small" danger onClick={() => confirmRollback(record)}>
              回滚
            </Button>
          ) : null}
        </Space>
      ),
    },
  ]

  return (
    <Card title="API 运行时策略">
      <Typography.Paragraph type="secondary">
        正式模型冻结时编译为 API 级运行时策略，随整站发布联动生效；发布失败或生效异常时可回滚到上一已知良好版本。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="按接口过滤"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 320 }}
          loading={endpointsQuery.isLoading}
          value={endpointId}
          options={(endpointsQuery.data?.items ?? []).map((e) => ({
            value: e.id,
            label: e.endpoint_key,
          }))}
          onChange={(v) => {
            setEndpointId(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="按状态过滤"
          allowClear
          style={{ width: 160 }}
          value={status}
          options={Object.entries(API_RUNTIME_POLICY_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiRuntimePolicy>
        storageKey="api-runtime-policies"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1200 }}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
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

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="运行时策略详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <Drawer
        title={
          traceSource ? `模型 → 策略溯源（${traceSource.endpoint_key} ${traceSource.runtime_version}）` : '策略溯源'
        }
        open={traceSource !== null}
        onClose={() => setTraceSource(null)}
        width={560}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary">
          来源模型版本 <Typography.Text code>{traceSource?.source_model_version_id}</Typography.Text>
          编译产生的全部运行时策略：
        </Typography.Paragraph>
        {traceQuery.isLoading ? (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        ) : traceQuery.error ? (
          <Typography.Text type="danger">
            {traceQuery.error instanceof ApiError ? traceQuery.error.message : '获取溯源信息失败'}
          </Typography.Text>
        ) : (
          <Space direction="vertical" size={12} style={{ width: '100%' }}>
            {(traceQuery.data ?? []).map((p) => (
              <Card key={p.id} size="small">
                <Space direction="vertical" size={4}>
                  <Space size={8}>
                    <Typography.Text strong>{p.runtime_version}</Typography.Text>
                    <StatusTag value={p.status} map={API_RUNTIME_POLICY_STATUS_META} />
                    {p.id === traceSource?.id ? <Typography.Text type="secondary">（当前）</Typography.Text> : null}
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    内容哈希 <Typography.Text code>{p.content_hash.slice(0, 16)}…</Typography.Text>
                  </Typography.Text>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    创建时间 {formatDateTime(p.created_at)}
                  </Typography.Text>
                  {p.error ? (
                    <Typography.Text type="danger" style={{ fontSize: 12 }}>
                      失败原因：{p.error}
                    </Typography.Text>
                  ) : null}
                </Space>
              </Card>
            ))}
          </Space>
        )}
      </Drawer>
    </Card>
  )
}
