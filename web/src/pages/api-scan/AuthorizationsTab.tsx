import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiScanApi, type ApiScanAuthorization } from '../../api/apiScan'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { authorizationState, SCAN_PROBE_SET_META, splitProbeSets } from './meta'

/**
 * 扫描授权 Tab：按目标查看授权单，吊销（api_scan.execute）二次确认——吊销即停全部关联任务。
 */
export default function AuthorizationsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canExecute = hasPermission(permissions, 'api_scan.execute')

  const [targetId, setTargetId] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiScanAuthorization | null>(null)

  /** 目标选项（授权按目标维度查询） */
  const targetsQuery = useQuery({
    queryKey: ['api-scan-targets', 'options'],
    queryFn: () => apiScanApi.listTargets({ page: 1, page_size: 100 }),
  })
  const targetOptions = (targetsQuery.data?.items ?? []).map((t) => ({
    value: t.id,
    label: `${t.name}（${t.base_url}）`,
  }))

  const listQuery = useQuery({
    queryKey: ['api-scan-authorizations', targetId, page, pageSize],
    queryFn: () => apiScanApi.listAuthorizations(targetId as string, { page, page_size: pageSize }),
    enabled: targetId !== undefined,
  })

  const revokeMut = useMutation({
    mutationFn: (id: string) => apiScanApi.revokeAuthorization(id),
    onSuccess: (r) => {
      message.success(`授权已吊销，已联动停止 ${r.stopped_jobs} 个在跑任务`)
      void qc.invalidateQueries({ queryKey: ['api-scan-authorizations'] })
      // 吊销联动停任务：任务列表一并刷新
      void qc.invalidateQueries({ queryKey: ['api-scan-jobs'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '吊销失败'),
  })

  const confirmRevoke = (record: ApiScanAuthorization) => {
    modal.confirm({
      title: '吊销扫描授权',
      content: `确定吊销该授权吗？吊销立即生效：该授权下全部在跑任务将被联动停止，且不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => revokeMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiScanAuthorization> = [
    {
      title: '授权单',
      dataIndex: 'id',
      width: 110,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>#{v.slice(0, 8)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '状态',
      key: 'state',
      width: 100,
      render: (_, record) => {
        const s = authorizationState(record)
        return <Tag color={s.color}>{s.label}</Tag>
      },
    },
    {
      title: '白名单',
      dataIndex: 'allowlist',
      ellipsis: true,
      render: (v: string[]) =>
        v && v.length > 0 ? (
          <Tooltip title={v.join('、')}>
            <Typography.Text>{v.length} 条</Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">未设置</Typography.Text>
        ),
    },
    {
      title: '时间窗',
      key: 'window',
      width: 230,
      render: (_, record) => {
        const { start, end } = record.time_window ?? {}
        if (!start && !end) return <Typography.Text type="secondary">不限</Typography.Text>
        return (
          <Typography.Text style={{ fontSize: 12 }}>
            {formatDateTime(start)} ~ {formatDateTime(end)}
          </Typography.Text>
        )
      },
    },
    { title: 'QPS', dataIndex: 'max_qps', width: 70 },
    { title: '并发', dataIndex: 'max_concurrency', width: 70 },
    {
      title: '探针集画像',
      dataIndex: 'test_profile',
      width: 200,
      ellipsis: true,
      render: (v: string) => {
        const sets = splitProbeSets(v)
        const labels = sets.map((s) => SCAN_PROBE_SET_META[s] ?? s).join('、')
        return sets.length > 0 ? (
          <Tooltip title={labels}>
            <Typography.Text style={{ fontSize: 12 }}>{labels}</Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">默认全集</Typography.Text>
        )
      },
    },
    {
      title: '截止时间',
      dataIndex: 'expires_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(canExecute
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 90,
            fixed: 'right' as const,
            render: (_: unknown, record: ApiScanAuthorization) => {
              const active = authorizationState(record).active
              return (
                <Button
                  type="link"
                  size="small"
                  danger
                  disabled={!active}
                  onClick={() => confirmRevoke(record)}
                >
                  吊销
                </Button>
              )
            },
          },
        ]
      : []),
  ]

  return (
    <>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="选择扫描目标查看授权"
          showSearch
          optionFilterProp="label"
          style={{ width: 320 }}
          value={targetId}
          options={targetOptions}
          loading={targetsQuery.isLoading}
          onChange={(v) => {
            setTargetId(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiScanAuthorization>
        storageKey="api-scan-authorizations"
        rowKey="id"
        loading={targetId !== undefined && listQuery.isLoading}
        columns={columns}
        dataSource={targetId !== undefined ? (listQuery.data?.items ?? []) : []}
        locale={{ emptyText: targetId === undefined ? '请先选择扫描目标' : '暂无授权记录' }}
        scroll={{ x: 1300 }}
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
        title="扫描授权详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
