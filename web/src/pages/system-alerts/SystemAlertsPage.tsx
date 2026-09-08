import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Input,
  Select,
  Space,
  Timeline,
  Typography,
} from 'antd'
import SmartTable from '../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { systemAlertsApi } from '../../api/systemAlerts'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasAnyPermission } from '../../utils/permission'
import { ALERT_SEVERITY_META, ALERT_STATUS_META, ALERT_TYPE_META, COMPONENT_NAME_META } from '../../utils/stage6'
import type { SystemAlertItem } from '../../types'

interface Filters {
  status?: string
  severity?: string
  alert_type?: string
  component?: string
}

/** 系统告警：列表筛选 + 确认/解决/忽略/备注（按权限）+ 详情抽屉备注时间线 */
export default function SystemAlertsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  // SYS：全部告警操作；SEC：安全类告警确认；AUD：只读
  const canAcknowledge = hasAnyPermission(permissions, ['system_alerts.acknowledge', 'system_alerts.acknowledge_security'])
  const canResolve = hasAnyPermission(permissions, ['system_alerts.resolve'])

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailId, setDetailId] = useState<string | null>(null)
  const [noteText, setNoteText] = useState('')

  const listQuery = useQuery({
    queryKey: ['system-alerts', filters, page, pageSize],
    queryFn: () => systemAlertsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['system-alerts', 'detail', detailId],
    queryFn: () => systemAlertsApi.get(detailId!),
    enabled: detailId !== null,
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['system-alerts'] })
  }
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const actionMutation = useMutation({
    mutationFn: ({ id, action }: { id: string; action: 'acknowledge' | 'resolve' | 'ignore' }) => {
      if (action === 'acknowledge') return systemAlertsApi.acknowledge(id)
      if (action === 'resolve') return systemAlertsApi.resolve(id)
      return systemAlertsApi.ignore(id)
    },
    onSuccess: (_d, vars) => {
      message.success(vars.action === 'acknowledge' ? '告警已确认' : vars.action === 'resolve' ? '告警已解决' : '告警已忽略')
      invalidate()
    },
    onError,
  })

  const noteMutation = useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) => systemAlertsApi.addNote(id, note),
    onSuccess: () => {
      message.success('备注已添加')
      setNoteText('')
      invalidate()
    },
    onError,
  })

  const confirmAction = (record: SystemAlertItem, action: 'acknowledge' | 'resolve' | 'ignore') => {
    const textMap = {
      acknowledge: `确定确认告警「${record.title}」吗？确认后表示已知悉该告警。`,
      resolve: `确定将告警「${record.title}」标记为已解决吗？请确认对应问题已处置完成。`,
      ignore: `确定忽略告警「${record.title}」吗？忽略后该告警不再出现在未处理列表。`,
    }
    modal.confirm({
      title: '操作确认',
      content: textMap[action],
      onOk: () => actionMutation.mutate({ id: record.id, action }),
    })
  }

  const columns: ColumnsType<SystemAlertItem> = [
    {
      title: '等级',
      dataIndex: 'severity',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ALERT_SEVERITY_META} />,
    },
    {
      title: '类型',
      dataIndex: 'alert_type',
      width: 150,
      render: (v: string) => <StatusTag value={v} map={ALERT_TYPE_META} />,
    },
    {
      title: '组件',
      dataIndex: 'component',
      width: 120,
      render: (v: string) => COMPONENT_NAME_META[v] ?? v,
    },
    { title: '标题', dataIndex: 'title', ellipsis: true },
    { title: '次数', dataIndex: 'occurrence_count', width: 70 },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={ALERT_STATUS_META} />,
    },
    {
      title: '最近发生',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {canAcknowledge && record.status === 'OPEN' && (
            <Button type="link" size="small" onClick={() => confirmAction(record, 'acknowledge')}>
              确认
            </Button>
          )}
          {canResolve && (record.status === 'OPEN' || record.status === 'ACKNOWLEDGED') && (
            <>
              <Button type="link" size="small" onClick={() => confirmAction(record, 'resolve')}>
                解决
              </Button>
              <Button type="link" size="small" onClick={() => confirmAction(record, 'ignore')}>
                忽略
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  const detail = detailQuery.data
  const alert = detail?.alert
  const notes = detail?.notes ?? []

  return (
    <Card title="系统告警">
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="等级"
          allowClear
          style={{ width: 110 }}
          options={Object.entries(ALERT_SEVERITY_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, severity: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="类型"
          allowClear
          showSearch
          style={{ width: 180 }}
          options={Object.entries(ALERT_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, alert_type: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="组件"
          allowClear
          style={{ width: 140 }}
          options={Object.entries(COMPONENT_NAME_META).map(([value, label]) => ({ value, label }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, component: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 110 }}
          options={Object.entries(ALERT_STATUS_META).map(([value, meta]) => ({ value, label: meta.label }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载系统告警失败" />
      ) : (
        <SmartTable<SystemAlertItem>
          storageKey="system-alerts"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
            style: { cursor: 'pointer' },
          })}
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
      )}

      <Drawer
        title="告警详情"
        open={detailId !== null}
        onClose={() => {
          setDetailId(null)
          setNoteText('')
        }}
        width={560}
        destroyOnHidden
      >
        {detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载告警详情失败" />
        ) : alert ? (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Descriptions column={1} size="small" bordered
              items={[
                { key: 'severity', label: '等级', children: <StatusTag value={alert.severity} map={ALERT_SEVERITY_META} /> },
                { key: 'type', label: '类型', children: <StatusTag value={alert.alert_type} map={ALERT_TYPE_META} /> },
                { key: 'component', label: '组件', children: COMPONENT_NAME_META[alert.component] ?? alert.component },
                { key: 'title', label: '标题', children: alert.title },
                { key: 'message', label: '详情', children: alert.message || '-' },
                { key: 'count', label: '发生次数', children: alert.occurrence_count },
                { key: 'status', label: '状态', children: <StatusTag value={alert.status} map={ALERT_STATUS_META} /> },
                { key: 'first', label: '首次发生', children: formatDateTime(alert.first_seen_at) },
                { key: 'last', label: '最近发生', children: formatDateTime(alert.last_seen_at) },
                { key: 'ack', label: '确认人/时间', children: alert.acknowledged_by ? `${alert.acknowledged_by} / ${formatDateTime(alert.acknowledged_at)}` : '-' },
                { key: 'resolve', label: '解决人/时间', children: alert.resolved_by ? `${alert.resolved_by} / ${formatDateTime(alert.resolved_at)}` : '-' },
              ]}
            />
            <Typography.Title level={5} style={{ margin: 0 }}>
              备注时间线
            </Typography.Title>
            {notes.length === 0 ? (
              <Typography.Text type="secondary">暂无备注</Typography.Text>
            ) : (
              <Timeline
                items={notes.map((n) => ({
                  children: (
                    <>
                      <Typography.Text strong>{n.username}</Typography.Text>
                      <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                        {formatDateTime(n.created_at)}
                      </Typography.Text>
                      <div>{n.note}</div>
                    </>
                  ),
                }))}
              />
            )}
            {(canAcknowledge || canResolve) && (
              <Space.Compact style={{ width: '100%' }}>
                <Input
                  placeholder="添加处置备注"
                  value={noteText}
                  maxLength={500}
                  onChange={(e) => setNoteText(e.target.value)}
                />
                <Button
                  type="primary"
                  disabled={!noteText.trim()}
                  loading={noteMutation.isPending}
                  onClick={() => detailId && noteMutation.mutate({ id: detailId, note: noteText.trim() })}
                >
                  添加
                </Button>
              </Space.Compact>
            )}
          </Space>
        ) : (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        )}
      </Drawer>
    </Card>
  )
}
