import { useMemo, useState } from 'react'
import { useQueries, useQuery } from '@tanstack/react-query'
import { Button, Card, Col, Descriptions, Row, Select, Space, Statistic, Table, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { applicationsApi } from '../../api/applications'
import {
  apiAuthzApi,
  type ApiAuthzConflict,
  type ApiAuthzEnforcementReadinessItem,
  type ApiAuthzNodeAck,
} from '../../api/apiAuthz'
import { ReadinessBadge } from '../../components/AuthzEnforcement'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import {
  ACK_STATE_META,
  ENFORCEMENT_VALUE_META,
  GAP_STATUS_META,
  RELATION_SOURCE_META,
} from '../../utils/authzEnforcement'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import ProtectWizard from './ProtectWizard'

function shortRef(value?: string | null) {
  if (!value) return '-'
  return value.length > 28 ? `${value.slice(0, 15)}…${value.slice(-8)}` : value
}

/**
 * 态势与实断资格（NG-AZ-04 §1.1 六要素聚合 Tab）：来源/有效期/冲突/最后同步/节点 ACK/当前能否实断。
 * 明细编辑仍归原 Tab/原页面；readiness 为服务端派生（前端只渲染），切换 PROTECT 走向导。
 */
export default function PostureTab() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.manage')
  const canReadApps = hasPermission(permissions, 'applications.read')
  const [applicationId, setApplicationId] = useState<string>()
  const [conflictPage, setConflictPage] = useState(1)
  const [wizardPreset, setWizardPreset] = useState<{ endpoint_id: string; object_segment: string } | null>(null)

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'api-authz-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canReadApps,
  })
  const applicationOptions = useMemo(
    () => (applicationsQuery.data?.items ?? []).map((app) => ({ value: app.id, label: `${app.name}（${app.code}）` })),
    [applicationsQuery.data],
  )

  // 六要素数据源：readiness（能否实断）/ 已确认关系（来源与有效期摘要）/ OPEN 冲突 / 节点 ACK / 权威来源状态（最后同步）
  const readinessQuery = useQuery({
    queryKey: ['api-authz', 'enforcement-readiness', applicationId],
    queryFn: () => apiAuthzApi.listEnforcementReadiness({ application_id: applicationId! }),
    enabled: Boolean(applicationId),
  })
  const relationsQuery = useQuery({
    queryKey: ['api-authz', 'posture-relations', applicationId],
    queryFn: () => apiAuthzApi.listObjectRelations({ application_id: applicationId!, status: 'CONFIRMED', page: 1, page_size: 100 }),
    enabled: Boolean(applicationId),
  })
  const conflictsQuery = useQuery({
    queryKey: ['api-authz', 'conflicts', applicationId, conflictPage],
    queryFn: () => apiAuthzApi.listAuthzConflicts({ application_id: applicationId, status: 'OPEN', page: conflictPage, page_size: 20 }),
    enabled: Boolean(applicationId),
  })
  const nodeAcksQuery = useQuery({
    queryKey: ['api-authz', 'node-acks'],
    queryFn: () => apiAuthzApi.listNodeAcks(),
    enabled: Boolean(applicationId),
  })
  const authoritiesQuery = useQuery({
    queryKey: ['api-authz', 'authorities'],
    queryFn: () => apiAuthzApi.listAuthzAuthorities(),
    enabled: Boolean(applicationId),
  })
  const authorityStatusQueries = useQueries({
    queries: (authoritiesQuery.data?.items ?? []).map((src) => ({
      queryKey: ['api-authz', 'authority-status', src.id],
      queryFn: () => apiAuthzApi.getAuthzAuthorityStatus(src.id),
    })),
  })

  const readinessItems = useMemo(() => readinessQuery.data?.items ?? [], [readinessQuery.data])
  const readyCount = readinessItems.filter((r) => r.readiness === 'READY').length
  const relations = useMemo(() => relationsQuery.data?.items ?? [], [relationsQuery.data])
  const sourceCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const rel of relations) counts[rel.source] = (counts[rel.source] ?? 0) + 1
    return counts
  }, [relations])
  const manualLastSync = useMemo(() => {
    let max = ''
    for (const rel of relations) {
      const t = rel.updated_at || rel.created_at
      if (t && t > max) max = t
    }
    return max
  }, [relations])
  const nodeAcks = useMemo(() => nodeAcksQuery.data?.items ?? [], [nodeAcksQuery.data])
  const freshCount = nodeAcks.filter((n) => n.ack_state === 'FRESH').length
  const authorityStatuses = authorityStatusQueries
    .map((q) => q.data)
    .filter((d): d is NonNullable<typeof d> => Boolean(d))

  const readinessColumns: ColumnsType<ApiAuthzEnforcementReadinessItem> = [
    { title: '接口', dataIndex: 'endpoint_key', ellipsis: true, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '对象段', dataIndex: 'object_segment', width: 130, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    {
      title: '当前 enforcement', dataIndex: 'enforcement', width: 150,
      render: (v: string) => <StatusTag value={v || 'OBSERVE'} map={ENFORCEMENT_VALUE_META} />,
    },
    {
      title: '能否实断', dataIndex: 'readiness', width: 170,
      render: (v: string, record) => <ReadinessBadge readiness={v} reasons={record.reasons} />,
    },
    {
      title: '阻塞因子', dataIndex: 'reasons', ellipsis: true,
      render: (v: string[]) => (v && v.length > 0 ? <Typography.Text type="secondary">{v[0]}{v.length > 1 ? ` 等 ${v.length} 项` : ''}</Typography.Text> : <Typography.Text type="secondary">无</Typography.Text>),
    },
    { title: '评估时间', dataIndex: 'checked_at', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 130, fixed: 'right',
      render: (_, record) =>
        canManage && record.enforcement !== 'PROTECT' ? (
          <Button type="link" size="small" onClick={() => setWizardPreset({ endpoint_id: record.endpoint_id, object_segment: record.object_segment })}>
            切换 PROTECT
          </Button>
        ) : null,
    },
  ]

  const conflictColumns: ColumnsType<ApiAuthzConflict> = [
    { title: '对象类型', dataIndex: 'object_type', width: 140 },
    { title: '对象引用', dataIndex: 'object_ref', width: 240, render: (v: string) => <Typography.Text code title={v}>{shortRef(v)}</Typography.Text> },
    { title: '租户域', dataIndex: 'tenant_domain', width: 140, render: (v: string) => v || '-' },
    { title: '涉及主体数', key: 'principals', width: 110, render: (_, record) => (record.principals ?? []).length },
    { title: '首次冲突时间', dataIndex: 'first_seen', width: 170, render: formatDateTime },
  ]

  const nodeAckColumns: ColumnsType<ApiAuthzNodeAck> = [
    { title: '节点', dataIndex: 'node_name', width: 160 },
    { title: '活性', dataIndex: 'status', width: 100, render: (v: string) => <Tag color={v === 'ACTIVE' ? 'green' : 'orange'}>{v}</Tag> },
    { title: 'ACK 状态', dataIndex: 'ack_state', width: 130, render: (v: string) => <StatusTag value={v} map={ACK_STATE_META} /> },
    {
      title: '陈旧秒数', dataIndex: 'staleness_seconds', width: 110,
      render: (v?: number | null) => (v === null || v === undefined ? <Typography.Text type="secondary">—</Typography.Text> : `${v}s`),
    },
    {
      title: '快照版本', dataIndex: 'authz_policy_version', width: 180, ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : <Typography.Text type="secondary">未上报</Typography.Text>),
    },
    {
      title: '水位', dataIndex: 'authz_watermark', width: 150,
      render: (v?: { manual_seq: number; sources: Record<string, number> } | null) =>
        v ? <Typography.Text code>manual={v.manual_seq} · sources={Object.keys(v.sources ?? {}).length}</Typography.Text> : <Typography.Text type="secondary">—</Typography.Text>,
    },
    {
      title: '租约', dataIndex: 'lease_seconds', width: 90,
      render: (v?: number | null) => (v === null || v === undefined ? <Typography.Text type="secondary">—</Typography.Text> : `${v}s`),
    },
    { title: '最近 ACK', dataIndex: 'last_ack_at', width: 170, render: (v?: string | null) => (v ? formatDateTime(v) : '—') },
  ]

  const noApplication = !applicationId
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space wrap>
        <Typography.Text strong>应用</Typography.Text>
        <Select
          showSearch
          optionFilterProp="label"
          value={applicationId}
          options={applicationOptions}
          loading={applicationsQuery.isLoading}
          placeholder="选择应用后查看态势与实断资格"
          style={{ width: 320 }}
          onChange={(value) => { setApplicationId(value); setConflictPage(1) }}
        />
      </Space>
      <QueryErrorAlert
        error={applicationsQuery.error ?? readinessQuery.error ?? conflictsQuery.error ?? nodeAcksQuery.error ?? authoritiesQuery.error}
        message="加载授权态势失败"
      />
      {noApplication ? (
        <Card><Typography.Text type="secondary">请选择应用。来源、有效期、冲突、最后同步、节点 ACK 与实断资格共同回答「这个端点现在切 PROTECT 会发生什么」。</Typography.Text></Card>
      ) : (
        <>
          <Row gutter={[12, 12]}>
            <Col xs={12} lg={4}><Card size="small"><Statistic title="已确认关系" value={relationsQuery.data?.total ?? 0} /></Card></Col>
            <Col xs={12} lg={5}>
              <Card size="small">
                <Statistic title="OPEN 冲突" value={conflictsQuery.data?.total ?? 0} valueStyle={{ color: (conflictsQuery.data?.total ?? 0) > 0 ? '#ad6800' : undefined }} />
              </Card>
            </Col>
            <Col xs={12} lg={5}><Card size="small"><Statistic title="节点 ACK（FRESH/全部）" value={freshCount} suffix={`/ ${nodeAcks.length}`} /></Card></Col>
            <Col xs={12} lg={5}><Card size="small"><Statistic title="可实断端点（READY/全部）" value={readyCount} suffix={`/ ${readinessItems.length}`} /></Card></Col>
            <Col xs={12} lg={5}>
              <Card size="small">
                <Statistic title="最大陈旧窗口" value={nodeAcksQuery.data?.max_staleness_seconds ?? '—'} suffix={nodeAcksQuery.data?.max_staleness_seconds != null ? '秒' : ''} />
              </Card>
            </Col>
          </Row>

          <Card size="small" title="关系来源与最后同步">
            <Descriptions size="small" column={1} bordered>
              <Descriptions.Item label="已确认关系来源">
                <Space size={[8, 4]} wrap>
                  {Object.entries(sourceCounts).length > 0
                    ? Object.entries(sourceCounts).map(([source, count]) => (
                        <Tag key={source} color={RELATION_SOURCE_META[source]?.color}>{RELATION_SOURCE_META[source]?.label ?? source} {count}</Tag>
                      ))
                    : <Typography.Text type="secondary">暂无已确认关系</Typography.Text>}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="手工登记（MANUAL）最后同步">
                {manualLastSync ? formatDateTime(manualLastSync) : <Typography.Text type="secondary">无手工关系</Typography.Text>}
              </Descriptions.Item>
              <Descriptions.Item label="权威同步（AUTHORITY_SYNC）">
                {authorityStatuses.length > 0 ? (
                  <Space direction="vertical" size={4} style={{ width: '100%' }}>
                    {authorityStatuses.map((st) => {
                      const lastBatch = st.batches.find((b) => b.status === 'APPLIED') ?? st.batches[0]
                      return (
                        <Space key={st.source.id} size={8} wrap>
                          <Typography.Text strong>{st.source.name}</Typography.Text>
                          <StatusTag value={st.gap_status} map={GAP_STATUS_META} />
                          <Typography.Text type="secondary">水位 seq={st.watermark.last_sequence}</Typography.Text>
                          <Typography.Text type="secondary">
                            最近批次 {lastBatch ? formatDateTime(lastBatch.created_at) : '—'}
                          </Typography.Text>
                        </Space>
                      )
                    })}
                  </Space>
                ) : (
                  <Typography.Text type="secondary">未登记权威来源（权威来源管理页面属后续批次）</Typography.Text>
                )}
              </Descriptions.Item>
            </Descriptions>
          </Card>

          <Card size="small" title="端点实断资格（readiness 服务端派生）">
            <SmartTable<ApiAuthzEnforcementReadinessItem>
              rowKey={(r) => `${r.endpoint_id}:${r.object_segment}`}
              storageKey="api-authz-enforcement-readiness"
              columns={readinessColumns}
              dataSource={readinessItems}
              loading={readinessQuery.isLoading}
              pagination={false}
              scroll={{ x: 1200 }}
              locale={{ emptyText: '该应用暂无对象模型行' }}
            />
          </Card>

          <Card size="small" title={`OPEN 冲突（${conflictsQuery.data?.total ?? 0}）`}>
            <SmartTable<ApiAuthzConflict>
              rowKey="id"
              storageKey="api-authz-conflicts"
              columns={conflictColumns}
              dataSource={conflictsQuery.data?.items ?? []}
              loading={conflictsQuery.isLoading}
              pagination={{ current: conflictPage, pageSize: 20, total: conflictsQuery.data?.total ?? 0, showSizeChanger: false, onChange: setConflictPage }}
              scroll={{ x: 950 }}
              locale={{ emptyText: '无 OPEN 冲突' }}
            />
          </Card>

          <Card size="small" title="节点 ACK（全节点授权快照应用状态）">
            <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
              管理面向量水位 manual_seq={nodeAcksQuery.data?.management_watermark?.manual_seq ?? 0}
              {nodeAcksQuery.data?.generated_at ? ` · 视图生成于 ${formatDateTime(nodeAcksQuery.data.generated_at)}` : ''}
            </Typography.Paragraph>
            <Table<ApiAuthzNodeAck>
              rowKey="node_name"
              size="small"
              columns={nodeAckColumns}
              dataSource={nodeAcks}
              loading={nodeAcksQuery.isLoading}
              pagination={false}
              scroll={{ x: 1100 }}
              locale={{ emptyText: '暂无节点心跳数据' }}
            />
          </Card>
        </>
      )}
      <ProtectWizard
        open={wizardPreset !== null}
        onClose={() => setWizardPreset(null)}
        applicationId={applicationId}
        preset={wizardPreset ?? undefined}
        onSwitched={() => {
          void readinessQuery.refetch()
          void relationsQuery.refetch()
        }}
      />
    </Space>
  )
}
