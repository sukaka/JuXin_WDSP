import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Card, Space, Table, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiNodesApi, type ApiNode, type ApiNodeVersionGroup } from '../../api/apiNodes'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'

/** 节点状态展示映射（与 server/internal/apinodes 状态词表一致） */
const NODE_STATUS_META: Record<string, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '活跃' },
  STALE: { color: 'gold', label: '停滞' },
  SILENT: { color: 'default', label: '静默' },
}

/** 配置同步结果展示映射（last_sync_result 词表；空串 = 从未同步） */
const SYNC_RESULT_META: Record<string, { color: string; label: string }> = {
  SUCCESS: { color: 'green', label: '成功' },
  FAILED: { color: 'red', label: '失败' },
  HASH_MISMATCH: { color: 'volcano', label: '哈希不一致' },
}

/** 版本文本截断展示（空串 = 未上报，占位符；hover 显示完整值） */
function VersionText({ value }: { value: string }) {
  if (!value) return <span>-</span>
  return (
    <Tooltip title={value}>
      <Typography.Text code ellipsis style={{ maxWidth: 220, verticalAlign: 'middle' }}>
        {value}
      </Typography.Text>
    </Tooltip>
  )
}

/**
 * 网关节点版本校验（WDSP / 阶段8）：节点状态与策略/模型版本视图 + 版本一致性判定。
 * 一致性横幅回答「所有节点策略版本是否一致」；SILENT 离线节点不参与判定但如实列出。
 */
export default function ApiNodesPage() {
  const listQuery = useQuery({
    queryKey: ['api-nodes'],
    queryFn: () => apiNodesApi.list(),
  })

  const consistencyQuery = useQuery({
    queryKey: ['api-nodes', 'consistency'],
    queryFn: () => apiNodesApi.consistency(),
  })

  const report = consistencyQuery.data

  const [detailRecord, setDetailRecord] = useState<Record<string, unknown> | null>(null)
  const [detailTitle, setDetailTitle] = useState('记录详情')

  const columns: ColumnsType<ApiNode> = [
    { title: '节点名称', dataIndex: 'node_name', ellipsis: true },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={NODE_STATUS_META} />,
    },
    {
      title: '最近事件时间',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '策略版本',
      dataIndex: 'last_policy_version',
      width: 240,
      render: (v: string) => <VersionText value={v} />,
    },
    {
      title: '模型版本',
      dataIndex: 'last_model_version',
      width: 240,
      render: (v: string) => <VersionText value={v} />,
    },
    { title: '事件数', dataIndex: 'event_count', width: 100 },
    {
      title: '配置同步',
      dataIndex: 'last_sync_result',
      width: 110,
      render: (v: string, record: ApiNode) => {
        if (!record.sync_enabled) return <Tag>未参与</Tag>
        if (!v) return <Tag>未同步</Tag>
        const tag = <StatusTag value={v} map={SYNC_RESULT_META} />
        // hover 补充最近同步时间与失败原因（如实展示后端截断值）
        const tips: string[] = []
        if (record.last_sync_at) tips.push(`最近同步：${formatDateTime(record.last_sync_at)}`)
        if (record.last_sync_error) tips.push(`错误：${record.last_sync_error}`)
        return tips.length > 0 ? <Tooltip title={tips.join('；')}>{tag}</Tooltip> : tag
      },
    },
    {
      title: '版本一致',
      dataIndex: 'version_consistent',
      width: 100,
      render: (v: boolean | null) => {
        if (v === null || v === undefined) return '-'
        return v ? <Tag color="green">一致</Tag> : <Tag color="red">不一致</Tag>
      },
    },
  ]

  const groupColumns: ColumnsType<ApiNodeVersionGroup> = [
    {
      title: '策略版本',
      dataIndex: 'policy_version',
      width: 280,
      render: (v: string) => (v ? <VersionText value={v} /> : <Tag>未上报</Tag>),
    },
    { title: '节点数', dataIndex: 'node_count', width: 90 },
    {
      title: '节点',
      dataIndex: 'nodes',
      render: (nodes: string[]) => (
        <Space size={4} wrap>
          {nodes.map((n) => (
            <Tag key={n}>{n}</Tag>
          ))}
        </Space>
      ),
    },
  ]

  return (
    <Card title="网关节点版本校验">
      <Typography.Paragraph type="secondary">
        节点状态按最近事件距当前时刻判定（5 分钟内活跃、5 分钟~1 小时停滞、超过 1 小时静默）；
        一致性判定仅统计活跃且已上报策略版本的节点，静默节点不参与但单独列出。
      </Typography.Paragraph>
      {report ? (
        <>
          <Alert
            style={{ marginBottom: 16 }}
            type={report.consistent ? (report.evaluated_nodes > 0 ? 'success' : 'info') : 'error'}
            showIcon
            message={
              report.consistent
                ? report.evaluated_nodes > 0
                  ? `活跃节点策略版本一致（${report.evaluated_nodes} 个参与判定，版本 ${report.dominant_version}）`
                  : '无版本数据可比（当前没有活跃节点上报策略版本）'
                : `节点策略版本不一致：${report.evaluated_nodes} 个活跃节点存在多个版本`
            }
            description={
              report.silent_nodes.length > 0
                ? `静默节点（离线不参与判定）：${report.silent_nodes.join('、')}`
                : undefined
            }
          />
          {report.groups.length > 0 ? (
            <Table<ApiNodeVersionGroup>
              style={{ marginBottom: 16 }}
              rowKey={(g) => g.policy_version || '(unreported)'}
              onRow={(record) => ({
                onDoubleClick: () => {
                  setDetailTitle('版本分组详情')
                  setDetailRecord(record as unknown as Record<string, unknown>)
                },
                style: { cursor: 'pointer' },
              })}
              size="small"
              columns={groupColumns}
              dataSource={report.groups}
              pagination={false}
            />
          ) : null}
        </>
      ) : null}
      <QueryErrorAlert error={listQuery.error ?? consistencyQuery.error} />
      <SmartTable<ApiNode>
        storageKey="api-nodes"
        rowKey="id"
        onRow={(record) => ({
          onDoubleClick: () => {
            setDetailTitle('节点详情')
            setDetailRecord(record as unknown as Record<string, unknown>)
          },
          style: { cursor: 'pointer' },
        })}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
        pagination={false}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title={detailTitle}
        record={detailRecord}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
