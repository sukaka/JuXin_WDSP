import { Descriptions, Drawer, Empty, Table, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type { ApiGraphEdge } from '../../api/apiSecurity'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_ENDPOINT_STATUS_META, API_LEARNING_STATUS_META } from '../../utils/stage8'
import {
  HTTP_METHOD_COLOR,
  truncateMiddle,
  type EndpointEdgeStats,
  type IndexedTopologyNode,
} from './topologyUtils'

export interface EndpointTopologyDrawerProps {
  endpoint: IndexedTopologyNode | null
  stats?: EndpointEdgeStats
  nodeById: Map<string, IndexedTopologyNode>
  onClose: () => void
  onSelectEndpoint: (node: IndexedTopologyNode) => void
  onSelectEdge: (edge: ApiGraphEdge) => void
}

/** 单个接口的拓扑与上下游调用详情抽屉 */
export default function EndpointTopologyDrawer({
  endpoint,
  stats,
  nodeById,
  onClose,
  onSelectEndpoint,
  onSelectEdge,
}: EndpointTopologyDrawerProps) {
  const incoming = stats?.incomingEdges ?? []
  const outgoing = stats?.outgoingEdges ?? []
  const methodStyle = endpoint ? HTTP_METHOD_COLOR[endpoint.http_method.toUpperCase()] : undefined

  const incomingColumns: ColumnsType<ApiGraphEdge> = [
    {
      title: '调用方指纹',
      dataIndex: 'caller_fingerprint',
      width: 170,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{truncateMiddle(v, 10, 4)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '上游来源',
      dataIndex: 'source_endpoint_id',
      ellipsis: true,
      render: (v?: string | null) => {
        if (!v) return <Tag>外部调用方</Tag>
        const src = nodeById.get(v)
        if (!src) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
        return (
          <Tooltip title={src.endpoint_key}>
            <Typography.Link
              className="api-topology-code-ellipsis"
              onClick={() => onSelectEndpoint(src)}
            >
              {src.endpoint_key}
            </Typography.Link>
          </Tooltip>
        )
      },
    },
    {
      title: '调用次数',
      dataIndex: 'call_count',
      width: 84,
      align: 'right',
      render: (v: number) => <span className="api-topology-num">{v.toLocaleString()}</span>,
    },
    {
      title: '身份数',
      dataIndex: 'identity_count',
      width: 72,
      align: 'right',
      render: (v?: number) => <span className="api-topology-num">{v ?? '-'}</span>,
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen_at',
      width: 146,
      render: (v?: string) => formatDateTime(v),
    },
  ]

  const outgoingColumns: ColumnsType<ApiGraphEdge> = [
    {
      title: '目标接口',
      dataIndex: 'target_endpoint_id',
      ellipsis: true,
      render: (v: string) => {
        const target = nodeById.get(v)
        if (!target) return <Typography.Text type="secondary">{truncateMiddle(v)}</Typography.Text>
        return (
          <Tooltip title={target.endpoint_key}>
            <Typography.Link
              className="api-topology-code-ellipsis"
              onClick={() => onSelectEndpoint(target)}
            >
              {target.endpoint_key}
            </Typography.Link>
          </Tooltip>
        )
      },
    },
    {
      title: '调用次数',
      dataIndex: 'call_count',
      width: 84,
      align: 'right',
      render: (v: number) => <span className="api-topology-num">{v.toLocaleString()}</span>,
    },
    {
      title: '身份数',
      dataIndex: 'identity_count',
      width: 72,
      align: 'right',
      render: (v?: number) => <span className="api-topology-num">{v ?? '-'}</span>,
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen_at',
      width: 146,
      render: (v?: string) => formatDateTime(v),
    },
  ]

  return (
    <Drawer
      title="接口拓扑详情"
      open={endpoint !== null}
      onClose={onClose}
      size={680}
      destroyOnHidden
    >
      {endpoint && (
        <>
          <div className="api-topology-drawer-path">
            <span
              className="api-topology-method-badge"
              style={
                methodStyle
                  ? {
                      background: methodStyle.bg,
                      borderColor: methodStyle.border,
                      color: methodStyle.text,
                      marginRight: 8,
                    }
                  : { marginRight: 8 }
              }
            >
              {endpoint.http_method}
            </span>
            <Typography.Text copyable style={{ wordBreak: 'break-all' }}>
              {endpoint.normalized_path || '/'}
            </Typography.Text>
          </div>

          <div className="api-topology-drawer-kpis">
            <div className="api-topology-drawer-kpi">
              <span>累计命中</span>
              <strong>{(endpoint.hit_count ?? 0).toLocaleString()}</strong>
            </div>
            <div className="api-topology-drawer-kpi">
              <span>未闭环风险</span>
              <strong className={(endpoint.open_findings_count ?? 0) > 0 ? 'is-danger' : undefined}>
                {endpoint.open_findings_count ?? 0}
              </strong>
            </div>
            <div className="api-topology-drawer-kpi">
              <span>上游调用边</span>
              <strong>{incoming.length}</strong>
            </div>
            <div className="api-topology-drawer-kpi">
              <span>下游调用边</span>
              <strong>{outgoing.length}</strong>
            </div>
          </div>

          <Descriptions column={2} bordered size="small">
            <Descriptions.Item label="所属应用">{endpoint.applicationName}</Descriptions.Item>
            <Descriptions.Item label="资产状态">
              <StatusTag value={endpoint.asset_status} map={API_ENDPOINT_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="学习状态">
              {endpoint.learning_status ? (
                <StatusTag value={endpoint.learning_status} map={API_LEARNING_STATUS_META} />
              ) : (
                '-'
              )}
            </Descriptions.Item>
            <Descriptions.Item label="涉及调用方">{stats?.callerCount ?? 0}</Descriptions.Item>
            <Descriptions.Item label="完整端点键" span={2}>
              <Typography.Text copyable style={{ wordBreak: 'break-all', fontSize: 12 }}>
                {endpoint.endpoint_key}
              </Typography.Text>
            </Descriptions.Item>
          </Descriptions>

          <div className="api-topology-drawer-section">
            <div className="api-topology-drawer-section-title">
              上游调用关系（共 {incoming.length} 条）
            </div>
            {incoming.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前时间窗暂无上游调用边记录" />
            ) : (
              <Table<ApiGraphEdge>
                size="small"
                rowKey="id"
                tableLayout="fixed"
                columns={incomingColumns}
                dataSource={incoming}
                onRow={(record) => ({
                  onClick: () => onSelectEdge(record),
                  style: { cursor: 'pointer' },
                })}
                pagination={{ pageSize: 6, hideOnSinglePage: true, showSizeChanger: false }}
              />
            )}
          </div>

          <div className="api-topology-drawer-section">
            <div className="api-topology-drawer-section-title">
              下游调用关系（共 {outgoing.length} 条）
            </div>
            {outgoing.length === 0 ? (
              <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前时间窗暂无下游调用边记录" />
            ) : (
              <Table<ApiGraphEdge>
                size="small"
                rowKey="id"
                tableLayout="fixed"
                columns={outgoingColumns}
                dataSource={outgoing}
                onRow={(record) => ({
                  onClick: () => onSelectEdge(record),
                  style: { cursor: 'pointer' },
                })}
                pagination={{ pageSize: 6, hideOnSinglePage: true, showSizeChanger: false }}
              />
            )}
          </div>
        </>
      )}
    </Drawer>
  )
}
