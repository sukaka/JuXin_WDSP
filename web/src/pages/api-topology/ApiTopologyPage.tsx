import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Col, Row, Space, Table, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiGraphApi, type ApiGraphEdge, type ApiGraphNode } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { API_ENDPOINT_STATUS_META } from '../../utils/stage8'

/** 指纹/ID 截断展示：保留首尾，中间省略 */
function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** API 调用拓扑（WDSP / 阶段8）：按应用分组的端点卡片墙 + 调用边明细 */
export default function ApiTopologyPage() {
  const topologyQuery = useQuery({
    queryKey: ['api-topology'],
    queryFn: () => apiGraphApi.topology(),
  })

  const groups = useMemo(() => topologyQuery.data?.groups ?? [], [topologyQuery.data])
  const edges = useMemo(() => topologyQuery.data?.edges ?? [], [topologyQuery.data])

  const nodeById = useMemo(() => {
    const map = new Map<string, ApiGraphNode>()
    for (const g of groups) {
      for (const n of g.endpoints ?? []) map.set(n.id, n)
    }
    return map
  }, [groups])

  const edgeColumns: ColumnsType<ApiGraphEdge> = [
    {
      title: '调用方指纹',
      dataIndex: 'caller_fingerprint',
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>{truncateMiddle(v, 12, 6)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '目标端点',
      dataIndex: 'target_endpoint_id',
      ellipsis: true,
      render: (v: string) => {
        const target = nodeById.get(v)
        return target ? <Typography.Text code>{target.endpoint_key}</Typography.Text> : truncateMiddle(v)
      },
    },
    { title: '调用次数', dataIndex: 'call_count', width: 110, align: 'right' },
  ]

  return (
    <Card title="API 调用拓扑">
      <Typography.Paragraph type="secondary">
        端点按所属应用分组展示，Tag 颜色对应资产状态（蓝=已发现、绿=已确认、灰=已忽略、橙=已废弃）；下方为运行时观测到的调用边明细。
      </Typography.Paragraph>
      <QueryErrorAlert error={topologyQuery.error} />
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        {groups.map((g) => (
          <Col xs={24} sm={12} lg={8} key={g.application_id ?? 'unassigned'}>
            <Card
              size="small"
              title={g.application_name || '未分配应用'}
              extra={<Typography.Text type="secondary">{g.endpoints?.length ?? 0} 个端点</Typography.Text>}
            >
              <Space size={[8, 8]} wrap>
                {(g.endpoints ?? []).map((n) => {
                  const meta = API_ENDPOINT_STATUS_META[n.asset_status]
                  return (
                    <Tooltip key={n.id} title={`资产状态：${meta?.label ?? n.asset_status}`}>
                      <Tag color={meta?.color} style={{ marginInlineEnd: 0 }}>
                        {n.http_method} {n.normalized_path}
                      </Tag>
                    </Tooltip>
                  )
                })}
              </Space>
            </Card>
          </Col>
        ))}
      </Row>
      <Typography.Title level={5}>调用边明细</Typography.Title>
      <Table<ApiGraphEdge>
        rowKey="id"
        size="small"
        loading={topologyQuery.isLoading}
        columns={edgeColumns}
        dataSource={edges}
        pagination={{ pageSize: 8, showSizeChanger: false, hideOnSinglePage: true, showTotal: (t) => `共 ${t} 条` }}
      />
    </Card>
  )
}
