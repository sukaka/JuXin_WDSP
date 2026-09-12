import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Col,
  Drawer,
  Row,
  Select,
  Space,
  Statistic,
  Timeline,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiFindingsApi, apiLifecycleApi, type ApiFinding } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  API_ENDPOINT_STATUS_META,
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_FINDING_TYPE_META,
} from '../../utils/stage8'

/** 本页固定关注的三类风险：影子 / 僵尸 / 已下线 API */
const LIFECYCLE_FINDING_TYPES = ['SHADOW', 'ZOMBIE', 'DEPRECATED'] as const

/** 指纹/ID 截断展示：保留首尾，中间省略 */
function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** 单类风险计数（page_size=1 仅取 total） */
function useFindingTotal(findingType: string) {
  return useQuery({
    queryKey: ['api-findings', 'count', findingType],
    queryFn: () => apiFindingsApi.list({ finding_type: findingType, page: 1, page_size: 1 }),
  })
}

/** Shadow 与 Zombie API（WDSP / 阶段8）：影子/僵尸/已下线 API 计数与列表，行内查看接口生命周期 */
export default function ApiShadowZombiePage() {
  const [findingType, setFindingType] = useState<string>('SHADOW')
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiFinding | null>(null)

  const shadowTotal = useFindingTotal('SHADOW')
  const zombieTotal = useFindingTotal('ZOMBIE')
  const deprecatedTotal = useFindingTotal('DEPRECATED')

  const listQuery = useQuery({
    queryKey: ['api-findings', 'lifecycle', findingType, status, page, pageSize],
    queryFn: () =>
      apiFindingsApi.list({
        finding_type: findingType,
        status,
        page,
        page_size: pageSize,
      }),
  })

  const lifecycleQuery = useQuery({
    queryKey: ['api-lifecycle-events', selected?.endpoint_id],
    queryFn: () => apiLifecycleApi.events(selected!.endpoint_id!, { page: 1, page_size: 50 }),
    enabled: selected?.endpoint_id != null,
  })

  const columns: ColumnsType<ApiFinding> = [
    {
      title: '类型',
      dataIndex: 'finding_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_TYPE_META} />,
    },
    {
      title: '严重级别',
      dataIndex: 'severity',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_SEVERITY_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={API_FINDING_STATUS_META} />,
    },
    { title: '标题', dataIndex: 'title', ellipsis: true },
    {
      title: '接口',
      dataIndex: 'endpoint_id',
      width: 150,
      render: (v: string | null) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text code>{truncateMiddle(v)}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '首次发现',
      dataIndex: 'first_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '最近发现',
      dataIndex: 'last_seen_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 100,
      fixed: 'right',
      render: (_, record) =>
        record.endpoint_id ? (
          <Button type="link" size="small" onClick={() => setSelected(record)}>
            生命周期
          </Button>
        ) : null,
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="影子 API"
              value={shadowTotal.data?.total ?? 0}
              loading={shadowTotal.isLoading}
              valueStyle={{ color: '#d4380d' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="僵尸 API"
              value={zombieTotal.data?.total ?? 0}
              loading={zombieTotal.isLoading}
              valueStyle={{ color: '#c41d7f' }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={8}>
          <Card size="small">
            <Statistic
              title="已下线 API"
              value={deprecatedTotal.data?.total ?? 0}
              loading={deprecatedTotal.isLoading}
              valueStyle={{ color: '#d46b08' }}
            />
          </Card>
        </Col>
      </Row>
      <Card title="Shadow 与 Zombie API">
        <Typography.Paragraph type="secondary">
          影子 API：运行时观测到但未登记的 API；僵尸 API：登记在册但长期无流量的 API；已下线 API：已废弃仍被调用的 API。
        </Typography.Paragraph>
        <QueryErrorAlert error={listQuery.error} />
        <Space style={{ marginBottom: 16 }} wrap>
          <Select
            style={{ width: 160 }}
            value={findingType}
            options={LIFECYCLE_FINDING_TYPES.map((value) => ({
              value,
              label: API_FINDING_TYPE_META[value]?.label ?? value,
            }))}
            onChange={(v) => {
              setFindingType(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="处置状态"
            allowClear
            style={{ width: 140 }}
            value={status}
            options={Object.entries(API_FINDING_STATUS_META).map(([value, meta]) => ({
              value,
              label: meta.label,
            }))}
            onChange={(v) => {
              setStatus(v)
              setPage(1)
            }}
          />
        </Space>
        <SmartTable<ApiFinding>
          storageKey="api-shadow-zombie"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items ?? []}
          scroll={{ x: 1200 }}
          onRow={(record) => ({
            // 与操作列「生命周期」按钮同口径：仅有关联接口的发现可查看
            onDoubleClick: () => {
              if (record.endpoint_id) setSelected(record)
            },
            style: { cursor: record.endpoint_id ? 'pointer' : undefined },
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
      </Card>
      <Drawer
        title={selected ? `接口生命周期：${truncateMiddle(selected.endpoint_id ?? '')}` : '接口生命周期'}
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={520}
      >
        {lifecycleQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : lifecycleQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载生命周期事件失败"
            description={lifecycleQuery.error instanceof ApiError ? lifecycleQuery.error.message : undefined}
          />
        ) : (lifecycleQuery.data?.items ?? []).length === 0 ? (
          <Typography.Text type="secondary">暂无生命周期事件</Typography.Text>
        ) : (
          <Timeline
            items={(lifecycleQuery.data?.items ?? []).map((e) => ({
              color: API_ENDPOINT_STATUS_META[e.to_status]?.color === 'default' ? 'gray' : (API_ENDPOINT_STATUS_META[e.to_status]?.color ?? 'blue'),
              children: (
                <>
                  <Space size={4}>
                    <StatusTag value={e.from_status} map={API_ENDPOINT_STATUS_META} />
                    <Typography.Text type="secondary">→</Typography.Text>
                    <StatusTag value={e.to_status} map={API_ENDPOINT_STATUS_META} />
                  </Space>
                  <div>{e.reason || '-'}</div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {e.actor || '-'} · {formatDateTime(e.created_at)}
                  </Typography.Text>
                </>
              ),
            }))}
          />
        )}
      </Drawer>
    </Space>
  )
}
