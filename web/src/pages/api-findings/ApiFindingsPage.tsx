import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button, Card, Descriptions, Drawer, Select, Space, Table, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiFindingsApi, type ApiFinding } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { formatDateTime, formatJson } from '../../utils/format'
import {
  API_FINDING_SEVERITY_META,
  API_FINDING_STATUS_META,
  API_FINDING_TYPE_META,
} from '../../utils/stage8'

/** 指纹/ID 截断展示：保留首尾，中间省略 */
function truncateMiddle(value: string, head = 8, tail = 4): string {
  if (!value) return '-'
  if (value.length <= head + tail + 3) return value
  return `${value.slice(0, head)}…${value.slice(-tail)}`
}

/** API 风险发现（WDSP / 阶段8）：影子/僵尸接口、越权、模型偏离等风险列表 */
export default function ApiFindingsPage() {
  const [findingType, setFindingType] = useState<string | undefined>()
  const [severity, setSeverity] = useState<string | undefined>()
  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<ApiFinding | null>(null)

  const listQuery = useQuery({
    queryKey: ['api-findings', findingType, severity, status, page, pageSize],
    queryFn: () =>
      apiFindingsApi.list({
        finding_type: findingType,
        severity,
        status,
        page,
        page_size: pageSize,
      }),
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
      title: '端点',
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
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card title="API 风险发现">
      <Typography.Paragraph type="secondary">
        运行时识别出的接口风险：影子/僵尸接口、对象级与功能级越权、模型偏离、敏感数据泄露等。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="风险类型"
          allowClear
          style={{ width: 160 }}
          value={findingType}
          options={Object.entries(API_FINDING_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFindingType(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="严重级别"
          allowClear
          style={{ width: 140 }}
          value={severity}
          options={Object.entries(API_FINDING_SEVERITY_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setSeverity(v)
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
      <Table<ApiFinding>
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
      <Drawer
        title={selected ? `风险详情：${selected.title}` : '风险详情'}
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={640}
      >
        {selected ? (
          <>
            <Descriptions column={2} size="small" style={{ marginBottom: 16 }}>
              <Descriptions.Item label="风险类型">
                <StatusTag value={selected.finding_type} map={API_FINDING_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="严重级别">
                <StatusTag value={selected.severity} map={API_FINDING_SEVERITY_META} />
              </Descriptions.Item>
              <Descriptions.Item label="处置状态">
                <StatusTag value={selected.status} map={API_FINDING_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="端点 ID">
                {selected.endpoint_id ? <Typography.Text code>{selected.endpoint_id}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="请求 ID">
                <Typography.Text code>{selected.request_id || '-'}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="发现 ID">
                <Typography.Text code>{selected.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="首次发现">{formatDateTime(selected.first_seen_at)}</Descriptions.Item>
              <Descriptions.Item label="最近发现">{formatDateTime(selected.last_seen_at)}</Descriptions.Item>
              <Descriptions.Item label="标题" span={2}>
                {selected.title}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>风险明细（detail）</Typography.Title>
            <Typography.Paragraph>
              <pre style={{ background: '#fafafa', padding: 12, fontSize: 12, overflow: 'auto', margin: 0 }}>
                {formatJson(selected.detail)}
              </pre>
            </Typography.Paragraph>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
