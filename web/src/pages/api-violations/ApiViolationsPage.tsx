import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, DatePicker, Select, Space, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import type dayjs from 'dayjs'
import { apiEndpointsApi } from '../../api/apiAssets'
import { apiFindingsApi, type ApiViolation } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_ACTION_META, API_VIOLATION_TYPE_META } from '../../utils/stage8'

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

/** Schema 违例（WDSP / 阶段8）：请求字段与正式模型约束不一致的运行时记录列表 */
export default function ApiViolationsPage() {
  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [violationType, setViolationType] = useState<string | undefined>()
  const [range, setRange] = useState<RangeValue>(null)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiViolation | null>(null)

  /** 接口选择器数据源（同时用于把 endpoint_id 映射为接口键展示） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  const endpointKeyById = useMemo(() => {
    const m = new Map<string, string>()
    for (const e of endpointsQuery.data?.items ?? []) m.set(e.id, e.endpoint_key)
    return m
  }, [endpointsQuery.data])

  const listQuery = useQuery({
    queryKey: ['api-violations', endpointId, violationType, range?.[0]?.toISOString(), range?.[1]?.toISOString(), page, pageSize],
    queryFn: () =>
      apiFindingsApi.violations({
        endpoint_id: endpointId,
        violation_type: violationType,
        start_time: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
        end_time: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
        page,
        page_size: pageSize,
      }),
  })

  const columns: ColumnsType<ApiViolation> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '接口',
      dataIndex: 'endpoint_id',
      width: 220,
      ellipsis: true,
      render: (v: string | null) => {
        if (!v) return '-'
        const key = endpointKeyById.get(v)
        return key ? (
          <Typography.Text code>{key}</Typography.Text>
        ) : (
          <Tooltip title={`接口 ID: ${v}`}>
            <Typography.Text code>{v.slice(0, 8)}…</Typography.Text>
          </Tooltip>
        )
      },
    },
    {
      title: '违例类型',
      dataIndex: 'violation_type',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={API_VIOLATION_TYPE_META} />,
    },
    {
      title: '字段路径',
      dataIndex: 'field_path',
      width: 180,
      ellipsis: true,
      render: (v: string) => <Typography.Text code>{v || '-'}</Typography.Text>,
    },
    {
      title: '期望值',
      dataIndex: 'expected',
      width: 180,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '观测值',
      dataIndex: 'observed',
      width: 180,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '执行动作',
      dataIndex: 'action_taken',
      width: 110,
      render: (v: string) => (v ? <StatusTag value={v} map={API_ACTION_META} /> : '-'),
    },
    {
      title: '请求 ID',
      dataIndex: 'request_id',
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
  ]

  return (
    <Card title="Schema 违例">
      <Typography.Paragraph type="secondary">
        运行时请求字段与正式模型约束不一致的违例记录（未定义字段、类型不匹配、缺失字段、约束违例），按发生时间倒序。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="接口"
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
          placeholder="违例类型"
          allowClear
          style={{ width: 160 }}
          value={violationType}
          options={Object.entries(API_VIOLATION_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setViolationType(v)
            setPage(1)
          }}
        />
        <DatePicker.RangePicker
          value={range}
          onChange={(v) => {
            setRange(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiViolation>
        storageKey="api-violations"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
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
        title="违例详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
