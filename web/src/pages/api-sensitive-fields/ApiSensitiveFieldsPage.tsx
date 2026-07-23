import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Select, Space, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiSensitiveFieldsApi, type ApiSensitiveField } from '../../api/apiSecurity'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { API_SENSITIVE_TYPE_META } from '../../utils/stage8'

/** 敏感数据（WDSP / 阶段8）：学习过程中识别出的敏感字段，按方向与数据类型筛选 */
export default function ApiSensitiveFieldsPage() {
  const [direction, setDirection] = useState<string | undefined>()
  const [dataType, setDataType] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const listQuery = useQuery({
    queryKey: ['api-sensitive-fields', direction, dataType, page, pageSize],
    queryFn: () =>
      apiSensitiveFieldsApi.list({ direction, data_type: dataType, page, page_size: pageSize }),
  })

  const columns: ColumnsType<ApiSensitiveField> = [
    {
      title: '端点 ID',
      dataIndex: 'endpoint_id',
      width: 120,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 8)}…</Typography.Text> : '-'),
    },
    { title: '方向', dataIndex: 'direction', width: 100 },
    {
      title: '字段路径',
      dataIndex: 'structured_path',
      ellipsis: true,
      render: (v: string) => (v ? <Typography.Text code>{v}</Typography.Text> : '-'),
    },
    {
      title: '数据类型',
      dataIndex: 'data_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={API_SENSITIVE_TYPE_META} />,
    },
    {
      title: '置信度',
      dataIndex: 'confidence',
      width: 90,
      align: 'right',
      render: (v: number) => (v * 100).toFixed(0) + '%',
    },
    {
      title: '识别来源',
      dataIndex: 'detection_source',
      width: 110,
      render: (v: string) => v || '-',
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <Card title="敏感数据">
      <Typography.Paragraph type="secondary">
        学习过程中从请求与响应样本里识别出的敏感字段（手机号、证件号、凭据等），供脱敏与泄露检测策略参考。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="方向"
          allowClear
          style={{ width: 140 }}
          value={direction}
          options={[
            { value: 'REQUEST', label: 'REQUEST' },
            { value: 'RESPONSE', label: 'RESPONSE' },
          ]}
          onChange={(v) => {
            setDirection(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="数据类型"
          allowClear
          style={{ width: 160 }}
          value={dataType}
          options={Object.entries(API_SENSITIVE_TYPE_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setDataType(v)
            setPage(1)
          }}
        />
      </Space>
      <SmartTable<ApiSensitiveField>
        storageKey="api-sensitive-fields"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1100 }}
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
  )
}
