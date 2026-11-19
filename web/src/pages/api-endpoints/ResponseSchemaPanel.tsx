import { Table, Alert, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { useQuery } from '@tanstack/react-query'
import { apiModelsApi, type ApiResponseSchemaItem } from '../../api/apiAssets'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { API_BASE_TYPE_META } from '../../utils/stage8'

interface Props {
  endpointId: string
}

export default function ResponseSchemaPanel({ endpointId }: Props) {
  const permissions = useAuthStore((state) => state.user?.permissions)
  const canRead = hasPermission(permissions, 'api_model.read')
  const query = useQuery({
    queryKey: ['api-response-schemas', endpointId],
    queryFn: () => apiModelsApi.listResponseSchemas(endpointId),
    enabled: canRead && endpointId !== '',
  })

  const columns: ColumnsType<ApiResponseSchemaItem> = [
    {
      title: '状态码',
      dataIndex: 'status_code',
      width: 82,
      render: (value: number) => (
        <Tag color={value >= 400 ? 'orange' : 'green'}>{value}</Tag>
      ),
    },
    {
      title: 'Content-Type',
      dataIndex: 'content_type',
      width: 165,
      ellipsis: true,
      render: (value?: string) => value || '-',
    },
    {
      title: '字段数',
      key: 'field_count',
      width: 75,
      align: 'right',
      render: (_, record) => Object.keys(record.fields).length,
    },
    {
      title: '样本数',
      dataIndex: 'sample_count',
      width: 85,
      align: 'right',
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen',
      width: 155,
      render: (value: string) => formatDateTime(value),
    },
    {
      title: '完整性',
      dataIndex: 'truncated',
      width: 90,
      render: (value: boolean) =>
        value ? (
          <Tag color="orange">曾截断</Tag>
        ) : (
          <Tag color="green">完整</Tag>
        ),
    },
    {
      title: '结构哈希',
      dataIndex: 'content_hash',
      width: 135,
      render: (value: string) =>
        value ? (
          <Typography.Text code title={value}>
            {value.slice(0, 12)}…
          </Typography.Text>
        ) : (
          '-'
        ),
    },
  ]

  return (
    <section aria-label="运行时响应 Schema" style={{ marginTop: 16 }}>
      <Typography.Title level={5}>响应 Schema（运行时）</Typography.Title>
      <Typography.Paragraph type="secondary">
        按状态码展示真实运行时学习结果；仅含字段路径与类型，不包含响应值或模型版本快照。
      </Typography.Paragraph>
      {!canRead ? (
        <Alert
          type="info"
          showIcon
          message="缺少 api_model.read 权限，无法查看响应 Schema"
        />
      ) : (
        <>
          <QueryErrorAlert error={query.error} />
          <Table<ApiResponseSchemaItem>
            size="small"
            rowKey="id"
            loading={query.isLoading}
            columns={columns}
            dataSource={query.data ?? []}
            locale={{ emptyText: '当前接口暂无运行时响应 Schema 学习结果' }}
            scroll={{ x: 790 }}
            pagination={false}
            expandable={{
              rowExpandable: (record) => Object.keys(record.fields).length > 0,
              expandedRowRender: (record) => (
                <Table
                  size="small"
                  rowKey="field"
                  pagination={false}
                  columns={[
                    {
                      title: '字段路径',
                      dataIndex: 'field',
                      render: (value: string) => (
                        <Typography.Text code>{value}</Typography.Text>
                      ),
                    },
                    {
                      title: '类型',
                      dataIndex: 'type',
                      width: 160,
                      render: (value: string) => (
                        <StatusTag value={value} map={API_BASE_TYPE_META} />
                      ),
                    },
                  ]}
                  dataSource={Object.entries(record.fields)
                    .sort(([left], [right]) => left.localeCompare(right))
                    .map(([field, type]) => ({ field, type }))}
                />
              ),
            }}
          />
        </>
      )}
    </section>
  )
}
