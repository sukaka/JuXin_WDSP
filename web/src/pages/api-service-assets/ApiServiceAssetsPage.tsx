import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, Descriptions, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiServiceAssetsApi, type ApiServiceAsset } from '../../api/apiServiceAssets'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'

/**
 * 服务资产（WDSP / 阶段8 §14）：源站主机:端口 视角的聚合视图。
 * 应用数/接口数/近 7 天流量/涉敏接口数/未闭环风险数由服务端从 upstreams
 * 反聚端点归属得出；行展开可查看计数明细。
 */
export default function ApiServiceAssetsPage() {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiServiceAsset | null>(null)

  const listQuery = useQuery({
    queryKey: ['api-service-assets', page, pageSize],
    queryFn: () => apiServiceAssetsApi.list({ page, page_size: pageSize }),
  })

  const columns: ColumnsType<ApiServiceAsset> = [
    {
      title: '服务地址',
      key: 'address',
      ellipsis: true,
      render: (_, record) => (
        <Typography.Text code>{`${record.server_ip}:${record.port}`}</Typography.Text>
      ),
    },
    { title: '应用数', dataIndex: 'application_count', width: 90 },
    { title: '接口数', dataIndex: 'api_count', width: 90 },
    { title: '近 7 天请求量', dataIndex: 'traffic_7d', width: 130 },
    {
      title: '涉敏接口',
      dataIndex: 'sensitive_api_count',
      width: 130,
      render: (v: number) => (
        <Space size={4}>
          <span>{v}</span>
          {v > 0 ? <Tag color="orange">涉敏</Tag> : null}
        </Space>
      ),
    },
    {
      title: '未闭环风险',
      dataIndex: 'risk_count',
      width: 130,
      render: (v: number) => (
        <Space size={4}>
          <span>{v}</span>
          {v > 0 ? <Tag color="red">风险</Tag> : null}
        </Space>
      ),
    },
  ]

  return (
    <Card title="服务资产">
      <Typography.Paragraph type="secondary">
        按源站主机:端口聚合的服务资产视图：展示各服务承载的应用数、归属接口数、近 7 天请求量，
        并标记含敏感字段接口（涉敏）与未闭环风险发现（风险）的服务。行展开可查看计数明细。
      </Typography.Paragraph>
      <QueryErrorAlert error={listQuery.error} />
      <SmartTable<ApiServiceAsset>
        storageKey="api-service-assets"
        rowKey={(r) => `${r.server_ip}:${r.port}`}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        expandable={{
          expandedRowRender: (record) => (
            <Descriptions column={3} size="small" bordered>
              <Descriptions.Item label="服务地址" span={3}>
                <Typography.Text code>{`${record.server_ip}:${record.port}`}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="承载应用数">{record.application_count}</Descriptions.Item>
              <Descriptions.Item label="归属接口数">{record.api_count}</Descriptions.Item>
              <Descriptions.Item label="近 7 天请求量">{record.traffic_7d}</Descriptions.Item>
              <Descriptions.Item label="涉敏接口数">
                {record.sensitive_api_count}
                {record.sensitive_api_count > 0 ? (
                  <Tag color="orange" style={{ marginLeft: 8 }}>
                    涉敏
                  </Tag>
                ) : null}
              </Descriptions.Item>
              <Descriptions.Item label="未闭环风险数">
                {record.risk_count}
                {record.risk_count > 0 ? (
                  <Tag color="red" style={{ marginLeft: 8 }}>
                    风险
                  </Tag>
                ) : null}
              </Descriptions.Item>
            </Descriptions>
          ),
        }}
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
        title="服务资产详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
