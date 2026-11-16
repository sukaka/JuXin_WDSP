import { useQuery } from '@tanstack/react-query'
import { Alert, Table, Typography } from 'antd'
import { apiFileSignatureApi } from '../../api/apiFileSignature'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { formatDateTime } from '../../utils/format'

export default function FileLineagePanel({ sha256 }: { sha256: string }) {
  const query = useQuery({
    queryKey: ['api-file-lineage', sha256],
    queryFn: () => apiFileSignatureApi.lineage(sha256),
    enabled: sha256 !== '',
    retry: false,
  })
  const data = query.data
  const items = data?.items ?? []

  return (
    <div
      style={{ marginTop: 16, borderTop: '1px solid #f0f0f0', paddingTop: 16 }}
    >
      <Typography.Text strong>同内容传输关联</Typography.Text>
      <Typography.Paragraph type="secondary" style={{ marginTop: 4 }}>
        按完整文件内容指纹关联实际上传与下载，不代表业务所有权或创建者。
      </Typography.Paragraph>
      <QueryErrorAlert error={query.error} />
      {data ? (
        <Typography.Paragraph type="secondary">
          共 {data.total} 条关联资产（上传 {data.upload_assets}，下载{' '}
          {data.download_assets}）
        </Typography.Paragraph>
      ) : null}
      {data?.truncated ? (
        <Alert
          type="warning"
          showIcon
          title={`关联记录较多，仅展示前 100 条，实际共 ${data.total} 条`}
        />
      ) : null}
      {data && items.length === 0 ? (
        <Typography.Text type="secondary">
          暂无相同内容的传输记录
        </Typography.Text>
      ) : null}
      {items.length > 0 ? (
        <Table
          rowKey="id"
          size="small"
          loading={query.isLoading}
          pagination={false}
          dataSource={items}
          scroll={{ x: 1080 }}
          columns={[
            {
              title: '方向',
              dataIndex: 'direction',
              width: 80,
              render: (value: string) => (value === 'UPLOAD' ? '上传' : '下载'),
            },
            {
              title: '文件名',
              dataIndex: 'filename',
              width: 160,
              ellipsis: true,
            },
            {
              title: '身份指纹',
              dataIndex: 'identity_fingerprint',
              width: 220,
              ellipsis: true,
              render: (value: string) => value || '匿名',
            },
            {
              title: '来源 IP（脱敏）',
              dataIndex: 'client_ip_masked',
              width: 150,
              ellipsis: true,
              render: (value: string) => value || '未知',
            },
            {
              title: '端点',
              dataIndex: 'endpoint_key',
              ellipsis: true,
              render: (value: string) => (
                <Typography.Text code>{value}</Typography.Text>
              ),
            },
            {
              title: '传输次数',
              dataIndex: 'transfer_count',
              width: 90,
              align: 'right',
            },
            {
              title: '最近观测',
              dataIndex: 'last_seen',
              width: 170,
              render: (value: string) => formatDateTime(value),
            },
          ]}
        />
      ) : null}
    </div>
  )
}
