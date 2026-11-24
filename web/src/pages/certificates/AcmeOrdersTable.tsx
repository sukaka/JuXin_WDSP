import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Select, Space, Tag, Tooltip, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ReloadOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { acmeApi } from '../../api/acme'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  ACME_ORDER_STATUS_META,
  ACME_PROVIDER_META,
  ACME_TRIGGER_META,
  isActiveAcmeOrderStatus,
} from '../../utils/stage3'
import type { AcmeOrderItem } from '../../types'

export default function AcmeOrdersTable({ applicationId }: { applicationId?: string }) {
  const [status, setStatus] = useState<string | undefined>(undefined)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const ordersQuery = useQuery({
    queryKey: ['acme-orders', applicationId ?? 'all', status, page, pageSize],
    queryFn: () =>
      acmeApi.listOrders({
        application_id: applicationId,
        status,
        page,
        page_size: pageSize,
      }),
    refetchInterval: (q) => {
      const items = q.state.data?.items ?? []
      return items.some((it) => isActiveAcmeOrderStatus(it.status)) ? 3000 : false
    },
  })

  const columns: ColumnsType<AcmeOrderItem> = [
    {
      title: '触发时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    ...(!applicationId
      ? [
          {
            title: '关联站点',
            key: 'app',
            width: 170,
            render: (_: unknown, r: AcmeOrderItem) =>
              r.app_name ? `${r.app_name}（${r.app_code}）` : r.app_code || r.application_id,
          },
        ]
      : []),
    {
      title: '触发方式',
      dataIndex: 'trigger_type',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={ACME_TRIGGER_META} />,
    },
    {
      title: 'CA 提供商',
      dataIndex: 'provider',
      width: 150,
      render: (v: string) => <StatusTag value={v} map={ACME_PROVIDER_META} />,
    },
    {
      title: '申请域名',
      dataIndex: 'domains',
      width: 220,
      render: (domains: string[]) =>
        domains && domains.length > 0 ? (
          <Space wrap size={4}>
            {domains.map((d) => (
              <Tag key={d} style={{ fontFamily: 'monospace' }}>
                {d}
              </Tag>
            ))}
          </Space>
        ) : (
          '-'
        ),
    },
    {
      title: '任务状态',
      dataIndex: 'status',
      width: 140,
      render: (v: string) => <StatusTag value={v} map={ACME_ORDER_STATUS_META} />,
    },
    {
      title: '结果说明',
      key: 'error',
      ellipsis: true,
      render: (_, r) =>
        r.error_message ? (
          <Tooltip title={r.error_message}>
            <Typography.Text type="danger">{r.error_message}</Typography.Text>
          </Tooltip>
        ) : r.status === 'SUCCEEDED' ? (
          <Typography.Text type="success">签发并绑定完成</Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '完成时间',
      dataIndex: 'finished_at',
      width: 170,
      render: (v?: string | null) => formatDateTime(v),
    },
  ]

  return (
    <div>
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="任务状态"
          allowClear
          style={{ width: 180 }}
          options={Object.entries(ACME_ORDER_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Button
          icon={<ReloadOutlined />}
          onClick={() => void ordersQuery.refetch()}
          loading={ordersQuery.isFetching}
        >
          刷新
        </Button>
      </Space>

      {ordersQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载申请与续约记录失败"
          description={ordersQuery.error instanceof ApiError ? ordersQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<AcmeOrderItem>
          storageKey={applicationId ? 'app-acme-orders' : 'acme-orders'}
          rowKey="id"
          loading={ordersQuery.isLoading}
          columns={columns}
          dataSource={ordersQuery.data?.items}
          scroll={{ x: 1100 }}
          pagination={{
            current: page,
            pageSize,
            total: ordersQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (t) => `共 ${t} 条`,
            onChange: (p, ps) => {
              setPage(p)
              setPageSize(ps)
            },
          }}
        />
      )}
    </div>
  )
}
