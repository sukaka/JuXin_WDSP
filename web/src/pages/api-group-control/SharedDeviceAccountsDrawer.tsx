import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Drawer, Empty, Segmented, Spin, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  apiGroupControlApi,
  type SharedDeviceAccount,
  type SharedDeviceGroup,
  type SharedDeviceQuery,
} from '../../api/apiGroupControl'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import SharedDeviceRelationshipGraph from './SharedDeviceRelationshipGraph'

type AccountsView = 'list' | 'graph'

export default function SharedDeviceAccountsDrawer({
  group,
  query,
  onClose,
}: {
  group: SharedDeviceGroup
  query: SharedDeviceQuery
  onClose: () => void
}) {
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [view, setView] = useState<AccountsView>('list')
  const accountsQuery = useQuery({
    queryKey: [
      'api-group-control-shared-device-accounts',
      group.application_id,
      group.device_fingerprint,
      query.start,
      query.end,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiGroupControlApi.sharedDeviceAccounts({
        start: query.start,
        end: query.end,
        application_id: group.application_id,
        device_fingerprint: group.device_fingerprint,
        page,
        page_size: pageSize,
      }),
  })
  const accounts = accountsQuery.data?.items ?? []

  const columns: ColumnsType<SharedDeviceAccount> = [
    {
      title: '可信主体 HMAC 引用',
      dataIndex: 'principal_ref',
      width: 230,
      render: (value: string) => (
        <Typography.Text code copyable={{ text: value }} title={value}>
          {value.slice(0, 16)}…
        </Typography.Text>
      ),
    },
    {
      title: '关联安全事件',
      dataIndex: 'event_count',
      width: 130,
      align: 'right',
    },
    {
      title: '群控观察信号',
      dataIndex: 'signal_count',
      width: 130,
      align: 'right',
      render: (value: number) => (
        <Tag color={value > 0 ? 'orange' : 'default'}>{value}</Tag>
      ),
    },
    {
      title: '涉及接口',
      dataIndex: 'endpoint_count',
      width: 100,
      align: 'right',
    },
    {
      title: '首次观测',
      dataIndex: 'first_seen_at',
      width: 175,
      render: (value: string) => formatDateTime(value),
    },
    {
      title: '最近观测',
      dataIndex: 'last_seen_at',
      width: 175,
      render: (value: string) => formatDateTime(value),
    },
  ]

  return (
    <Drawer title="共享设备主体关联" open onClose={onClose} size="large">
      <Typography.Paragraph>
        <Typography.Text strong>
          {group.application_name || '历史应用'}
        </Typography.Text>
      </Typography.Paragraph>
      <Typography.Paragraph type="secondary">
        设备指纹{' '}
        <Typography.Text code>{group.device_fingerprint}</Typography.Text>
      </Typography.Paragraph>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="仅展示脱敏主体引用"
        description="主体引用为应用隔离的 HMAC 指纹，不是原始账号。统计仅覆盖已采集安全事件，不证明这些主体存在协同行为。"
      />
      <Segmented<AccountsView>
        value={view}
        onChange={setView}
        options={[
          { value: 'list', label: '明细列表' },
          { value: 'graph', label: '关系图' },
        ]}
        style={{ marginBottom: 16 }}
      />
      <QueryErrorAlert error={accountsQuery.error} message="加载主体关联失败" />
      {view === 'list' ? (
        <SmartTable<SharedDeviceAccount>
          rowKey="principal_ref"
          loading={accountsQuery.isLoading}
          columns={columns}
          dataSource={accounts}
          locale={{ emptyText: '当前设备与时间范围内暂无可信主体关联记录' }}
          scroll={{ x: 940 }}
          pagination={{
            current: page,
            pageSize,
            total: accountsQuery.data?.total ?? 0,
            showSizeChanger: true,
            showTotal: (total) => `共 ${total} 个可信主体`,
            onChange: (nextPage, nextPageSize) => {
              setPage(nextPageSize === pageSize ? nextPage : 1)
              setPageSize(nextPageSize)
            },
          }}
        />
      ) : (
        <>
          <Typography.Paragraph type="secondary">
            关系图仅展示当前第 {page} 页（每页 {pageSize}{' '}
            条）的可信主体，不自动拼接其他页。
          </Typography.Paragraph>
          {accountsQuery.isLoading ? (
            <Spin tip="正在加载当前页主体关联">
              <div style={{ minHeight: 120 }} />
            </Spin>
          ) : accountsQuery.error ? null : accounts.length === 0 ? (
            <Empty description="当前页暂无可信主体，无法生成关系图" />
          ) : (
            <SharedDeviceRelationshipGraph group={group} accounts={accounts} />
          )}
        </>
      )}
    </Drawer>
  )
}
