import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Empty,
  Input,
  InputNumber,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs, { type Dayjs } from 'dayjs'
import {
  apiGroupControlApi,
  type SharedDeviceGroup,
  type SharedDeviceQuery,
} from '../../api/apiGroupControl'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'
import SharedDeviceAccountsDrawer from './SharedDeviceAccountsDrawer'
import GroupControlTrend from './GroupControlTrend'

type DayRange = [Dayjs, Dayjs]

function defaultRange(): DayRange {
  return [dayjs().subtract(24, 'hour'), dayjs()]
}

function defaultQuery(range: DayRange): SharedDeviceQuery {
  return {
    start: range[0].toISOString(),
    end: range[1].toISOString(),
    min_accounts: 3,
    page: 1,
    page_size: 20,
  }
}

export default function ApiGroupControlPage() {
  const { message } = AntdApp.useApp()
  const [range, setRange] = useState<DayRange>(defaultRange)
  const [applicationId, setApplicationId] = useState<string>()
  const [deviceFingerprint, setDeviceFingerprint] = useState('')
  const [minAccounts, setMinAccounts] = useState(3)
  const [applied, setApplied] = useState<SharedDeviceQuery>(() =>
    defaultQuery(defaultRange()),
  )
  const [selectedGroup, setSelectedGroup] = useState<SharedDeviceGroup | null>(
    null,
  )

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'api-group-control-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })
  const groupsQuery = useQuery({
    queryKey: ['api-group-control-shared-devices', applied],
    queryFn: () => apiGroupControlApi.sharedDevices(applied),
  })

  const applyFilters = () => {
    const fingerprint = deviceFingerprint.trim().toLowerCase()
    if (fingerprint && !/^[0-9a-f]{32}$/.test(fingerprint)) {
      message.warning('设备指纹需为 32 位十六进制字符串')
      return
    }
    if (!range[0].isBefore(range[1])) {
      message.warning('开始时间必须早于结束时间')
      return
    }
    if (range[1].diff(range[0], 'millisecond') > 31 * 24 * 60 * 60 * 1000) {
      message.warning('查询时间范围不得超过 31 天')
      return
    }
    setSelectedGroup(null)
    setApplied({
      start: range[0].toISOString(),
      end: range[1].toISOString(),
      application_id: applicationId || undefined,
      device_fingerprint: fingerprint || undefined,
      min_accounts: minAccounts,
      page: 1,
      page_size: applied.page_size,
    })
  }

  const resetFilters = () => {
    const nextRange = defaultRange()
    setRange(nextRange)
    setApplicationId(undefined)
    setDeviceFingerprint('')
    setMinAccounts(3)
    setSelectedGroup(null)
    setApplied(defaultQuery(nextRange))
  }

  const columns: ColumnsType<SharedDeviceGroup> = [
    {
      title: '应用',
      dataIndex: 'application_name',
      width: 200,
      ellipsis: true,
      render: (value: string, record) => (
        <Typography.Text strong title={record.application_id}>
          {value || '历史应用'}
        </Typography.Text>
      ),
    },
    {
      title: '设备指纹',
      dataIndex: 'device_fingerprint',
      width: 200,
      render: (value: string) => (
        <Typography.Text code copyable={{ text: value }} title={value}>
          {value.slice(0, 16)}…
        </Typography.Text>
      ),
    },
    {
      title: '观察账号数',
      dataIndex: 'distinct_accounts',
      width: 120,
      align: 'right',
      render: (value: number) => (
        <Typography.Text strong>{value}</Typography.Text>
      ),
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
      title: '关联安全事件',
      dataIndex: 'event_count',
      width: 130,
      align: 'right',
    },
    {
      title: '涉及接口',
      dataIndex: 'endpoint_count',
      width: 100,
      align: 'right',
    },
    {
      title: '网关节点',
      dataIndex: 'gateway_node_count',
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
    {
      title: '操作',
      key: 'actions',
      width: 110,
      fixed: 'right',
      render: (_, record) => (
        <Button
          type="link"
          size="small"
          onClick={() => setSelectedGroup(record)}
        >
          主体关联
        </Button>
      ),
    },
  ]

  return (
    <Card title="群控分析">
      <Typography.Paragraph type="secondary">
        按应用与被动设备指纹汇总通过 JWT
        验证的可信账号，用于发现同设备多账号观察线索；不展示原始账号，不自动封禁。
      </Typography.Paragraph>
      <Space wrap size={12} style={{ marginBottom: 16 }}>
        <DatePicker.RangePicker
          aria-label="观测时间"
          allowClear={false}
          showTime
          value={range}
          onChange={(value) => {
            if (value?.[0] && value[1]) setRange([value[0], value[1]])
          }}
        />
        <Select
          aria-label="应用"
          value={applicationId}
          onChange={setApplicationId}
          allowClear
          showSearch
          optionFilterProp="label"
          loading={applicationsQuery.isLoading}
          placeholder="全部应用"
          style={{ width: 230 }}
          options={(applicationsQuery.data?.items ?? []).map((application) => ({
            value: application.id,
            label: `${application.name} (${application.code})`,
          }))}
        />
        <Input
          allowClear
          aria-label="设备指纹"
          placeholder="32 位设备指纹"
          maxLength={32}
          value={deviceFingerprint}
          onChange={(event) => setDeviceFingerprint(event.target.value)}
          onPressEnter={applyFilters}
          style={{ width: 260, fontFamily: 'monospace' }}
        />
        <Space size={4}>
          <Typography.Text type="secondary">最少账号</Typography.Text>
          <InputNumber
            aria-label="最少可信账号数"
            min={2}
            max={1000}
            precision={0}
            value={minAccounts}
            onChange={(value) => setMinAccounts(value ?? 3)}
          />
        </Space>
        <Button onClick={resetFilters}>重置</Button>
        <Button
          type="primary"
          loading={groupsQuery.isFetching}
          onClick={applyFilters}
        >
          查询
        </Button>
      </Space>
      <QueryErrorAlert
        error={applicationsQuery.error}
        message="加载应用列表失败"
      />
      <QueryErrorAlert
        error={groupsQuery.error}
        message="加载群控观察数据失败"
      />
      {groupsQuery.data?.partial && (
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          title="当前为安全事件观察范围"
          description="仅统计已采集的安全事件，不代表全量请求或实际活跃账号总数。被动设备指纹可能由多台设备共享，结果只作为排查线索，不是群控定罪证据。"
        />
      )}
      <GroupControlTrend query={applied} />
      <SmartTable<SharedDeviceGroup>
        storageKey="api-group-control-shared-devices"
        rowKey={(record) =>
          `${record.application_id}:${record.device_fingerprint}`
        }
        loading={groupsQuery.isLoading}
        columns={columns}
        dataSource={groupsQuery.data?.items ?? []}
        locale={{
          emptyText: (
            <Empty description="当前条件下暂无同设备多账号观察记录">
              <Typography.Text type="secondary">
                需启用 API 动态防护与 JWT
                信任验证，并产生包含可信主体和设备指纹的安全事件。
              </Typography.Text>
            </Empty>
          ),
        }}
        scroll={{ x: 1500 }}
        pagination={{
          current: applied.page,
          pageSize: applied.page_size,
          total: groupsQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (total) => `共 ${total} 个共享设备分组`,
          onChange: (page, pageSize) => {
            setApplied((previous) => ({
              ...previous,
              page: pageSize === previous.page_size ? page : 1,
              page_size: pageSize,
            }))
          },
        }}
      />
      {selectedGroup && (
        <SharedDeviceAccountsDrawer
          group={selectedGroup}
          query={applied}
          onClose={() => setSelectedGroup(null)}
        />
      )}
    </Card>
  )
}
