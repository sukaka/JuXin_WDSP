import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { WarningOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { temporaryBlocksApi } from '../../api/temporaryBlocks'
import { applicationsApi } from '../../api/applications'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  TEMP_BLOCK_RELEASE_TYPE_META,
  TEMP_BLOCK_STATUS_META,
  TEMP_BLOCK_TRIGGER_META,
} from '../../utils/stage5'
import type { ApplicationItem, TemporaryBlockItem } from '../../types'

interface Filters {
  status?: string
  client_ip?: string
  application_id?: string
}

interface ExtendFormValues {
  new_expires_at: dayjs.Dayjs
}

/** 应用列：ID → 名称（编码），未加载完成时回退显示 ID 前缀 */
function appLabel(appId: string | null | undefined, apps: ApplicationItem[] | undefined): string {
  if (!appId) return '全局'
  const app = apps?.find((a) => a.id === appId)
  return app ? `${app.name}（${app.code}）` : appId.slice(0, 8)
}

export default function TemporaryBlocksPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'temporary_blocks.manage')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [extending, setExtending] = useState<TemporaryBlockItem | null>(null)
  const [extendForm] = Form.useForm<ExtendFormValues>()

  const listQuery = useQuery({
    queryKey: ['temporary-blocks', filters, page, pageSize],
    queryFn: () => temporaryBlocksApi.list({ ...filters, page, page_size: pageSize }),
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-temp-blocks'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['temporary-blocks'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const releaseMutation = useMutation({
    mutationFn: (id: string) => temporaryBlocksApi.release(id),
    onSuccess: () => {
      message.success('封禁已解除')
      void invalidate()
    },
    onError,
  })

  const extendMutation = useMutation({
    mutationFn: ({ id, newExpiresAt }: { id: string; newExpiresAt: string }) =>
      temporaryBlocksApi.extend(id, newExpiresAt),
    onSuccess: () => {
      message.success('封禁已延长')
      setExtending(null)
      extendForm.resetFields()
      void invalidate()
    },
    onError,
  })

  const convertMutation = useMutation({
    mutationFn: (id: string) => temporaryBlocksApi.convertToPermanent(id),
    onSuccess: (data) => {
      message.success(data.message || '已转换为永久封禁规则')
      void invalidate()
      void queryClient.invalidateQueries({ queryKey: ['access-rules'] })
    },
    onError,
  })

  const confirmRelease = (record: TemporaryBlockItem) => {
    modal.confirm({
      title: '解封确认',
      content: `确定解除对 ${record.client_ip} 的临时封禁吗？解封后该地址立即恢复访问。`,
      onOk: () => releaseMutation.mutate(record.id),
    })
  }

  const confirmConvert = (record: TemporaryBlockItem) => {
    modal.confirm({
      title: '高风险操作确认：转永久封禁',
      icon: <WarningOutlined />,
      content: `确定将 ${record.client_ip} 转为永久封禁吗？系统将创建一条永久 DENY 规则并发布到网关，该地址将被长期阻断，只能在「IP黑白名单」中手工删除。请确认该地址确属恶意来源。`,
      okText: '确认转永久',
      okButtonProps: { danger: true },
      onOk: () => convertMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<TemporaryBlockItem> = [
    {
      title: '客户端IP',
      dataIndex: 'client_ip',
      width: 140,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '应用',
      dataIndex: 'application_id',
      width: 180,
      ellipsis: true,
      render: (v: string | null) => appLabel(v, appsQuery.data?.items),
    },
    {
      title: '触发类型',
      dataIndex: 'trigger_type',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={TEMP_BLOCK_TRIGGER_META} />,
    },
    {
      title: '开始时间',
      dataIndex: 'block_started_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '到期时间',
      dataIndex: 'block_expires_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 130,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={TEMP_BLOCK_STATUS_META} />
          {record.release_type && (
            <Tag>{TEMP_BLOCK_RELEASE_TYPE_META[record.release_type]?.label ?? record.release_type}</Tag>
          )}
        </Space>
      ),
    },
    { title: '命中数', dataIndex: 'hit_count', width: 80, align: 'right' },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, record) =>
        canManage && record.status === 'ACTIVE' ? (
          <Space size={0}>
            <Button type="link" size="small" onClick={() => confirmRelease(record)}>
              解封
            </Button>
            <Button
              type="link"
              size="small"
              onClick={() => {
                setExtending(record)
                extendForm.resetFields()
              }}
            >
              延期
            </Button>
            <Button type="link" size="small" danger onClick={() => confirmConvert(record)}>
              转永久
            </Button>
          </Space>
        ) : null,
    },
  ]

  return (
    <Card title="临时封禁">
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 150 }}
          options={Object.entries(TEMP_BLOCK_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, status: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="应用"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 220 }}
          loading={appsQuery.isLoading}
          options={(appsQuery.data?.items ?? []).map((a) => ({
            value: a.id,
            label: `${a.name}（${a.code}）`,
          }))}
          onChange={(v) => {
            setFilters((f) => ({ ...f, application_id: v }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="客户端IP"
          allowClear
          style={{ width: 180 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, client_ip: v || undefined }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载临时封禁失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <Table<TemporaryBlockItem>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1250 }}
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
      )}

      <Modal
        title={`延长封禁 ${extending?.client_ip ?? ''}`}
        open={extending !== null}
        onCancel={() => setExtending(null)}
        onOk={() => extendForm.submit()}
        confirmLoading={extendMutation.isPending}
        destroyOnHidden
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          当前到期时间：{formatDateTime(extending?.block_expires_at)}；新到期时间必须晚于当前时间。
        </Typography.Paragraph>
        <Form<ExtendFormValues>
          form={extendForm}
          layout="vertical"
          onFinish={(values) => {
            if (extending) {
              extendMutation.mutate({
                id: extending.id,
                newExpiresAt: values.new_expires_at.toISOString(),
              })
            }
          }}
        >
          <Form.Item
            name="new_expires_at"
            label="新的到期时间"
            rules={[
              { required: true, message: '请选择新的到期时间' },
              {
                validator: (_, v: dayjs.Dayjs | undefined) =>
                  v && v.isAfter(dayjs())
                    ? Promise.resolve()
                    : Promise.reject(new Error('新到期时间必须晚于当前时间')),
              },
            ]}
          >
            <DatePicker
              showTime
              style={{ width: '100%' }}
              disabledDate={(d) => d.isBefore(dayjs().startOf('day'))}
            />
          </Form.Item>
        </Form>
      </Modal>
    </Card>
  )
}
