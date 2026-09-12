import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  DatePicker,
  Drawer,
  Form,
  Input,
  Modal,
  Radio,
  Select,
  Space,
  Tag,
  TimePicker,
  Typography,
} from 'antd'
import { DeleteOutlined, PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { ColumnsType } from 'antd/es/table'
import SmartTable from '../../components/SmartTable'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import { ApiError } from '../../api/client'
import { systemAlertsApi } from '../../api/systemAlerts'
import { formatDateTime } from '../../utils/format'
import { ALERT_TYPE_META, COMPONENT_NAME_META } from '../../utils/stage6'
import type { SystemAlertMaintenanceWindow, SystemAlertMaintenanceWindowCreateInput } from '../../types'

interface CreateFormValues {
  name: string
  description?: string
  scope: 'ALL' | 'CUSTOM'
  alert_types?: string[]
  components?: string[]
  recurrence: 'ONCE' | 'DAILY'
  range: [dayjs.Dayjs, dayjs.Dayjs]
  dailyRange?: [dayjs.Dayjs, dayjs.Dayjs]
}

/** 本地时刻转 UTC 日内分钟（0~1439），与服务端判定口径一致 */
function toUtcMinute(d: dayjs.Dayjs) {
  const date = d.toDate()
  return date.getUTCHours() * 60 + date.getUTCMinutes()
}

/** UTC 日内分钟（0~1439）格式化为 HH:mm */
function formatMinute(minute?: number | null) {
  if (minute === null || minute === undefined) return '-'
  const h = Math.floor(minute / 60)
  const m = minute % 60
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`
}

/** 维护窗口管理抽屉：列表 + 创建/删除（阶段6 §11.5） */
export default function MaintenanceWindowsDrawer({
  open,
  canManage,
  onClose,
}: {
  open: boolean
  canManage: boolean
  onClose: () => void
}) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [createOpen, setCreateOpen] = useState(false)
  const [form] = Form.useForm<CreateFormValues>()
  const watchScope = Form.useWatch('scope', form)
  const watchRecurrence = Form.useWatch('recurrence', form)

  const listQuery = useQuery({
    queryKey: ['system-alerts', 'maintenance-windows'],
    queryFn: () => systemAlertsApi.listMaintenanceWindows(),
    enabled: open,
  })

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['system-alerts', 'maintenance-windows'] })
  }
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (input: SystemAlertMaintenanceWindowCreateInput) => systemAlertsApi.createMaintenanceWindow(input),
    onSuccess: () => {
      message.success('维护窗口已创建')
      setCreateOpen(false)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => systemAlertsApi.deleteMaintenanceWindow(id),
    onSuccess: () => {
      message.success('维护窗口已删除')
      invalidate()
    },
    onError,
  })

  const submitCreate = async () => {
    const values = await form.validateFields()
    const input: SystemAlertMaintenanceWindowCreateInput = {
      name: values.name.trim(),
      description: values.description?.trim() || undefined,
      scope: values.scope,
      recurrence: values.recurrence,
      starts_at: values.range[0].toISOString(),
      ends_at: values.range[1].toISOString(),
    }
    if (values.scope === 'CUSTOM') {
      input.alert_types = values.alert_types ?? []
      input.components = values.components ?? []
    }
    if (values.recurrence === 'DAILY' && values.dailyRange) {
      // 每日时段按 UTC 日内分钟提交（与服务端判定口径一致）
      input.daily_start_minute = toUtcMinute(values.dailyRange[0])
      input.daily_end_minute = toUtcMinute(values.dailyRange[1])
    }
    createMutation.mutate(input)
  }

  const columns: ColumnsType<SystemAlertMaintenanceWindow> = [
    { title: '名称', dataIndex: 'name', width: 140, ellipsis: true },
    {
      title: '范围',
      dataIndex: 'scope',
      width: 150,
      render: (v: string, record) =>
        v === 'ALL' ? (
          <Tag>全部告警</Tag>
        ) : (
          <Space size={4} wrap>
            {(record.alert_types ?? []).map((t) => (
              <Tag key={t}>{ALERT_TYPE_META[t]?.label ?? t}</Tag>
            ))}
            {(record.components ?? []).map((c) => (
              <Tag key={c} color="blue">
                {COMPONENT_NAME_META[c] ?? c}
              </Tag>
            ))}
          </Space>
        ),
    },
    {
      title: '周期',
      dataIndex: 'recurrence',
      width: 150,
      render: (v: string, record) =>
        v === 'DAILY' ? (
          <span>
            每日 {formatMinute(record.daily_start_minute)}~{formatMinute(record.daily_end_minute)}（UTC）
          </span>
        ) : (
          <Tag>一次性</Tag>
        ),
    },
    {
      title: '起止时间',
      key: 'range',
      width: 240,
      render: (_, record) => (
        <span>
          {formatDateTime(record.starts_at)}
          <br />
          {formatDateTime(record.ends_at)}
        </span>
      ),
    },
    {
      title: '已抑制',
      dataIndex: 'suppressed_count',
      width: 110,
      render: (v: number, record) => (
        <span>
          {v} 次
          {record.last_suppressed_at && (
            <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12 }}>
              最近 {formatDateTime(record.last_suppressed_at)}
            </Typography.Text>
          )}
        </span>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      render: (_, record) =>
        canManage && (
          <Button
            type="link"
            size="small"
            danger
            icon={<DeleteOutlined />}
            onClick={() =>
              modal.confirm({
                title: '删除维护窗口',
                content: `确定删除维护窗口「${record.name}」吗？删除后窗口内被抑制的告警将恢复评估。`,
                onOk: () => deleteMutation.mutate(record.id),
              })
            }
          >
            删除
          </Button>
        ),
    },
  ]

  return (
    <Drawer
      title="告警维护窗口"
      open={open}
      onClose={onClose}
      width={860}
      destroyOnHidden
      extra={
        canManage && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            新建窗口
          </Button>
        )
      }
    >
      <Typography.Paragraph type="secondary" style={{ marginBottom: 16 }}>
        维护窗口生效期间，匹配的告警评估将被抑制（不新建、不合并），抑制次数计入「已抑制」列可观测。
      </Typography.Paragraph>
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载维护窗口失败" />
      ) : (
        <SmartTable<SystemAlertMaintenanceWindow>
          storageKey="system-alert-maintenance-windows"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          pagination={false}
        />
      )}

      <Modal
        title="新建维护窗口"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => void submitCreate()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
        width={560}
      >
        <Form<CreateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ scope: 'ALL', recurrence: 'ONCE' }}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[{ required: true, whitespace: true, message: '请输入名称' }, { max: 100 }]}
          >
            <Input placeholder="如：网关升级维护" maxLength={100} />
          </Form.Item>
          <Form.Item name="description" label="描述" rules={[{ max: 500 }]}>
            <Input.TextArea rows={2} maxLength={500} placeholder="可选" />
          </Form.Item>
          <Form.Item
            name="range"
            label="生效起止时间"
            rules={[{ required: true, message: '请选择起止时间' }]}
          >
            <DatePicker.RangePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="recurrence" label="周期" rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { value: 'ONCE', label: '一次性' },
                { value: 'DAILY', label: '每日时段' },
              ]}
            />
          </Form.Item>
          {watchRecurrence === 'DAILY' && (
            <Form.Item
              name="dailyRange"
              label="每日时段（UTC，结束早于开始表示跨零点）"
              rules={[{ required: true, message: '请选择每日时段' }]}
            >
              <TimePicker.RangePicker format="HH:mm" style={{ width: '100%' }} />
            </Form.Item>
          )}
          <Form.Item name="scope" label="作用范围" rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { value: 'ALL', label: '全部告警' },
                { value: 'CUSTOM', label: '按类型/组件' },
              ]}
            />
          </Form.Item>
          {watchScope === 'CUSTOM' && (
            <>
              <Form.Item name="alert_types" label="告警类型（留空表示不限制该维度）">
                <Select
                  mode="multiple"
                  allowClear
                  showSearch
                  options={Object.entries(ALERT_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
                />
              </Form.Item>
              <Form.Item name="components" label="组件（留空表示不限制该维度）">
                <Select
                  mode="multiple"
                  allowClear
                  options={Object.entries(COMPONENT_NAME_META).map(([value, label]) => ({ value, label }))}
                />
              </Form.Item>
            </>
          )}
        </Form>
      </Modal>
    </Drawer>
  )
}
