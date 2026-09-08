import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Form,
  Input,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  TimePicker,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import { ApiError } from '../../api/client'
import { reportSchedulesApi } from '../../api/reportSchedules'
import type { SaveReportScheduleBody } from '../../api/reportSchedules'
import { reportTemplatesApi } from '../../api/reportTemplates'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { CONTENT_SCOPE_META, REPORT_FORMAT_META, REPORT_TYPE_META } from '../../utils/stage6'
import type { ReportScheduleItem } from '../../types'

interface ScheduleFormValues {
  name: string
  report_type: string
  content_scope: string
  application_ids?: string[]
  template_id?: string
  file_format: string
  include_api_assets?: boolean
  page_orientation?: 'P' | 'L'
  time_of_day: Dayjs
  day_of_week: number
  day_of_month: number
  send_email: boolean
  emails?: string[]
  enabled: boolean
}

const WEEKDAY_OPTIONS = [
  { value: 1, label: '周一' },
  { value: 2, label: '周二' },
  { value: 3, label: '周三' },
  { value: 4, label: '周四' },
  { value: 5, label: '周五' },
  { value: 6, label: '周六' },
  { value: 7, label: '周日' },
]

const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/

/** 周期描述（与后端 ScheduleDescription 同口径） */
function scheduleDesc(s: ReportScheduleItem): string {
  const weekNames = ['', '一', '二', '三', '四', '五', '六', '日']
  if (s.report_type === 'DAILY') return `每天 ${s.time_of_day} UTC`
  if (s.report_type === 'WEEKLY') return `每周${weekNames[s.day_of_week] ?? s.day_of_week} ${s.time_of_day} UTC`
  if (s.report_type === 'MONTHLY') return `每月${s.day_of_month}号 ${s.time_of_day} UTC`
  return s.report_type
}

/** 定时报告计划：CRUD + 启停 + 立即执行 + 邮件发送状态 */
export default function ReportSchedulesPanel() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const canManage = hasPermission(user?.permissions, 'reports.create')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editOpen, setEditOpen] = useState(false)
  const [editing, setEditing] = useState<ReportScheduleItem | null>(null)
  const [detailRecord, setDetailRecord] = useState<ReportScheduleItem | null>(null)
  const [form] = Form.useForm<ScheduleFormValues>()

  const listQuery = useQuery({
    queryKey: ['report-schedules', page, pageSize],
    queryFn: () => reportSchedulesApi.list({ page, page_size: pageSize }),
  })

  const templatesQuery = useQuery({
    queryKey: ['report-templates', 'all-for-schedule'],
    queryFn: () => reportTemplatesApi.list({ page: 1, page_size: 100 }),
    enabled: editOpen,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-schedule'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: editOpen,
    retry: false,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['report-schedules'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const saveMutation = useMutation({
    mutationFn: async (body: SaveReportScheduleBody) => {
      if (editing) {
        await reportSchedulesApi.update(editing.id, body)
        return null
      }
      return reportSchedulesApi.create(body)
    },
    onSuccess: () => {
      message.success(editing ? '计划已更新' : '计划已创建')
      setEditOpen(false)
      setEditing(null)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportSchedulesApi.remove(id),
    onSuccess: () => {
      message.success('计划已删除')
      invalidate()
    },
    onError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ReportScheduleItem>({
    remove: (id) => reportSchedulesApi.remove(id),
    invalidateKeys: [['report-schedules']],
    entityName: '报表调度',
    canDelete: canManage,
  })

  const runNowMutation = useMutation({
    mutationFn: (id: string) => reportSchedulesApi.runNow(id),
    onSuccess: () => {
      message.success('已加入执行队列')
      invalidate()
    },
    onError,
  })

  const toggleMutation = useMutation({
    mutationFn: (record: ReportScheduleItem) =>
      reportSchedulesApi.update(record.id, {
        name: record.name,
        report_type: record.report_type,
        content_scope: record.content_scope ?? 'WAF_API',
        application_ids: record.application_ids ?? undefined,
        template_id: record.template_id ?? undefined,
        file_format: record.file_format,
        include_api_assets: record.include_api_assets,
        page_orientation: record.page_orientation ?? 'P',
        time_of_day: record.time_of_day,
        day_of_week: record.day_of_week,
        day_of_month: record.day_of_month,
        send_email: record.send_email,
        emails: record.emails ?? undefined,
        enabled: !record.enabled,
      }),
    onSuccess: invalidate,
    onError,
  })

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setEditOpen(true)
  }

  const openEdit = (record: ReportScheduleItem) => {
    setEditing(record)
    form.setFieldsValue({
      name: record.name,
      report_type: record.report_type,
      content_scope: record.content_scope ?? 'WAF_API',
      application_ids: record.application_ids ?? undefined,
      template_id: record.template_id ?? undefined,
      file_format: record.file_format,
      include_api_assets: record.include_api_assets ?? false,
      page_orientation: record.page_orientation ?? 'P',
      time_of_day: dayjs(record.time_of_day, 'HH:mm'),
      day_of_week: record.day_of_week,
      day_of_month: record.day_of_month,
      send_email: record.send_email,
      emails: record.emails ?? [],
      enabled: record.enabled,
    })
    setEditOpen(true)
  }

  const submit = (values: ScheduleFormValues) => {
    const body: SaveReportScheduleBody = {
      name: values.name,
      report_type: values.report_type,
      content_scope: values.content_scope,
      application_ids: values.application_ids?.length ? values.application_ids : undefined,
      template_id: values.template_id || undefined,
      file_format: values.file_format,
      include_api_assets: values.content_scope !== 'WAF' ? values.include_api_assets : undefined,
      page_orientation: values.page_orientation,
      time_of_day: values.time_of_day.format('HH:mm'),
      day_of_week: values.day_of_week,
      day_of_month: values.day_of_month,
      send_email: values.send_email,
      emails: values.send_email ? values.emails : undefined,
      enabled: values.enabled,
    }
    if (values.send_email) {
      const invalid = (values.emails ?? []).filter((e) => !EMAIL_RE.test(e))
      if (invalid.length > 0) {
        message.error(`邮箱格式无效：${invalid[0]}`)
        return
      }
    }
    saveMutation.mutate(body)
  }

  const confirmDelete = (record: ReportScheduleItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除定时计划「${record.name}」吗？已生成的报告不受影响。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<ReportScheduleItem> = [
    { title: '名称', dataIndex: 'name', width: 150, ellipsis: true },
    {
      title: '类型',
      dataIndex: 'report_type',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={REPORT_TYPE_META} />,
    },
    {
      title: '内容范围',
      dataIndex: 'content_scope',
      width: 110,
      render: (v: string) => (v ? <StatusTag value={v} map={CONTENT_SCOPE_META} /> : '-'),
    },
    { title: '周期', key: 'schedule', width: 170, render: (_, r) => scheduleDesc(r) },
    {
      title: '格式',
      dataIndex: 'file_format',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={REPORT_FORMAT_META} />,
    },
    {
      title: '邮件',
      key: 'emails',
      width: 90,
      render: (_, r) =>
        r.send_email ? (
          <Tooltip title={(r.emails ?? []).join('、')}>
            <Tag color="blue">{r.emails?.length ?? 0} 个邮箱</Tag>
          </Tooltip>
        ) : (
          <Tag>不发送</Tag>
        ),
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 70,
      render: (v: boolean, r) => (
        <Switch
          size="small"
          checked={v}
          disabled={!canManage || toggleMutation.isPending}
          onChange={() => toggleMutation.mutate(r)}
        />
      ),
    },
    {
      title: '下次执行',
      dataIndex: 'next_run_at',
      width: 160,
      render: (v: string | null, r) => (r.enabled && v ? formatDateTime(v) : '-'),
    },
    {
      title: '最近邮件',
      key: 'last_email',
      width: 110,
      render: (_, r) => {
        if (!r.last_email_status) return '-'
        if (r.last_email_status === 'SENT') return <Tag color="green">已发送</Tag>
        return (
          <Tooltip title={r.last_email_error}>
            <Tag color="red">发送失败</Tag>
          </Tooltip>
        )
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 190,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {canManage && (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                loading={runNowMutation.isPending && runNowMutation.variables === record.id}
                onClick={() => runNowMutation.mutate(record.id)}
              >
                立即执行
              </Button>
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            </>
          )}
        </Space>
      ),
    },
  ]

  return (
    <>
      <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }} wrap>
        <Typography.Text type="secondary">
          按计划自动创建报告（UTC 时刻）；邮件发送需先在「系统告警 → 通知渠道」配置 SMTP 邮件渠道
        </Typography.Text>
        {canManage && (
          <Space wrap>
            {batchDeleteButton}
            <Button type="primary" icon={<PlusOutlined />} onClick={openCreate}>
              新建定时计划
            </Button>
          </Space>
        )}
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载定时计划失败" />
      ) : (
        <Table<ReportScheduleItem>
          rowKey="id"
          rowSelection={rowSelection}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
          size="middle"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1280 }}
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
        title={editing ? '编辑定时计划' : '新建定时计划'}
        open={editOpen}
        onCancel={() => {
          setEditOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={saveMutation.isPending}
        destroyOnHidden
        width={560}
      >
        <Form<ScheduleFormValues>
          form={form}
          layout="vertical"
          initialValues={{
            report_type: 'WEEKLY',
            content_scope: 'WAF_API',
            file_format: 'pdf',
            page_orientation: 'P',
            time_of_day: dayjs('02:00', 'HH:mm'),
            day_of_week: 1,
            day_of_month: 1,
            send_email: false,
            enabled: true,
          }}
          onFinish={submit}
        >
          <Form.Item name="name" label="计划名称" rules={[{ required: true, max: 64, message: '必填，不超过 64 字符' }]}>
            <Input placeholder="如：安全周报（管理层）" />
          </Form.Item>
          <Form.Item name="report_type" label="报告类型" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(REPORT_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
          </Form.Item>
          <Form.Item name="content_scope" label="内容范围" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(CONTENT_SCOPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.content_scope !== cur.content_scope}>
            {({ getFieldValue }) =>
              getFieldValue('content_scope') !== 'WAF' && (
                <Form.Item
                  name="include_api_assets"
                  label="API 资产清单（全量，含用途与影子/僵尸标记）"
                  valuePropName="checked"
                >
                  <Switch />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item name="application_ids" label="应用范围（留空为全部应用）">
            <Select
              mode="multiple"
              allowClear
              showSearch
              optionFilterProp="label"
              placeholder="全部应用"
              loading={appsQuery.isLoading}
              options={(appsQuery.data?.items ?? []).map((a) => ({ value: a.id, label: `${a.name}（${a.code}）` }))}
            />
          </Form.Item>
          <Form.Item name="template_id" label="报告模板（留空使用默认模板）">
            <Select
              allowClear
              placeholder="默认模板"
              loading={templatesQuery.isLoading}
              options={(templatesQuery.data?.items ?? []).map((t) => ({ value: t.id, label: t.name }))}
            />
          </Form.Item>
          <Form.Item name="page_orientation" label="纸张方向（PDF/Word 生效）" rules={[{ required: true }]}>
            <Radio.Group
              options={[
                { value: 'P', label: '竖向 A4' },
                { value: 'L', label: '横向 A4' },
              ]}
              optionType="button"
            />
          </Form.Item>
          <Form.Item name="file_format" label="导出格式" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(REPORT_FORMAT_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
          </Form.Item>
          <Space size="large" wrap>
            <Form.Item name="time_of_day" label="执行时刻（UTC）" rules={[{ required: true }]}>
              <TimePicker format="HH:mm" minuteStep={5} allowClear={false} />
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.report_type !== cur.report_type}>
              {({ getFieldValue }) =>
                getFieldValue('report_type') === 'WEEKLY' && (
                  <Form.Item name="day_of_week" label="每周期" rules={[{ required: true }]}>
                    <Select style={{ width: 100 }} options={WEEKDAY_OPTIONS} />
                  </Form.Item>
                )
              }
            </Form.Item>
            <Form.Item noStyle shouldUpdate={(prev, cur) => prev.report_type !== cur.report_type}>
              {({ getFieldValue }) =>
                getFieldValue('report_type') === 'MONTHLY' && (
                  <Form.Item name="day_of_month" label="每月日期（1-28）" rules={[{ required: true }]}>
                    <InputNumber min={1} max={28} style={{ width: 100 }} />
                  </Form.Item>
                )
              }
            </Form.Item>
          </Space>
          <Form.Item name="send_email" label="发送邮件" valuePropName="checked">
            <Switch />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.send_email !== cur.send_email}>
            {({ getFieldValue }) =>
              getFieldValue('send_email') && (
                <Form.Item
                  name="emails"
                  label="收件邮箱（回车添加，最多 10 个）"
                  rules={[{ required: true, message: '开启邮件发送时至少一个收件邮箱' }]}
                >
                  <Select mode="tags" placeholder="sec@example.com" open={false} suffixIcon={null} maxCount={10} />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item name="enabled" label="启用计划" valuePropName="checked">
            <Switch />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="定时计划详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
