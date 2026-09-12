import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Form,
  Modal,
  Progress,
  Radio,
  Select,
  Space,
  Switch,
  Tabs,
  Typography,
} from 'antd'
import SmartTable from '../../components/SmartTable'
import ReportSchedulesPanel from './ReportSchedulesPanel'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, EyeOutlined, PlusOutlined, ReloadOutlined } from '@ant-design/icons'
import dayjs from 'dayjs'
import type { Dayjs } from 'dayjs'
import { ApiError } from '../../api/client'
import { reportsApi } from '../../api/reports'
import type { CreateReportBody } from '../../api/reports'
import { reportTemplatesApi } from '../../api/reportTemplates'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasAnyPermission, hasPermission } from '../../utils/permission'
import { CONTENT_SCOPE_META, REPORT_FORMAT_META, REPORT_STATUS_META, REPORT_TYPE_META, isTerminalReportStatus } from '../../utils/stage6'
import type { ReportContentScope, ReportJobItem, ReportType } from '../../types'

interface CreateFormValues {
  report_type: ReportType
  content_scope: ReportContentScope
  include_api_assets?: boolean
  page_orientation?: 'P' | 'L'
  custom_range?: [Dayjs, Dayjs] | null
  application_ids?: string[]
  template_id?: string
  format: 'html' | 'pdf' | 'docx'
}

/** 周期单元格：起止时间 */
function PeriodCell({ record }: { record: ReportJobItem }) {
  return (
    <Typography.Text style={{ fontSize: 12 }}>
      {dayjs(record.time_range_start).format('YYYY-MM-DD')} ~ {dayjs(record.time_range_end).format('YYYY-MM-DD')}
    </Typography.Text>
  )
}

/** 报告任务：创建（类型/周期/应用/模板/格式）+ 进度轮询 + 预览/下载/重试/删除 */
export default function ReportsPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const permissions = user?.permissions
  const canCreate = hasPermission(permissions, 'reports.create')
  const canDownload = hasAnyPermission(permissions, ['reports.download', 'reports.download_audit'])
  const canDeleteOwn = hasPermission(permissions, 'reports.delete_own')
  /** reports.delete_all：删除任意用户报告（管理）；行内删除与批量删除的显隐都受它升级 */
  const canDeleteAll = hasPermission(permissions, 'reports.delete_all')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [typeFilter, setTypeFilter] = useState<string>()
  const [statusFilter, setStatusFilter] = useState<string>()
  const [createOpen, setCreateOpen] = useState(false)
  const [previewId, setPreviewId] = useState<string | null>(null)
  const [detailRecord, setDetailRecord] = useState<ReportJobItem | null>(null)
  const [form] = Form.useForm<CreateFormValues>()

  const listQuery = useQuery({
    queryKey: ['reports', typeFilter, statusFilter, page, pageSize],
    queryFn: () =>
      reportsApi.list({ report_type: typeFilter, status: statusFilter, page, page_size: pageSize }),
    // 存在非终态任务时轮询进度
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((r) => !isTerminalReportStatus(r.status)) ? 3000 : false,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<ReportJobItem>({
    remove: (id) => reportsApi.remove(id),
    invalidateKeys: [['reports']],
    entityName: '报表',
    canDelete: canDeleteOwn || canDeleteAll,
    // 仅 delete_own 时他人报告不可勾选（后端逐条 403），与行内删除按钮显隐口径一致
    rowDisabled: (record) => !(canDeleteAll || (canDeleteOwn && user?.id === record.requested_by)),
  })

  const templatesQuery = useQuery({
    queryKey: ['report-templates', 'all-for-report'],
    queryFn: () => reportTemplatesApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen,
  })

  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-report'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: createOpen,
    retry: false,
  })

  const previewQuery = useQuery({
    queryKey: ['reports', 'preview', previewId],
    queryFn: () => reportsApi.preview(previewId!),
    enabled: previewId !== null,
  })

  const invalidate = () => void queryClient.invalidateQueries({ queryKey: ['reports'] })
  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createMutation = useMutation({
    mutationFn: (body: CreateReportBody) => reportsApi.create(body),
    onSuccess: () => {
      message.success('报告任务已创建，正在后台生成')
      setCreateOpen(false)
      form.resetFields()
      invalidate()
    },
    onError,
  })

  const retryMutation = useMutation({
    mutationFn: (id: string) => reportsApi.retry(id),
    onSuccess: () => {
      message.success('已重新提交生成任务')
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => reportsApi.remove(id),
    onSuccess: () => {
      message.success('报告已删除')
      invalidate()
    },
    onError,
  })

  const submitCreate = (values: CreateFormValues) => {
    const body: CreateReportBody = {
      report_type: values.report_type,
      content_scope: values.content_scope,
      include_api_assets: values.content_scope !== 'WAF' ? values.include_api_assets : undefined,
      page_orientation: values.page_orientation,
      format: values.format,
      application_ids: values.application_ids?.length ? values.application_ids : undefined,
      template_id: values.template_id || undefined,
    }
    if (values.report_type === 'CUSTOM') {
      if (!values.custom_range?.[0] || !values.custom_range?.[1]) {
        message.error('自定义报告必须选择时间范围')
        return
      }
      body.start_time = values.custom_range[0].toISOString()
      body.end_time = values.custom_range[1].toISOString()
    }
    createMutation.mutate(body)
  }

  const confirmDelete = (record: ReportJobItem) => {
    modal.confirm({
      title: '删除确认',
      content: `确定删除报告「${record.report_no || record.id}」吗？删除后报告文件将一并清除，不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMutation.mutate(record.id),
    })
  }

  const columns: ColumnsType<ReportJobItem> = [
    {
      title: '编号',
      dataIndex: 'report_no',
      width: 180,
      ellipsis: true,
      render: (v: string, record) => v || record.id.slice(0, 8),
    },
    {
      title: '类型',
      dataIndex: 'report_type',
      width: 150,
      render: (v: string, record) => (
        <Space size={4}>
          <StatusTag value={v} map={REPORT_TYPE_META} />
          {record.content_scope && record.content_scope !== 'WAF_API' && (
            <StatusTag value={record.content_scope} map={CONTENT_SCOPE_META} />
          )}
        </Space>
      ),
    },
    { title: '统计周期', key: 'period', width: 190, render: (_, r) => <PeriodCell record={r} /> },
    {
      title: '格式',
      dataIndex: 'file_format',
      width: 80,
      render: (v: string) => <StatusTag value={v} map={REPORT_FORMAT_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={REPORT_STATUS_META} />,
    },
    {
      title: '进度',
      dataIndex: 'progress',
      width: 140,
      render: (v: number, record) =>
        isTerminalReportStatus(record.status) ? (
          <Progress
            percent={record.status === 'SUCCESS' ? 100 : v}
            size="small"
            status={record.status === 'SUCCESS' ? 'success' : record.status === 'FAILED' ? 'exception' : 'normal'}
          />
        ) : (
          <Progress percent={v} size="small" status="active" />
        ),
    },
    {
      title: '创建时间',
      dataIndex: 'requested_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 240,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {record.status === 'SUCCESS' && record.file_format === 'html' && (
            <Button type="link" size="small" icon={<EyeOutlined />} onClick={() => setPreviewId(record.id)}>
              预览
            </Button>
          )}
          {record.status === 'SUCCESS' && canDownload && (
            <Button
              type="link"
              size="small"
              icon={<DownloadOutlined />}
              onClick={() => window.open(reportsApi.downloadUrl(record.id), '_blank')}
            >
              下载
            </Button>
          )}
          {record.status === 'FAILED' && canCreate && (
            <Button
              type="link"
              size="small"
              icon={<ReloadOutlined />}
              loading={retryMutation.isPending && retryMutation.variables === record.id}
              onClick={() => retryMutation.mutate(record.id)}
            >
              重试
            </Button>
          )}
          {record.status === 'FAILED' && record.failure_message && (
            <Typography.Text type="danger" style={{ fontSize: 12 }} ellipsis={{ tooltip: record.failure_message }}>
              {record.failure_message}
            </Typography.Text>
          )}
          {(canDeleteAll || (canDeleteOwn && user?.id === record.requested_by)) && (
            <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const jobsTab = (
    <>
      <Space style={{ marginBottom: 16, width: '100%', justifyContent: 'space-between' }} wrap>
        <Space wrap>
          <Select
            placeholder="报告类型"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(REPORT_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
            onChange={(v) => {
              setTypeFilter(v)
              setPage(1)
            }}
          />
          <Select
            placeholder="状态"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(REPORT_STATUS_META).map(([value, meta]) => ({ value, label: meta.label }))}
            onChange={(v) => {
              setStatusFilter(v)
              setPage(1)
            }}
          />
          {batchDeleteButton}
        </Space>
        {canCreate && (
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setCreateOpen(true)}>
            创建报告
          </Button>
        )}
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载报告任务失败" />
      ) : (
        <SmartTable<ReportJobItem>
          storageKey="reports"
          rowKey="id"
          rowSelection={rowSelection}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1300 }}
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
    </>
  )

  return (
    <Card>
      <Tabs
        items={[
          { key: 'jobs', label: '报告任务', children: jobsTab },
          { key: 'schedules', label: '定时报告', children: <ReportSchedulesPanel /> },
        ]}
      />

      <Modal
        title="创建报告"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMutation.isPending}
        destroyOnHidden
      >
        <Form<CreateFormValues>
          form={form}
          layout="vertical"
          initialValues={{ report_type: 'DAILY', content_scope: 'WAF_API', page_orientation: 'P', format: 'html' }}
          onFinish={submitCreate}
        >
          <Form.Item name="report_type" label="报告类型" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(REPORT_TYPE_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
          </Form.Item>
          <Form.Item name="content_scope" label="内容范围（API 部分按应用范围过滤）" rules={[{ required: true }]}>
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
                  tooltip="开启后报告附全部 API 资产列表（最多 500 条，按命中次数排序）"
                >
                  <Switch />
                </Form.Item>
              )
            }
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(prev, cur) => prev.report_type !== cur.report_type}>
            {({ getFieldValue }) =>
              getFieldValue('report_type') === 'CUSTOM' && (
                <Form.Item
                  name="custom_range"
                  label="统计时间范围"
                  rules={[{ required: true, message: '自定义报告必须选择时间范围' }]}
                >
                  <DatePicker.RangePicker showTime style={{ width: '100%' }} />
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
          <Form.Item name="format" label="导出格式" rules={[{ required: true }]}>
            <Radio.Group
              options={Object.entries(REPORT_FORMAT_META).map(([value, meta]) => ({ value, label: meta.label }))}
              optionType="button"
            />
          </Form.Item>
        </Form>
      </Modal>

      <Modal
        title="报告预览"
        open={previewId !== null}
        onCancel={() => setPreviewId(null)}
        footer={null}
        width={900}
        destroyOnHidden
      >
        {previewQuery.isError ? (
          <QueryErrorAlert error={previewQuery.error} message="加载报告预览失败" />
        ) : previewQuery.data ? (
          // sandbox 隔离预览内容，防止报告 HTML 注入影响管理平台
          <iframe
            title="报告预览"
            sandbox=""
            srcDoc={previewQuery.data}
            style={{ width: '100%', height: 560, border: '1px solid #f0f0f0', borderRadius: 4 }}
          />
        ) : (
          <Typography.Text type="secondary">加载中…</Typography.Text>
        )}
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="报告任务详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
