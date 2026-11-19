import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  apiAIOpsApi,
  type ApiAISchedule,
  type ApiAIScheduleBody,
  type ApiAITaskType,
} from '../../api/apiAIOps'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { AI_RUN_STATUS_META, AI_TASK_TYPE_META, taskTypeLabel, validateCronExpr } from './meta'
import RunsPanel from './RunsPanel'

interface ScheduleFormValues {
  task_type: ApiAITaskType
  name: string
  cron_expr: string
  enabled: boolean
}

/**
 * AI 运营计划 Tab：计划列表（任务类型/cron/启停/下次运行/上次状态）、
 * 新建编辑弹窗（cron 前端预检 + 后端权威校验）、立即执行（同步返回执行结果）、
 * 行内「运行记录」抽屉、行内删除与勾选批量删除。写操作需 api_ai.execute。
 */
export default function SchedulesTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canExecute = hasPermission(permissions, 'api_ai.execute')

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [modalOpen, setModalOpen] = useState(false)
  const [editing, setEditing] = useState<ApiAISchedule | null>(null)
  const [runsOf, setRunsOf] = useState<ApiAISchedule | null>(null)
  const [form] = Form.useForm<ScheduleFormValues>()

  /** 任务类型词表（接口为空/失败时回退本地词表，保证弹窗可用） */
  const taskTypesQuery = useQuery({
    queryKey: ['api-ai-ops-task-types'],
    queryFn: () => apiAIOpsApi.listTaskTypes(),
  })
  const taskTypeOptions = (taskTypesQuery.data && taskTypesQuery.data.length > 0
    ? taskTypesQuery.data.map((t) => ({ value: t.task_type, label: `${t.name}（${t.task_type}）`, description: t.description }))
    : Object.entries(AI_TASK_TYPE_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）`, description: meta.description })))

  const listQuery = useQuery({
    queryKey: ['api-ai-ops-schedules', page, pageSize],
    queryFn: () => apiAIOpsApi.listSchedules({ page, page_size: pageSize }),
  })

  const invalidateSchedules = () => void qc.invalidateQueries({ queryKey: ['api-ai-ops-schedules'] })
  const errText = (e: unknown, fallback: string) => (e instanceof ApiError ? e.message : fallback)

  const saveMut = useMutation({
    mutationFn: (v: ScheduleFormValues) => {
      const body: ApiAIScheduleBody = {
        task_type: v.task_type,
        name: v.name.trim(),
        cron_expr: v.cron_expr.trim(),
        ...(editing ? {} : { enabled: v.enabled }),
      }
      return editing ? apiAIOpsApi.updateSchedule(editing.id, body) : apiAIOpsApi.createSchedule(body)
    },
    onSuccess: () => {
      message.success(editing ? '计划已更新' : '计划已创建')
      setModalOpen(false)
      setEditing(null)
      invalidateSchedules()
    },
    onError: (e: unknown) => message.error(errText(e, '保存计划失败')),
  })

  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? apiAIOpsApi.enableSchedule(id) : apiAIOpsApi.disableSchedule(id),
    onSuccess: (schedule) => {
      message.success(schedule.enabled ? `计划「${schedule.name}」已启用` : `计划「${schedule.name}」已停用`)
      invalidateSchedules()
    },
    onError: (e: unknown) => message.error(errText(e, '启停操作失败')),
  })

  const runMut = useMutation({
    mutationFn: (id: string) => apiAIOpsApi.runSchedule(id),
    onSuccess: (run) => {
      // 立即执行同步返回执行记录：直接反馈本次结果，并刷新计划与执行记录
      if (run.status === 'SUCCESS') {
        message.success('立即执行完成，报告已生成（展开运行记录查看）')
      } else if (run.status === 'FAILED') {
        message.warning('立即执行结束：任务失败，请在运行记录中查看摘要')
      } else {
        message.info('立即执行已提交，任务执行中')
      }
      invalidateSchedules()
      void qc.invalidateQueries({ queryKey: ['api-ai-ops-runs'] })
    },
    onError: (e: unknown) => message.error(errText(e, '立即执行失败')),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiAIOpsApi.deleteSchedule(id),
    onSuccess: () => {
      message.success('计划已删除')
      invalidateSchedules()
    },
    onError: (e: unknown) => message.error(errText(e, '删除计划失败')),
  })

  /** 勾选 + 批量删除（后端仅单删接口，逐条 fan-out；与行内删除同权限 api_ai.execute） */
  const { rowSelection, batchDeleteButton } = useBatchDelete<ApiAISchedule>({
    remove: (id) => apiAIOpsApi.deleteSchedule(id),
    invalidateKeys: [['api-ai-ops-schedules']],
    entityName: 'AI 调度',
    canDelete: canExecute,
  })

  /** 行内删除：二次确认后调用单删接口 */
  const confirmDelete = (record: ApiAISchedule) => {
    modal.confirm({
      title: '删除计划',
      content: `确定删除计划「${record.name}」吗？删除后不可恢复。`,
      okButtonProps: { danger: true },
      onOk: () => deleteMut.mutate(record.id),
    })
  }

  /** 熔断态计划重新启用：明示将重置熔断计数，确认后才调 enable 接口 */
  const confirmReenable = (record: ApiAISchedule) => {
    modal.confirm({
      title: '重新启用（重置熔断计数）',
      content: (
        <div>
          <Typography.Paragraph style={{ marginBottom: 8 }}>
            计划「{record.name}」已连续失败 {record.consecutive_failures} 次并熔断
            {record.circuit_opened_at ? `（熔断时间：${formatDateTime(record.circuit_opened_at)}）` : ''}
            。
          </Typography.Paragraph>
          {record.circuit_reason ? (
            <Typography.Paragraph type="secondary" style={{ marginBottom: 8 }}>
              熔断原因：{record.circuit_reason}
            </Typography.Paragraph>
          ) : null}
          <Typography.Paragraph style={{ marginBottom: 0 }}>
            重新启用将重置连续失败计数与熔断状态，并按 cron 表达式恢复排期。确定继续吗？
          </Typography.Paragraph>
        </div>
      ),
      onOk: () => toggleMut.mutate({ id: record.id, enabled: true }),
    })
  }

  /** 启停开关变更：熔断态下启用需先确认（重置熔断计数） */
  const onToggle = (record: ApiAISchedule, checked: boolean) => {
    if (checked && record.circuit_opened_at) {
      confirmReenable(record)
      return
    }
    toggleMut.mutate({ id: record.id, enabled: checked })
  }

  const openCreate = () => {
    setEditing(null)
    form.resetFields()
    setModalOpen(true)
  }

  const openEdit = (record: ApiAISchedule) => {
    setEditing(record)
    form.resetFields()
    form.setFieldsValue({
      task_type: record.task_type,
      name: record.name,
      cron_expr: record.cron_expr,
      enabled: record.enabled,
    })
    setModalOpen(true)
  }

  const columns: ColumnsType<ApiAISchedule> = [
    {
      title: '计划名称',
      dataIndex: 'name',
      width: 180,
      ellipsis: true,
      render: (v: string) => <Typography.Text strong>{v}</Typography.Text>,
    },
    {
      title: '任务类型',
      dataIndex: 'task_type',
      width: 150,
      render: (v: string) => (
        <Tooltip title={AI_TASK_TYPE_META[v]?.description}>
          <Typography.Text>{taskTypeLabel(v)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: 'cron 表达式',
      dataIndex: 'cron_expr',
      width: 140,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '启用',
      dataIndex: 'enabled',
      width: 80,
      render: (v: boolean, record) => (
        <Switch
          checked={v}
          disabled={!canExecute || toggleMut.isPending}
          onChange={(checked) => onToggle(record, checked)}
        />
      ),
    },
    {
      title: '连续失败',
      key: 'consecutive_failures',
      width: 110,
      render: (_, record) => (
        <Space size={4}>
          <Typography.Text type={record.consecutive_failures > 0 ? 'danger' : undefined}>
            {record.consecutive_failures ?? 0}
          </Typography.Text>
          {record.circuit_opened_at ? (
            <Tooltip
              title={
                <>
                  <div>熔断原因：{record.circuit_reason || '-'}</div>
                  <div>熔断时间：{formatDateTime(record.circuit_opened_at)}</div>
                </>
              }
            >
              <Tag color="red">已熔断</Tag>
            </Tooltip>
          ) : null}
        </Space>
      ),
    },
    {
      title: '下次运行',
      dataIndex: 'next_run_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '上次状态',
      dataIndex: 'last_status',
      width: 100,
      render: (v: string, record) =>
        v ? (
          <Tooltip title={record.last_error || undefined}>
            <span>
              <StatusTag value={v} map={AI_RUN_STATUS_META} />
            </span>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '上次运行',
      dataIndex: 'last_run_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 220,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          {canExecute ? (
            <>
              <Button type="link" size="small" onClick={() => openEdit(record)}>
                编辑
              </Button>
              <Button
                type="link"
                size="small"
                loading={runMut.isPending && runMut.variables === record.id}
                onClick={() => runMut.mutate(record.id)}
              >
                立即执行
              </Button>
              <Button type="link" size="small" danger onClick={() => confirmDelete(record)}>
                删除
              </Button>
            </>
          ) : null}
          <Button type="link" size="small" onClick={() => setRunsOf(record)}>
            运行记录
          </Button>
        </Space>
      ),
    },
  ]

  return (
    <>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Typography.Text type="secondary">
          任务只产出报告与建议，不变更业务；总开关见系统设置中的定时任务总开关。
        </Typography.Text>
        {canExecute ? (
          <Button type="primary" onClick={openCreate}>
            新建计划
          </Button>
        ) : null}
        {batchDeleteButton}
      </Space>
      <SmartTable<ApiAISchedule>
        storageKey="api-ai-ops-schedules"
        rowKey="id"
        rowSelection={rowSelection}
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1310 }}
        onRow={(record) => ({
          onDoubleClick: () => setRunsOf(record),
          style: { cursor: 'pointer' },
        })}
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

      <Modal
        title={editing ? `编辑计划：${editing.name}` : '新建运营计划'}
        open={modalOpen}
        onCancel={() => {
          setModalOpen(false)
          setEditing(null)
        }}
        onOk={() => form.submit()}
        confirmLoading={saveMut.isPending}
        destroyOnHidden
      >
        <Form<ScheduleFormValues>
          form={form}
          layout="vertical"
          initialValues={{ enabled: false }}
          onFinish={(v) => saveMut.mutate(v)}
        >
          <Form.Item
            name="task_type"
            label="任务类型"
            rules={[{ required: true, message: '请选择任务类型' }]}
            extra={editing ? '任务类型创建后不可变更' : undefined}
          >
            <Select
              placeholder="选择内置任务类型"
              disabled={editing !== null}
              options={taskTypeOptions}
              loading={taskTypesQuery.isLoading}
            />
          </Form.Item>
          <Form.Item
            name="name"
            label="计划名称"
            rules={[
              { required: true, message: '请输入计划名称' },
              { max: 128, message: '名称不超过 128 字符' },
            ]}
          >
            <Input placeholder="如：每日资产变化摘要" maxLength={128} />
          </Form.Item>
          <Form.Item
            name="cron_expr"
            label="cron 表达式"
            rules={[
              {
                validator: (_, value: string) => {
                  const err = validateCronExpr(value ?? '')
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
            extra="五段（分 时 日 月 周）或 @hourly/@daily 等宏；启用后立即按表达式排期"
          >
            <Input placeholder="如：0 7 * * * 或 @daily" allowClear />
          </Form.Item>
          {editing === null ? (
            <Form.Item name="enabled" label="创建后启用" valuePropName="checked">
              <Switch />
            </Form.Item>
          ) : null}
        </Form>
      </Modal>

      <Drawer
        title={runsOf ? `运行记录：${runsOf.name}` : '运行记录'}
        open={runsOf !== null}
        onClose={() => setRunsOf(null)}
        width={860}
        destroyOnHidden
      >
        {runsOf ? (
          <Space direction="vertical" size={12} style={{ display: 'flex' }}>
            {runsOf.circuit_opened_at ? (
              <Alert
                type="error"
                showIcon
                message="计划已熔断"
                description={
                  <>
                    连续失败 {runsOf.consecutive_failures} 次，熔断时间{' '}
                    {formatDateTime(runsOf.circuit_opened_at)}。
                    {runsOf.circuit_reason ? `熔断原因：${runsOf.circuit_reason}。` : ''}
                    重新启用计划将重置熔断计数。
                  </>
                }
              />
            ) : null}
            <RunsPanel scheduleId={runsOf.id} />
          </Space>
        ) : null}
      </Drawer>
    </>
  )
}
