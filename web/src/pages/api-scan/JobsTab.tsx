import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Form,
  Modal,
  Progress,
  Select,
  Space,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  API_SCAN_PROBE_SETS,
  apiScanApi,
  type ApiScanAuthorization,
  type ApiScanJob,
} from '../../api/apiScan'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  authorizationState,
  isTerminalJobStatus,
  SCAN_JOB_STATUS_META,
  SCAN_PROBE_SET_META,
  splitProbeSets,
} from './meta'

interface JobFormValues {
  target_id: string
  authorization_id: string
  probe_set?: string[]
}

/**
 * 扫描任务 Tab：任务列表（进行中轮询刷新）、发起任务/启动/停止（api_scan.manage）、紧急停止（api_scan.execute）。
 */
export default function JobsTab() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_scan.manage')
  // 紧急停止副作用含吊销授权（revoke 超集），服务端挂 api_scan.execute，显隐同口径
  const canExecute = hasPermission(permissions, 'api_scan.execute')

  const [targetFilter, setTargetFilter] = useState<string | undefined>()
  const [statusFilter, setStatusFilter] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [createOpen, setCreateOpen] = useState(false)
  const [detailRecord, setDetailRecord] = useState<ApiScanJob | null>(null)
  const [form] = Form.useForm<JobFormValues>()
  /** 建任务表单当前选中目标（联动授权单选项） */
  const formTargetId = Form.useWatch('target_id', form)
  /** 建任务表单当前选中授权单（联动探针集可选范围） */
  const formAuthorizationId = Form.useWatch('authorization_id', form)

  /** 目标选项（过滤与建任务共用；建任务只允许 ENABLED 目标，后端强校验） */
  const targetsQuery = useQuery({
    queryKey: ['api-scan-targets', 'options'],
    queryFn: () => apiScanApi.listTargets({ page: 1, page_size: 100 }),
  })
  const targetItems = targetsQuery.data?.items ?? []
  const targetNameById = new Map(targetItems.map((t) => [t.id, t.name]))
  const targetOptions = targetItems.map((t) => ({ value: t.id, label: t.name }))

  const listQuery = useQuery({
    queryKey: ['api-scan-jobs', targetFilter, statusFilter, page, pageSize],
    queryFn: () =>
      apiScanApi.listJobs({ target_id: targetFilter, status: statusFilter, page, page_size: pageSize }),
    // 存在非终态任务时轮询进度
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((j) => !isTerminalJobStatus(j.status)) ? 3000 : false,
  })

  /** 建任务弹窗：选中目标的授权单（仅有效授权可选，后端同样强校验） */
  const authorizationsQuery = useQuery({
    queryKey: ['api-scan-authorizations', 'options', formTargetId],
    queryFn: () =>
      apiScanApi.listAuthorizations(formTargetId as string, { page: 1, page_size: 100 }),
    enabled: createOpen && formTargetId !== undefined,
  })
  const activeAuthorizations = (authorizationsQuery.data?.items ?? []).filter((a) =>
    authorizationState(a).active,
  )
  const selectedAuthorization = activeAuthorizations.find((a) => a.id === formAuthorizationId)
  /** 探针集可选范围：授权画像非空时收敛到画像内，否则全量词表 */
  const probeSetChoices = selectedAuthorization
    ? splitProbeSets(selectedAuthorization.test_profile)
    : API_SCAN_PROBE_SETS
  const probeSetOptions = (probeSetChoices.length > 0 ? probeSetChoices : API_SCAN_PROBE_SETS).map(
    (s) => ({ value: s, label: `${SCAN_PROBE_SET_META[s] ?? s}（${s}）` }),
  )

  const invalidateJobs = () => void qc.invalidateQueries({ queryKey: ['api-scan-jobs'] })

  const createMut = useMutation({
    mutationFn: (v: JobFormValues) =>
      apiScanApi.createJob({
        target_id: v.target_id,
        authorization_id: v.authorization_id,
        ...(v.probe_set && v.probe_set.length > 0 ? { probe_set: v.probe_set.join(',') } : {}),
      }),
    onSuccess: () => {
      message.success('任务已创建（待启动）')
      setCreateOpen(false)
      invalidateJobs()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '创建任务失败'),
  })

  const startMut = useMutation({
    mutationFn: (id: string) => apiScanApi.startJob(id),
    onSuccess: () => {
      message.success('任务已启动')
      invalidateJobs()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '启动失败'),
  })

  const stopMut = useMutation({
    mutationFn: (id: string) => apiScanApi.stopJob(id),
    onSuccess: () => {
      message.success('任务已停止（授权保留，可再次发起）')
      invalidateJobs()
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '停止失败'),
  })

  const emergencyMut = useMutation({
    mutationFn: (id: string) => apiScanApi.emergencyStopJob(id),
    onSuccess: (r) => {
      message.success(`紧急停止完成：授权已吊销，联动停止 ${r.stopped_jobs} 个任务`)
      invalidateJobs()
      // 紧急停止撤销授权：授权列表一并刷新
      void qc.invalidateQueries({ queryKey: ['api-scan-authorizations'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '紧急停止失败'),
  })

  const confirmStop = (record: ApiScanJob) => {
    modal.confirm({
      title: '停止扫描任务',
      content: '确定停止该任务吗？任务将置为已停止，授权保留，可重新发起新任务。',
      onOk: () => stopMut.mutate(record.id),
    })
  }

  /**
   * 启动前二次确认：展示目标、授权单、探针集与限流参数。
   * 授权单详情用于展示限流数值；拉取失败/未找到时如实提示（不静默吞错、不阻断确认）。
   */
  const confirmStart = async (record: ApiScanJob) => {
    let authorization: ApiScanAuthorization | undefined
    let authorizationLoadFailed = false
    try {
      const res = await apiScanApi.listAuthorizations(record.target_id, { page: 1, page_size: 100 })
      authorization = res.items.find((a) => a.id === record.authorization_id)
    } catch {
      authorizationLoadFailed = true
    }
    const probeSets = splitProbeSets(record.probe_set)
    modal.confirm({
      title: '启动扫描任务',
      content: (
        <Space direction="vertical" size={4} style={{ width: '100%' }}>
          <Typography.Text>
            目标：{targetNameById.get(record.target_id) ?? record.target_id}
          </Typography.Text>
          <Typography.Text>授权单：#{record.authorization_id.slice(0, 8)}</Typography.Text>
          <Typography.Text>
            探针集：
            {probeSets.length > 0
              ? probeSets.map((s) => SCAN_PROBE_SET_META[s] ?? s).join('、')
              : '授权画像默认'}
          </Typography.Text>
          {authorization ? (
            <Typography.Text>
              限流：QPS ≤ {authorization.max_qps}，并发 ≤ {authorization.max_concurrency}
            </Typography.Text>
          ) : (
            <Typography.Text type="warning">
              {authorizationLoadFailed
                ? '授权单详情加载失败，限流参数以后端授权为准'
                : '未找到授权单详情，限流参数以后端授权为准'}
            </Typography.Text>
          )}
          <Typography.Text>
            启动后引擎将按授权 allowlist、时间窗与限流参数向目标发送真实探针流量，确定启动吗？
          </Typography.Text>
        </Space>
      ),
      okText: '确认启动',
      onOk: () => startMut.mutate(record.id),
    })
  }

  const confirmEmergencyStop = (record: ApiScanJob) => {
    modal.confirm({
      title: '紧急停止',
      content:
        '紧急停止用于目标系统出现异常等紧急情况：将立即停止本任务、吊销关联授权，并联动停止该授权下全部在跑任务。确定继续吗？',
      okButtonProps: { danger: true },
      onOk: () => emergencyMut.mutate(record.id),
    })
  }

  const columns: ColumnsType<ApiScanJob> = [
    {
      title: '任务',
      dataIndex: 'id',
      width: 110,
      render: (v: string) => (
        <Tooltip title={v}>
          <Typography.Text code>#{v.slice(0, 8)}</Typography.Text>
        </Tooltip>
      ),
    },
    {
      title: '目标',
      dataIndex: 'target_id',
      width: 150,
      ellipsis: true,
      render: (v: string) => targetNameById.get(v) ?? v,
    },
    {
      title: '探针集',
      dataIndex: 'probe_set',
      width: 190,
      ellipsis: true,
      render: (v: string) => {
        const sets = splitProbeSets(v)
        return sets.length > 0 ? (
          <Tooltip title={sets.join('、')}>
            <Typography.Text style={{ fontSize: 12 }}>
              {sets.map((s) => SCAN_PROBE_SET_META[s] ?? s).join('、')}
            </Typography.Text>
          </Tooltip>
        ) : (
          <Typography.Text type="secondary">授权画像默认</Typography.Text>
        )
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 95,
      render: (v: string) => <StatusTag value={v} map={SCAN_JOB_STATUS_META} />,
    },
    {
      title: '进度',
      key: 'progress',
      width: 210,
      render: (_, record) => {
        const p = record.progress
        const percent = p && p.total > 0 ? Math.round((p.done / p.total) * 100) : 0
        return (
          <Space size={8} style={{ width: '100%' }}>
            <Progress
              percent={percent}
              size="small"
              style={{ width: 90, margin: 0 }}
              status={record.status === 'FAILED' ? 'exception' : undefined}
            />
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {p ? `${p.done}/${p.total} · 发现 ${p.findings} · 错误 ${p.errors}` : '-'}
            </Typography.Text>
          </Space>
        )
      },
    },
    {
      title: '最近错误',
      key: 'last_error',
      width: 160,
      ellipsis: true,
      render: (_, record) =>
        record.progress?.last_error ? (
          <Tooltip title={record.progress.last_error}>
            <Typography.Text type="danger" style={{ fontSize: 12 }}>
              {record.progress.last_error}
            </Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    {
      title: '完成时间',
      dataIndex: 'finished_at',
      width: 165,
      render: (v?: string | null) => formatDateTime(v),
    },
    ...(canManage || canExecute
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 200,
            fixed: 'right' as const,
            render: (_: unknown, record: ApiScanJob) => {
              const terminal = isTerminalJobStatus(record.status)
              const canStart = record.status === 'PENDING' || record.status === 'PAUSED'
              return (
                <Space size={0} wrap>
                  {canManage ? (
                    <>
                      <Button
                        type="link"
                        size="small"
                        disabled={!canStart}
                        onClick={() => void confirmStart(record)}
                      >
                        启动
                      </Button>
                      <Button
                        type="link"
                        size="small"
                        disabled={terminal}
                        onClick={() => confirmStop(record)}
                      >
                        停止
                      </Button>
                    </>
                  ) : null}
                  {canExecute ? (
                    <Button
                      type="link"
                      size="small"
                      danger
                      disabled={terminal}
                      onClick={() => confirmEmergencyStop(record)}
                    >
                      紧急停止
                    </Button>
                  ) : null}
                </Space>
              )
            },
          },
        ]
      : []),
  ]

  return (
    <>
      <QueryErrorAlert error={listQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="目标"
          allowClear
          showSearch
          optionFilterProp="label"
          style={{ width: 200 }}
          value={targetFilter}
          options={targetOptions}
          onChange={(v) => {
            setTargetFilter(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 130 }}
          value={statusFilter}
          options={Object.entries(SCAN_JOB_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatusFilter(v)
            setPage(1)
          }}
        />
        {canManage ? (
          <Button
            type="primary"
            onClick={() => {
              form.resetFields()
              setCreateOpen(true)
            }}
          >
            发起任务
          </Button>
        ) : null}
      </Space>
      <SmartTable<ApiScanJob>
        storageKey="api-scan-jobs"
        rowKey="id"
        loading={listQuery.isLoading}
        columns={columns}
        dataSource={listQuery.data?.items ?? []}
        scroll={{ x: 1400 }}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
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
        title="发起扫描任务"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => form.submit()}
        confirmLoading={createMut.isPending}
        destroyOnHidden
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="任务创建后为「待启动」，需在列表手动启动；引擎严格按授权的 allowlist、时间窗与限流参数执行。"
        />
        <Form<JobFormValues>
          form={form}
          layout="vertical"
          onFinish={(v) => createMut.mutate(v)}
        >
          <Form.Item
            name="target_id"
            label="扫描目标"
            rules={[{ required: true, message: '请选择扫描目标' }]}
          >
            <Select
              placeholder="仅启用状态的目标可发起（后端强校验）"
              showSearch
              optionFilterProp="label"
              options={targetOptions}
              loading={targetsQuery.isLoading}
              onChange={() => form.setFieldsValue({ authorization_id: undefined, probe_set: [] })}
            />
          </Form.Item>
          <Form.Item
            name="authorization_id"
            label="扫描授权单"
            rules={[{ required: true, message: '请选择有效授权单' }]}
          >
            <Select
              placeholder={formTargetId ? '选择有效授权单' : '请先选择扫描目标'}
              disabled={!formTargetId}
              loading={authorizationsQuery.isLoading}
              notFoundContent={
                formTargetId && !authorizationsQuery.isLoading ? '该目标暂无有效授权' : undefined
              }
              options={activeAuthorizations.map((a) => ({
                value: a.id,
                label: `#${a.id.slice(0, 8)} · 截止 ${formatDateTime(a.expires_at)} · QPS ${a.max_qps}`,
              }))}
              onChange={() => form.setFieldsValue({ probe_set: [] })}
            />
          </Form.Item>
          <Form.Item name="probe_set" label="探针集（留空 = 授权画像默认）">
            <Select
              mode="multiple"
              allowClear
              placeholder={
                selectedAuthorization && splitProbeSets(selectedAuthorization.test_profile).length > 0
                  ? '仅可选授权画像内探针集'
                  : '选择探针集'
              }
              disabled={!formAuthorizationId}
              options={probeSetOptions}
            />
          </Form.Item>
        </Form>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="扫描任务详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </>
  )
}
