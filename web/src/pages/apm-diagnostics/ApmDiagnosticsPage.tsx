import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  AutoComplete,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Drawer,
  Form,
  List,
  Modal,
  Popconfirm,
  Select,
  Slider,
  Space,
  Spin,
  Steps,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { apmApi, type ApmDiagnosticSessionBody } from '../../api/apm'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  APM_DIAG_AUDIT_ACTION_LABELS,
  APM_DIAG_STOP_REASON_LABELS,
  formatEnvironment,
} from '../../utils/i18nLabels'
import {
  APM_DIAGNOSTIC_CAPABILITY_META,
  APM_DIAGNOSTIC_STATUS_META,
  formatDiagnosticCountdown,
  formatPercent,
} from '../../utils/apm'
import type { ApmDiagnosticCapability, ApmDiagnosticSession } from '../../types'

/** 创建向导表单值（与 POST /apm/diagnostic-sessions 入参对齐） */
type WizardFormValues = ApmDiagnosticSessionBody

/** 每步提交前需要校验的字段（嵌套 namePath；第 4 步为 dry_run 预估展示，无表单字段） */
const STEP_FIELDS: (string | string[])[][] = [
  [
    ['scope', 'application_id'],
    ['scope', 'service'],
    ['scope', 'environment'],
    ['scope', 'instance_ids'],
  ],
  ['capabilities'],
  ['sampling_rate', 'duration_minutes'],
  [],
]

const ENVIRONMENT_OPTIONS = [
  { value: 'production', label: '生产（production）' },
  { value: 'staging', label: '预发布（staging）' },
  { value: 'testing', label: '测试（testing）' },
  { value: 'development', label: '开发（development）' },
]

/** ACTIVE 会话剩余时间倒计时：每 5 秒局部刷新显示（列表数据本身 30 秒轮询） */
function RemainingCountdown({ expiresAt }: { expiresAt: string }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 5000)
    return () => window.clearInterval(timer)
  }, [])
  return <Typography.Text>{formatDiagnosticCountdown(expiresAt, now)}</Typography.Text>
}

/** 深度诊断中心（权限 apm.diagnostics.manage）：会话列表（30 秒轮询）+ 分步创建向导（dry_run 预估后二次确认）
 *  + 详情 Drawer（全字段 + 关联审计）+ 全局 kill switch。设计依据：BUSINESS_PERFORMANCE_APM_DESIGN.md §6.3/§17.1/§21.2 */
export default function ApmDiagnosticsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [status, setStatus] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailId, setDetailId] = useState<string | null>(null)

  const [wizardOpen, setWizardOpen] = useState(false)
  const [step, setStep] = useState(0)
  const [ackRisk, setAckRisk] = useState(false)
  const [form] = Form.useForm<WizardFormValues>()
  const capabilitiesWatch: ApmDiagnosticCapability[] = Form.useWatch('capabilities', form) ?? []
  const samplingWatch: number | undefined = Form.useWatch('sampling_rate', form)
  const durationWatch: number | undefined = Form.useWatch('duration_minutes', form)
  const serviceWatch: string | undefined = Form.useWatch(['scope', 'service'], form)

  const listQuery = useQuery({
    queryKey: ['apm', 'diagnostic-sessions', status, page, pageSize],
    queryFn: () => apmApi.diagnosticSessions({ status, page, page_size: pageSize }),
    refetchInterval: 30000,
  })

  const detailQuery = useQuery({
    queryKey: ['apm', 'diagnostic-sessions', 'detail', detailId],
    queryFn: () => apmApi.diagnosticSession(detailId as string),
    enabled: detailId !== null,
  })

  // 向导选项数据源：应用清单 / APM 服务清单 / 实例（/apm/runtime，随已选 service 过滤），仅向导打开时拉取
  const applicationsQuery = useQuery({
    queryKey: ['applications', 'diagnostic-form-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: wizardOpen,
    retry: false,
  })
  const servicesQuery = useQuery({
    queryKey: ['apm', 'services', 'diagnostic-form-options'],
    queryFn: () =>
      apmApi.services({
        start_time: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        end_time: new Date().toISOString(),
        page: 1,
        page_size: 100,
      }),
    enabled: wizardOpen,
    retry: false,
  })
  const instancesQuery = useQuery({
    queryKey: ['apm', 'runtime', 'diagnostic-instance-options'],
    queryFn: () =>
      apmApi.runtime({
        start_time: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        end_time: new Date().toISOString(),
      }),
    enabled: wizardOpen,
    retry: false,
  })

  const onError = (e: unknown) => {
    // 409/参数校验等错误统一按 ApiError 透传后端消息（不静默吞错）
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const invalidateList = () =>
    void queryClient.invalidateQueries({ queryKey: ['apm', 'diagnostic-sessions'] })

  const dryRunMutation = useMutation({
    mutationFn: (body: ApmDiagnosticSessionBody) => apmApi.dryRunDiagnosticSession(body),
  })

  const createMutation = useMutation({
    mutationFn: (body: ApmDiagnosticSessionBody) => apmApi.createDiagnosticSession(body),
    onSuccess: () => {
      message.success('诊断会话已创建')
      closeWizard()
      invalidateList()
    },
    onError,
  })

  const stopMutation = useMutation({
    mutationFn: (id: string) => apmApi.stopDiagnosticSession(id),
    onSuccess: () => {
      message.success('诊断会话已停止')
      invalidateList()
    },
    onError,
  })

  const killSwitchMutation = useMutation({
    mutationFn: (enable: boolean) => apmApi.setDiagnosticKillSwitch(enable),
    onSuccess: (_data, enable) => {
      message.success(enable ? '全局熔断开关已开启' : '全局熔断开关已解除')
      invalidateList()
    },
    onError,
  })

  function closeWizard() {
    setWizardOpen(false)
    setStep(0)
    setAckRisk(false)
    form.resetFields()
    dryRunMutation.reset()
  }

  const wizardBody = (): ApmDiagnosticSessionBody => {
    const values = form.getFieldsValue(true) as WizardFormValues
    return {
      scope: values.scope,
      capabilities: values.capabilities,
      sampling_rate: values.sampling_rate,
      duration_minutes: values.duration_minutes,
    }
  }

  const handleNext = async () => {
    // 分步校验：onChange 触发的字段校验可能与本次 validateFields 并发，
    // antd 会以 { outOfDate: true, errorFields: [] } 拒绝较早的 Promise——这不是校验失败，重试即可
    let valid = false
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        await form.validateFields(STEP_FIELDS[step] as never)
        valid = true
        break
      } catch (e) {
        const err = e as { errorFields?: unknown[]; outOfDate?: boolean }
        if (err?.outOfDate && !err?.errorFields?.length) continue
        return
      }
    }
    if (!valid) return
    if (step === 2) {
      // 进入预估步：先 dry_run 拿预计开销，用户确认后方可正式创建（设计 §6.3 二次确认）
      setAckRisk(false)
      dryRunMutation.mutate(wizardBody())
    }
    setStep(step + 1)
  }

  const killSwitchOn = listQuery.data?.kill_switch_enabled === true
  const hasActive = (listQuery.data?.items ?? []).some((s) => s.status === 'ACTIVE')
  const overhead = dryRunMutation.data?.estimated_overhead

  const columns: ColumnsType<ApmDiagnosticSession> = [
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={APM_DIAGNOSTIC_STATUS_META} />,
    },
    {
      title: '范围',
      key: 'scope',
      width: 240,
      render: (_, r) => (
        <Space direction="vertical" size={0}>
          <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
            {r.scope?.service || '-'}
          </Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {formatEnvironment(r.scope?.environment)} · {r.scope?.instance_ids?.length ?? 0} 实例 · 应用{' '}
            {r.scope?.application_id || '-'}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '诊断能力',
      dataIndex: 'capabilities',
      width: 220,
      render: (caps: string[]) => (
        <Space size={4} wrap>
          {(caps ?? []).map((c) => {
            const meta = APM_DIAGNOSTIC_CAPABILITY_META[c]
            return (
              <Tag key={c} color={meta?.color} style={{ marginInlineEnd: 0 }}>
                {meta?.label ?? c}
              </Tag>
            )
          })}
        </Space>
      ),
    },
    {
      title: '采样率',
      dataIndex: 'sampling_rate',
      width: 80,
      render: (v: number) => formatPercent(v),
    },
    {
      title: '剩余时间',
      key: 'remaining',
      width: 110,
      render: (_, r) =>
        r.status === 'ACTIVE' ? <RemainingCountdown expiresAt={r.expires_at} /> : '-',
    },
    {
      title: '发起人 / 时间',
      key: 'created',
      width: 190,
      render: (_, r) => (
        <Space direction="vertical" size={0}>
          <Typography.Text style={{ fontSize: 12 }}>{r.created_by || '-'}</Typography.Text>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {formatDateTime(r.created_at)}
          </Typography.Text>
        </Space>
      ),
    },
    {
      title: '操作',
      key: 'actions',
      width: 150,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {record.status === 'ACTIVE' && (
            <Popconfirm
              title="提前停止诊断会话"
              description="停止后目标 Agent 将在 1 分钟内回到基线策略，已采集数据保留本会话 ID。确定停止吗？"
              okText="确认停止"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={() => stopMutation.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                提前停止
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  const detail = detailQuery.data

  return (
    <Card
      title="诊断中心"
      extra={
        <Space>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            30 秒自动刷新
          </Typography.Text>
          <Popconfirm
            title={killSwitchOn ? '解除全局熔断开关' : '开启全局熔断开关'}
            description={
              killSwitchOn
                ? '解除后将允许新建诊断会话。确定解除吗？'
                : '开启后将立即终止全部进行中的诊断会话，并拒绝新建任何诊断会话，直到手动解除。确定开启吗？'
            }
            okText={killSwitchOn ? '确认解除' : '确认开启'}
            okButtonProps={{ danger: true }}
            cancelText="取消"
            onConfirm={() => killSwitchMutation.mutate(!killSwitchOn)}
          >
            <Button danger type={killSwitchOn || hasActive ? 'primary' : 'default'}>
              {killSwitchOn ? '解除全局熔断开关' : '开启全局熔断开关'}
            </Button>
          </Popconfirm>
          <Button type="primary" onClick={() => setWizardOpen(true)} disabled={killSwitchOn}>
            新建诊断会话
          </Button>
        </Space>
      }
    >
      {killSwitchOn && (
        <Alert
          type="error"
          showIcon
          message="全局熔断开关已开启，新建会话被拒绝"
          description="全部进行中的诊断会话已被终止；解除右上角全局熔断开关后方可恢复诊断能力。"
          style={{ marginBottom: 16 }}
        />
      )}

      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="全部状态"
          allowClear
          style={{ width: 140 }}
          value={status}
          options={Object.entries(APM_DIAGNOSTIC_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载诊断会话列表失败" />
      ) : (
        <SmartTable<ApmDiagnosticSession>
          storageKey="apm-diagnostics"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1150 }}
          locale={{ emptyText: '暂无诊断会话，点击右上角「新建诊断会话」创建' }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailId(record.id),
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
      )}

      <Modal
        title="新建诊断会话"
        open={wizardOpen}
        onCancel={closeWizard}
        width={720}
        destroyOnHidden
        footer={
          <Space>
            <Button onClick={closeWizard}>取消</Button>
            {step > 0 && (
              <Button onClick={() => setStep(step - 1)} disabled={createMutation.isPending}>
                上一步
              </Button>
            )}
            {step < 3 && (
              <Button
                type="primary"
                onClick={() => void handleNext()}
                loading={step === 2 && dryRunMutation.isPending}
              >
                下一步
              </Button>
            )}
            {step === 3 && (
              <Button
                type="primary"
                disabled={!ackRisk || !overhead}
                loading={createMutation.isPending}
                onClick={() => createMutation.mutate(wizardBody())}
              >
                确认创建
              </Button>
            )}
          </Space>
        }
      >
        <Steps
          current={step}
          size="small"
          items={[
            { title: '范围' },
            { title: '诊断能力' },
            { title: '采样与时长' },
            { title: '预估与确认' },
          ]}
          style={{ marginBottom: 24 }}
        />
        <Form<WizardFormValues>
          form={form}
          layout="vertical"
          initialValues={{ sampling_rate: 0.5, duration_minutes: 15 }}
        >
          {/* 各步字段常驻挂载（隐藏而非卸载），保证跨步校验与值保留 */}
          <div style={{ display: step === 0 ? undefined : 'none' }}>
            <Form.Item
              name={['scope', 'application_id']}
              label="应用"
              rules={[{ required: true, message: '请选择应用' }]}
            >
              <Select
                placeholder="选择应用"
                showSearch
                optionFilterProp="label"
                loading={applicationsQuery.isLoading}
                options={(applicationsQuery.data?.items ?? []).map((a) => ({
                  value: a.id,
                  label: `${a.name}（${a.code}）`,
                }))}
              />
            </Form.Item>
            <Form.Item
              name={['scope', 'service']}
              label="服务"
              rules={[{ required: true, message: '请填写服务名' }]}
            >
              <AutoComplete
                placeholder="服务名（可从现有服务中选择）"
                options={(servicesQuery.data?.items ?? []).map((s) => ({
                  value: s.app,
                  label: `${s.name || s.app}（${s.app}）`,
                }))}
              />
            </Form.Item>
            <Form.Item
              name={['scope', 'environment']}
              label="环境"
              rules={[{ required: true, message: '请选择或填写环境' }]}
            >
              <AutoComplete placeholder="如 production" options={ENVIRONMENT_OPTIONS} />
            </Form.Item>
            <Form.Item
              name={['scope', 'instance_ids']}
              label="实例（深度诊断默认仅选定实例）"
              rules={[{ required: true, message: '请选择至少一个实例' }]}
            >
              <Select
                mode="multiple"
                placeholder="选择实例（选项来自近 24 小时运行时数据，随已填服务过滤）"
                showSearch
                optionFilterProp="label"
                loading={instancesQuery.isLoading}
                options={(instancesQuery.data?.instances ?? [])
                  // 已填服务时前端过滤实例，避免随输入换 key 重新请求导致下拉选项重建
                  .filter((inst) => !serviceWatch || inst.service_name === serviceWatch)
                  .map((inst) => ({
                    value: inst.instance_id,
                    label: `${inst.instance_id}（${inst.service_name}）`,
                  }))}
              />
            </Form.Item>
          </div>
          <div style={{ display: step === 1 ? undefined : 'none' }}>
            <Form.Item
              name="capabilities"
              label="诊断能力（逐项确认风险后勾选）"
              rules={[{ required: true, message: '请至少选择一项诊断能力' }]}
            >
              <Checkbox.Group
                style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
                options={Object.entries(APM_DIAGNOSTIC_CAPABILITY_META).map(([value, meta]) => ({
                  value,
                  label: (
                    <Space size={8}>
                      <Tag color={meta.color} style={{ marginInlineEnd: 0 }}>
                        {meta.label}
                      </Tag>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {meta.risk}
                      </Typography.Text>
                    </Space>
                  ),
                }))}
              />
            </Form.Item>
            {capabilitiesWatch.includes('function_probe') && (
              <Alert
                type="warning"
                showIcon
                message="函数探针需精确的实例/服务范围"
                description="函数探针为定向方法插桩，开销与敏感性最高；请确认第 1 步已选择精确的服务与实例范围，禁止全量方法追踪。"
              />
            )}
          </div>
          <div style={{ display: step === 2 ? undefined : 'none' }}>
            <Form.Item
              name="sampling_rate"
              label={`采样率（当前 ${formatPercent(samplingWatch ?? 0.5)}）`}
              rules={[{ required: true, message: '请设置采样率' }]}
            >
              <Slider min={0.1} max={1} step={0.1} marks={{ 0.1: '10%', 0.5: '50%', 1: '100%' }} />
            </Form.Item>
            <Form.Item
              name="duration_minutes"
              label={`诊断时长（当前 ${durationWatch ?? 15} 分钟，到期自动结束）`}
              rules={[{ required: true, message: '请设置诊断时长' }]}
            >
              <Slider
                min={15}
                max={120}
                step={5}
                marks={{ 15: '15 分钟', 60: '60 分钟', 120: '120 分钟' }}
              />
            </Form.Item>
          </div>
        </Form>
        {step === 3 && (
          <div>
            {dryRunMutation.isPending ? (
              <div style={{ textAlign: 'center', padding: 48 }}>
                <Spin />
              </div>
            ) : dryRunMutation.isError ? (
              <Alert
                type="error"
                showIcon
                message="开销预估失败"
                description={
                  dryRunMutation.error instanceof ApiError
                    ? dryRunMutation.error.message
                    : '请返回修改配置后重试'
                }
                action={
                  <Button size="small" onClick={() => dryRunMutation.mutate(wizardBody())}>
                    重试
                  </Button>
                }
              />
            ) : overhead ? (
              <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                <Descriptions column={1} size="small" bordered title="预计开销（试算预估）">
                  <Descriptions.Item label="CPU 开销">{overhead.cpu_hint || '-'}</Descriptions.Item>
                  <Descriptions.Item label="Span 速率">
                    {overhead.spans_per_s_hint || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="数据量">
                    {overhead.data_volume_hint || '-'}
                  </Descriptions.Item>
                </Descriptions>
                {(overhead.risk_notes ?? []).length > 0 && (
                  <Alert
                    type="warning"
                    showIcon
                    message="风险提示"
                    description={
                      <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                        {overhead.risk_notes.map((note, i) => (
                          <li key={i}>{note}</li>
                        ))}
                      </ul>
                    }
                  />
                )}
                <Checkbox
                  checked={ackRisk}
                  onChange={(e) => setAckRisk(e.target.checked)}
                >
                  我已了解开销与风险
                </Checkbox>
              </Space>
            ) : null}
          </div>
        )}
      </Modal>

      <Drawer
        title="诊断会话详情"
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={720}
      >
        {detailQuery.isLoading ? (
          <div style={{ textAlign: 'center', padding: 48 }}>
            <Spin />
          </div>
        ) : detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载诊断会话详情失败" />
        ) : detail ? (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="会话 ID" span={2}>
                <Typography.Text code style={{ fontSize: 12 }}>
                  {detail.id}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detail.status} map={APM_DIAGNOSTIC_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="剩余时间">
                {detail.status === 'ACTIVE' ? (
                  <RemainingCountdown expiresAt={detail.expires_at} />
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="应用">{detail.scope?.application_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="服务">{detail.scope?.service || '-'}</Descriptions.Item>
              <Descriptions.Item label="环境">{formatEnvironment(detail.scope?.environment)}</Descriptions.Item>
              <Descriptions.Item label="实例数">
                {detail.scope?.instance_ids?.length ?? 0}
              </Descriptions.Item>
              <Descriptions.Item label="实例" span={2}>
                {(detail.scope?.instance_ids ?? []).join('、') || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="诊断能力" span={2}>
                <Space size={4} wrap>
                  {(detail.capabilities ?? []).map((c) => {
                    const meta = APM_DIAGNOSTIC_CAPABILITY_META[c]
                    return (
                      <Tag key={c} color={meta?.color} style={{ marginInlineEnd: 0 }}>
                        {meta?.label ?? c}
                      </Tag>
                    )
                  })}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="采样率">
                {formatPercent(detail.sampling_rate)}
              </Descriptions.Item>
              <Descriptions.Item label="诊断时长">{detail.duration_minutes} 分钟</Descriptions.Item>
              <Descriptions.Item label="发起人">{detail.created_by || '-'}</Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTime(detail.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="到期时间">
                {formatDateTime(detail.expires_at)}
              </Descriptions.Item>
              {detail.stopped_at ? (
                <Descriptions.Item label="停止时间">
                  {formatDateTime(detail.stopped_at)}
                </Descriptions.Item>
              ) : null}
              {detail.stopped_by ? (
                <Descriptions.Item label="停止人">{detail.stopped_by}</Descriptions.Item>
              ) : null}
              {detail.stop_reason ? (
                <Descriptions.Item label="停止原因" span={2}>
                  {APM_DIAG_STOP_REASON_LABELS[detail.stop_reason] ?? detail.stop_reason}
                </Descriptions.Item>
              ) : null}
            </Descriptions>
            {detail.status === 'ACTIVE' && (
              <Popconfirm
                title="提前停止诊断会话"
                description="停止后目标 Agent 将在 1 分钟内回到基线策略，已采集数据保留本会话 ID。确定停止吗？"
                okText="确认停止"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => stopMutation.mutate(detail.id)}
              >
                <Button danger block>
                  提前停止
                </Button>
              </Popconfirm>
            )}
            <Card size="small" title="关联审计">
              {(detail.audits ?? []).length > 0 ? (
                <List
                  size="small"
                  dataSource={detail.audits ?? []}
                  renderItem={(audit) => {
                    const summaryText = audit.failure_reason
                      ? `失败原因：${audit.failure_reason}`
                      : audit.before_summary && audit.after_summary
                        ? `${audit.before_summary} → ${audit.after_summary}`
                        : audit.after_summary || audit.before_summary || ''
                    return (
                      <List.Item>
                        <Space direction="vertical" size={0}>
                          <Space size={8} wrap>
                            <Typography.Text strong style={{ fontSize: 12 }}>
                              {audit.action
                                ? (APM_DIAG_AUDIT_ACTION_LABELS[audit.action] ??
                                  APM_DIAG_AUDIT_ACTION_LABELS[audit.action.toLowerCase()] ??
                                  audit.action)
                                : '-'}
                            </Typography.Text>
                            {audit.result ? (
                              <Tag color={audit.result === 'FAILURE' ? 'red' : 'green'} style={{ marginInlineEnd: 0 }}>
                                {audit.result === 'FAILURE' ? '失败' : audit.result === 'SUCCESS' ? '成功' : audit.result}
                              </Tag>
                            ) : null}
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              {audit.username || '-'} · {formatDateTime(audit.occurred_at)}
                            </Typography.Text>
                          </Space>
                          {audit.object_name ? (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              对象：{audit.object_name}
                            </Typography.Text>
                          ) : null}
                          {summaryText ? (
                            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                              {summaryText}
                            </Typography.Text>
                          ) : null}
                        </Space>
                      </List.Item>
                    )
                  }}
                />
              ) : (
                <Typography.Text type="secondary">暂无审计记录</Typography.Text>
              )}
            </Card>
          </Space>
        ) : null}
      </Drawer>
    </Card>
  )
}
