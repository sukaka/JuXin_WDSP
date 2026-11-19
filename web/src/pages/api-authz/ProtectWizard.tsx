import { useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Col,
  Descriptions,
  Drawer,
  Form,
  Input,
  Popconfirm,
  Radio,
  Row,
  Select,
  Space,
  Spin,
  Statistic,
  Steps,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiAuthzApi, type ApiAuthzEnforcementImpact, type ApiAuthzEnforcementReadinessItem } from '../../api/apiAuthz'
import { apiObjectModelsApi, type ApiObjectModel } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import { gatewayConfigApi, publishTasksApi } from '../../api/gatewayConfig'
import { ReadinessBadge } from '../../components/AuthzEnforcement'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import {
  ENFORCEMENT_VALUE_META,
  EVIDENCE_SOURCE_META,
  UNKNOWN_NEVER_BLOCKS_NOTE,
  buildAuthzConfirmTextV1,
  classifyPatchError,
  isConfirmTokenExpired,
  isReadinessBlocking,
} from '../../utils/authzEnforcement'
import { formatDateTime } from '../../utils/format'
import { generateIdempotencyKey } from '../../utils/idempotency'
import { hasPermission } from '../../utils/permission'
import { isTerminalTaskStatus } from '../../utils/stage3'
import type { PublishTaskItem } from '../../types'

/** D6 固定标注（双人复核本批不做，如实披露治理缺口） */
const SINGLE_OPERATOR_NOTE = '当前为单人切换模式——签署人与操作人可为同一账户；生产环境建议经内部流程复核后操作。'

const WIZARD_STEPS = [
  { title: '选端点' },
  { title: '影响评估' },
  { title: '四要素' },
  { title: '确认单签署' },
  { title: '提交与结果' },
]

/** LOCK_BUSY 退避重试（沿用 s5_publish 惯例：3s 退避；上限 5 次防无限重试） */
const LOCK_BUSY_RETRY_DELAY_MS = 3000
const LOCK_BUSY_MAX_RETRIES = 5

export interface ProtectWizardPreset {
  endpoint_id: string
  object_segment: string
}

interface ProtectWizardProps {
  open: boolean
  onClose: () => void
  /** 态势 Tab 语境：候选列表与 readiness 按应用取数 */
  applicationId?: string
  /** 访问画像页/行操作入口：预选端点（直接进入影响评估，仍可回退改选） */
  preset?: ProtectWizardPreset
  /** 切换/切回成功后回调（宿主刷新 readiness 等） */
  onSwitched?: () => void
}

interface ElementValues {
  enforcement_owner: string
  evidence_source: string
}

type SubmitPhase = 'idle' | 'submitting' | 'publishing' | 'success' | 'failed'

interface FailureInfo {
  code: string
  message: string
}

/**
 * PROTECT 切换向导（NG-AZ-04 §1.5 冻结五步状态机）：
 * 选端点 → 影响评估（签发一次性 confirm_token）→ 四要素 → 确认单签署 → PATCH+发布轮询。
 * 失败路径：PATCH 400 回对应步骤保留表单；token 过期回影响评估重签；发布 FAILED 如实展示
 * 「配置与生效不一致」并提供快捷切回 OBSERVE，不自动回退。
 */
export default function ProtectWizard(props: ProtectWizardProps) {
  const { open, onClose } = props
  return (
    <Drawer title="切换 PROTECT（实断）" open={open} onClose={onClose} width={920} destroyOnHidden maskClosable={false}>
      {open ? <WizardBody {...props} /> : null}
    </Drawer>
  )
}

function WizardBody({ applicationId, preset, onClose, onSwitched }: ProtectWizardProps) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.manage')
  const canPublish = hasPermission(permissions, 'gateway_configs.publish')
  const displayName = useAuthStore((s) => s.user?.display_name || s.user?.username || '')

  const [step, setStep] = useState(preset ? 1 : 0)
  const [selectedId, setSelectedId] = useState<string>()
  const [windowDays, setWindowDays] = useState(7)
  const [impact, setImpact] = useState<ApiAuthzEnforcementImpact | null>(null)
  const [evalKey, setEvalKey] = useState('')
  const [impactLoading, setImpactLoading] = useState(false)
  const [impactError, setImpactError] = useState(false)
  const impactSeqRef = useRef(0)
  const activeEvalKeyRef = useRef('')
  const [elements, setElements] = useState<ElementValues | null>(null)
  const [signed, setSigned] = useState(false)
  const [ackChecked, setAckChecked] = useState(false)
  const [submitPhase, setSubmitPhase] = useState<SubmitPhase>('idle')
  const [submitAction, setSubmitAction] = useState<'PROTECT' | 'OBSERVE'>('PROTECT')
  const [taskId, setTaskId] = useState<string>()
  const [failure, setFailure] = useState<FailureInfo | null>(null)
  const lockBusyRetries = useRef(0)
  const [elementsForm] = Form.useForm<ElementValues>()

  // 候选对象模型行（第 1 步选择集；preset 语境按端点过滤）
  const modelsQuery = useQuery({
    queryKey: ['api-authz', 'wizard-object-models', applicationId, preset?.endpoint_id],
    queryFn: () =>
      apiObjectModelsApi.list({
        page: 1,
        page_size: 100,
        application_id: applicationId || undefined,
        endpoint_id: applicationId ? undefined : preset?.endpoint_id,
      }),
  })
  const readinessQuery = useQuery({
    queryKey: ['api-authz', 'wizard-readiness', applicationId, preset?.endpoint_id],
    queryFn: () => apiAuthzApi.listEnforcementReadiness({ application_id: applicationId, endpoint_id: preset?.endpoint_id }),
    enabled: Boolean(applicationId || preset?.endpoint_id),
  })
  const readinessMap = useMemo(() => {
    const map = new Map<string, ApiAuthzEnforcementReadinessItem>()
    for (const item of readinessQuery.data?.items ?? []) map.set(`${item.endpoint_id}:${item.object_segment}`, item)
    return map
  }, [readinessQuery.data])
  const models = useMemo(() => modelsQuery.data?.items ?? [], [modelsQuery.data])
  const selected = useMemo(() => models.find((m) => m.id === selectedId), [models, selectedId])

  // preset：数据到达后自动选中对应行；找不到回第 1 步改选
  useEffect(() => {
    if (!preset || selectedId || modelsQuery.isLoading) return
    const hit = models.find((m) => m.endpoint_id === preset.endpoint_id && m.object_segment === preset.object_segment)
    if (hit) setSelectedId(hit.id)
    else if (modelsQuery.data) setStep(0)
  }, [preset, selectedId, models, modelsQuery.isLoading, modelsQuery.data])

  // 影响评估：进入第 2 步即请求（§1.3）；换窗口/端点立即重新评估并用序号丢弃过期响应（防旧 confirm_token 覆盖）
  const impactMut = useMutation({
    mutationFn: ({
      endpoint_id,
      window_days,
      object_segment,
    }: {
      endpoint_id: string
      window_days: number
      object_segment?: string
      reqSeq: number
      reqEvalKey: string
    }) => apiAuthzApi.evaluateEnforcementImpact({ endpoint_id, window_days, object_segment }),
    onSuccess: (data, vars) => {
      if (vars.reqSeq !== impactSeqRef.current || vars.reqEvalKey !== activeEvalKeyRef.current) return
      setImpactLoading(false)
      setImpactError(false)
      setImpact(data)
      setSigned(false)
      setAckChecked(false)
    },
    onError: (e: unknown, vars) => {
      if (vars.reqSeq !== impactSeqRef.current || vars.reqEvalKey !== activeEvalKeyRef.current) return
      setImpactLoading(false)
      setImpactError(true)
      message.error(e instanceof ApiError ? e.message : '影响评估失败')
    },
  })
  const wantEvalKey = selected ? `${selected.endpoint_id}:${selected.object_segment}:${windowDays}` : ''
  useEffect(() => {
    if (step !== 1 || !selected) return
    if (evalKey === wantEvalKey) return
    const nextSeq = impactSeqRef.current + 1
    impactSeqRef.current = nextSeq
    activeEvalKeyRef.current = wantEvalKey
    setEvalKey(wantEvalKey)
    setImpact(null)
    setImpactError(false)
    setImpactLoading(true)
    setSigned(false)
    setAckChecked(false)
    impactMut.mutate({
      endpoint_id: selected.endpoint_id,
      window_days: windowDays,
      object_segment: selected.object_segment,
      reqSeq: nextSeq,
      reqEvalKey: wantEvalKey,
    })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, selected, wantEvalKey, evalKey])

  // 确认单签署（第 4 步；signed_at 落库）
  const signMut = useMutation({
    mutationFn: (params: { token: string; values: ElementValues }) =>
      apiAuthzApi.signEnforcementConfirmation(params.token, {
        enforcement_owner: params.values.enforcement_owner.trim(),
        evidence_source: params.values.evidence_source,
        on_unknown: 'ALLOW_UNKNOWN',
      }),
    onSuccess: () => setSigned(true),
    onError: (e: unknown) => {
      const msg = e instanceof ApiError ? e.message : '签署失败'
      message.error(msg)
      if (e instanceof ApiError && classifyPatchError(e.message) === 'token') {
        // token 失效（过期/已消费）→ 回影响评估重新签发
        impactSeqRef.current += 1
        activeEvalKeyRef.current = ''
        setImpact(null)
        setEvalKey('')
        setSigned(false)
        setAckChecked(false)
        setStep(1)
      }
    },
  })

  // 发布任务轮询（终态停轮询；LOCK_BUSY 退避自动重试）
  const taskQuery = useQuery({
    queryKey: ['api-authz', 'wizard-publish-task', taskId],
    queryFn: () => publishTasksApi.get(taskId!),
    enabled: Boolean(taskId),
    refetchInterval: (query) =>
      query.state.data && isTerminalTaskStatus(query.state.data.status) ? false : 1500,
  })
  const publishMut = useMutation({
    mutationFn: () => gatewayConfigApi.publish({ idempotency_key: generateIdempotencyKey() }),
    onSuccess: (task: PublishTaskItem) => {
      setTaskId(task.id)
      setSubmitPhase('publishing')
    },
    onError: (e: unknown) => {
      // PATCH 已落库但发布未能触发——同属「配置与生效不一致」，如实呈现
      setSubmitPhase('failed')
      const reason = e instanceof ApiError ? e.message : '发布触发失败'
      setFailure({
        code: 'PUBLISH_TRIGGER_FAILED',
        message: canPublish
          ? `${reason}（enforcement 已落库 ${submitAction}，但发布未触发；可点「重新发布」重试或前往配置发布页手动发布）`
          : `${reason}（enforcement 已落库 ${submitAction}，但当前账号无 gateway_configs.publish 权限，发布未触发；请由有权限账号在配置发布页发布）`,
      })
    },
  })

  // PATCH enforcement（PROTECT 携带 confirm_token；OBSERVE 切回免 token）
  const submitMut = useMutation({
    mutationFn: async (action: 'PROTECT' | 'OBSERVE') => {
      if (!selected) throw new Error('未选择对象模型行')
      if (action === 'PROTECT') {
        if (!elements || !impact?.confirm_token) throw new Error('缺少四要素或签署令牌')
        return apiObjectModelsApi.patch(selected.id, {
          enforcement: 'PROTECT',
          enforcement_owner: elements.enforcement_owner.trim(),
          evidence_source: elements.evidence_source,
          on_unknown: 'ALLOW_UNKNOWN',
          confirm_token: impact.confirm_token,
        })
      }
      return apiObjectModelsApi.patch(selected.id, { enforcement: 'OBSERVE' })
    },
    onSuccess: (_data, action) => {
      setSubmitAction(action)
      setFailure(null)
      lockBusyRetries.current = 0
      publishMut.mutate()
    },
    onError: (e: unknown, action) => {
      const msg = e instanceof ApiError ? e.message : '提交失败'
      message.error(msg)
      if (action === 'OBSERVE') {
        setFailure({ code: 'SWITCH_BACK_FAILED', message: msg })
        return
      }
      if (e instanceof ApiError && e.status === 400) {
        const kind = classifyPatchError(e.message)
        if (kind === 'token') {
          // token 过期/失效：回影响评估重新签发（§1.5 失败路径）
          impactSeqRef.current += 1
          activeEvalKeyRef.current = ''
          setImpact(null)
          setEvalKey('')
          setSigned(false)
          setAckChecked(false)
          setStep(1)
        } else if (kind === 'elements') {
          setStep(2)
        }
      }
    },
  })

  // 轮询终态处置：SUCCESS 收尾；FAILED 如实呈现；LOCK_BUSY 退避重试
  const task = taskQuery.data
  useEffect(() => {
    if (!task || !isTerminalTaskStatus(task.status)) return
    if (task.status === 'SUCCESS') {
      setSubmitPhase('success')
      void qc.invalidateQueries({ queryKey: ['api-authz'] })
      void qc.invalidateQueries({ queryKey: ['api-object-models'] })
      onSwitched?.()
      return
    }
    if (task.status === 'FAILED' && task.failure_code === 'LOCK_BUSY' && lockBusyRetries.current < LOCK_BUSY_MAX_RETRIES) {
      lockBusyRetries.current += 1
      const timer = setTimeout(() => publishMut.mutate(), LOCK_BUSY_RETRY_DELAY_MS)
      return () => clearTimeout(timer)
    }
    setSubmitPhase('failed')
    setFailure({ code: task.failure_code || 'PUBLISH_FAILED', message: task.failure_message || task.result_summary || '发布失败' })
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [task?.id, task?.status])

  const readinessOfSelected = selected ? readinessMap.get(`${selected.endpoint_id}:${selected.object_segment}`) : undefined
  const displayReadiness = impact?.readiness ?? readinessOfSelected?.readiness
  const displayReasons = impact?.readiness_reasons ?? readinessOfSelected?.reasons ?? []

  const bounceIfTokenExpired = (): boolean => {
    if (isConfirmTokenExpired(impact?.confirm_token_expires_at)) {
      message.warning('签署令牌已过期（15 分钟），请重新评估签发')
      impactSeqRef.current += 1
      activeEvalKeyRef.current = ''
      setImpact(null)
      setEvalKey('')
      setSigned(false)
      setAckChecked(false)
      setStep(1)
      return true
    }
    return false
  }

  const goNextFromElements = async () => {
    try {
      const values = await elementsForm.validateFields()
      const nextElements: ElementValues = {
        enforcement_owner: values.enforcement_owner.trim(),
        evidence_source: values.evidence_source,
      }
      const changed =
        !elements ||
        elements.enforcement_owner.trim() !== nextElements.enforcement_owner ||
        elements.evidence_source !== nextElements.evidence_source
      if (changed) {
        setSigned(false)
        setAckChecked(false)
      }
      setElements(nextElements)
      setStep(3)
    } catch {
      // 校验未通过：停留当前步，错误内联展示
    }
  }

  const candidateColumns: ColumnsType<ApiObjectModel> = [
    { title: '接口', dataIndex: 'endpoint_key', ellipsis: true, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    { title: '对象段', dataIndex: 'object_segment', width: 120, render: (v: string) => <Typography.Text code>{v}</Typography.Text> },
    {
      title: '当前 enforcement', dataIndex: 'enforcement', width: 150,
      render: (v?: string) => <StatusTag value={v || 'OBSERVE'} map={ENFORCEMENT_VALUE_META} />,
    },
    {
      title: '能否实断', key: 'readiness', width: 170,
      render: (_, record) => {
        const item = readinessMap.get(`${record.endpoint_id}:${record.object_segment}`)
        return <ReadinessBadge readiness={item?.readiness} reasons={item?.reasons} />
      },
    },
    {
      title: '缺项说明', key: 'missing', ellipsis: true,
      render: (_, record) => {
        const item = readinessMap.get(`${record.endpoint_id}:${record.object_segment}`)
        if (!item || item.readiness === 'READY') return <Typography.Text type="secondary">—</Typography.Text>
        return <Typography.Text type="secondary">{item.reasons[0] ?? ''}{item.reasons.length > 1 ? ` 等 ${item.reasons.length} 项` : ''}</Typography.Text>
      },
    },
  ]

  const confirmText = impact
    ? buildAuthzConfirmTextV1({
        windowDays: impact.window_days,
        observeViolationCount: impact.observe_violation_count,
        distinctPrincipalCount: impact.distinct_principal_count,
        confirmedByName: displayName,
      })
    : ''

  const unknownBuckets = impact?.unknown_by_reason ?? []

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Steps current={step} size="small" items={WIZARD_STEPS.map((s) => ({ title: s.title }))} />

      {step === 0 ? (
        <>
          <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
            仅 publishable 候选对象模型行可切换；资格不齐（NOT_PUBLISHABLE）行禁用并注明缺项。
          </Typography.Paragraph>
          <QueryErrorAlert error={modelsQuery.error ?? readinessQuery.error} message="加载候选端点失败" />
          <Table<ApiObjectModel>
            rowKey="id"
            size="small"
            loading={modelsQuery.isLoading}
            columns={candidateColumns}
            dataSource={models}
            pagination={false}
            scroll={{ y: 420 }}
            locale={{ emptyText: '暂无可切换的对象模型行' }}
            rowSelection={{
              type: 'radio',
              selectedRowKeys: selectedId ? [selectedId] : [],
              onChange: (keys) => {
                impactSeqRef.current += 1
                activeEvalKeyRef.current = ''
                setSelectedId(keys[0] as string)
                setImpact(null)
                setEvalKey('')
                setImpactError(false)
                setImpactLoading(false)
                setSigned(false)
                setAckChecked(false)
              },
              getCheckboxProps: (record) => {
                const item = readinessMap.get(`${record.endpoint_id}:${record.object_segment}`)
                return { disabled: record.enforcement === 'PROTECT' || item?.readiness === 'NOT_PUBLISHABLE' }
              },
            }}
          />
        </>
      ) : null}

      {step === 1 ? (
        <>
          {!selected ? (
            <Spin tip="加载对象模型…"><div style={{ minHeight: 120 }} /></Spin>
          ) : (
            <>
              <Space wrap align="center">
                <Typography.Text strong>评估端点：</Typography.Text>
                <Typography.Text code>{impact?.endpoint_key ?? selected.endpoint_key ?? selected.endpoint_id}</Typography.Text>
                <Typography.Text code>{selected.object_segment}</Typography.Text>
                <Typography.Text>窗口：</Typography.Text>
                <Select
                  value={windowDays}
                  style={{ width: 110 }}
                  options={[7, 14, 30].map((d) => ({ value: d, label: `近 ${d} 天` }))}
                  onChange={(d) => {
                    impactSeqRef.current += 1
                    activeEvalKeyRef.current = ''
                    setWindowDays(d)
                    setImpact(null)
                    setEvalKey('')
                    setImpactError(false)
                    setSigned(false)
                    setAckChecked(false)
                  }}
                />
              </Space>
              {impactError ? (
                <Alert type="error" showIcon message="影响评估失败" description="请返回上一步重选端点，或调整窗口后重试；失败不会签发任何令牌。" />
              ) : null}
              {impactLoading || (!impact && !impactError) ? (
                <Spin tip="评估中…"><div style={{ minHeight: 160 }} /></Spin>
              ) : impact ? (
                <>
                  {impact.observe_violation_count > 0 ? (
                    <Alert type="error" showIcon message="这些请求切换后将被实断" description={`近 ${impact.window_days} 天观测到 ${impact.observe_violation_count} 次违规请求，切换 PROTECT 后将被 403（AUTHZ_VIOLATION_DENIED）。`} />
                  ) : null}
                  <Row gutter={[12, 12]}>
                    <Col xs={12} lg={6}>
                      <Card size="small"><Statistic title="切换后将被 403（近似）" value={impact.observe_violation_count} valueStyle={{ color: impact.observe_violation_count > 0 ? '#cf1322' : undefined }} /></Card>
                    </Col>
                    <Col xs={12} lg={6}><Card size="small"><Statistic title="涉及主体数" value={impact.distinct_principal_count} /></Card></Col>
                    <Col xs={12} lg={6}><Card size="small"><Statistic title="UNKNOWN 总数" value={impact.unknown_total} valueStyle={{ color: '#ad6800' }} /></Card></Col>
                    <Col xs={12} lg={6}><Card size="small"><Statistic title="已实断数（复评）" value={impact.verified_violation_count} /></Card></Col>
                  </Row>
                  <Space align="center" wrap>
                    <Typography.Text strong>能否实断：</Typography.Text>
                    <ReadinessBadge readiness={impact.readiness} reasons={impact.readiness_reasons} />
                    <Typography.Text type="secondary">评估时间 {formatDateTime(impact.evaluated_at)}</Typography.Text>
                  </Space>
                  <div>
                    <Typography.Text strong>UNKNOWN 分桶（{UNKNOWN_NEVER_BLOCKS_NOTE}）</Typography.Text>
                    <Table
                      rowKey="reason_code"
                      size="small"
                      style={{ marginTop: 8 }}
                      columns={[
                        { title: '原因码', dataIndex: 'reason_code' },
                        { title: '次数', dataIndex: 'count', width: 100 },
                      ]}
                      dataSource={unknownBuckets}
                      pagination={false}
                      locale={{ emptyText: '近窗口内无 UNKNOWN 决策' }}
                    />
                    <Typography.Paragraph type="secondary" style={{ marginTop: 4, marginBottom: 0 }}>
                      UNKNOWN 永不阻断：证据不足的请求在 PROTECT 下仍放行（ALLOW_UNKNOWN）。
                    </Typography.Paragraph>
                  </div>
                  {impact.recent_samples && impact.recent_samples.length > 0 ? (
                    <div>
                      <Typography.Text strong>近期样本（脱敏）</Typography.Text>
                      <Table
                        rowKey={(r) => `${r.occurred_at}:${r.reason_code}`}
                        size="small"
                        style={{ marginTop: 8 }}
                        columns={[
                          { title: '时间', dataIndex: 'occurred_at', width: 180, render: formatDateTime },
                          { title: '决策', dataIndex: 'decision', width: 170, render: (v: string) => <Tag>{v}</Tag> },
                          { title: '原因码', dataIndex: 'reason_code' },
                        ]}
                        dataSource={impact.recent_samples}
                        pagination={false}
                      />
                    </div>
                  ) : null}
                  {!impact.confirm_token ? (
                    <Alert type="warning" showIcon message="当前账号无 api_authorization.manage 权限，未签发签署令牌——可查看评估，不能继续切换。" />
                  ) : null}
                </>
              ) : null}
            </>
          )}
        </>
      ) : null}

      {step === 2 ? (
        <>
          {isReadinessBlocking(displayReadiness) ? (
            <Alert
              type="warning"
              showIcon
              message="当前 readiness 非 READY——允许继续切换，但切换后也可能不实断（如实预期管理）"
              description={
                <ul style={{ margin: 0, paddingInlineStart: 18 }}>
                  {displayReasons.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              }
            />
          ) : null}
          <Form form={elementsForm} layout="vertical" initialValues={{ evidence_source: 'MANUAL_CONFIRMED' }}>
            <Form.Item
              name="enforcement_owner"
              label="业务负责人（enforcement_owner）"
              rules={[
                { required: true, whitespace: true, message: '请填写业务负责人标识' },
                { max: 128, message: '不超过 128 字符' },
              ]}
            >
              <Input placeholder="如 zhang.lei@example.com" allowClear autoComplete="off" />
            </Form.Item>
            <Form.Item name="evidence_source" label="证据来源声明（evidence_source）" rules={[{ required: true, message: '请选择证据来源' }]}>
              <Radio.Group>
                {Object.entries(EVIDENCE_SOURCE_META).map(([value, meta]) => (
                  <Radio key={value} value={value}>
                    {meta.label}
                    <Typography.Text type="secondary" style={{ marginLeft: 8 }}>{meta.hint}</Typography.Text>
                  </Radio>
                ))}
              </Radio.Group>
            </Form.Item>
            <Form.Item label="UNKNOWN 处理方式（on_unknown）">
              <Input value="ALLOW_UNKNOWN" disabled />
              <Typography.Paragraph type="secondary" style={{ marginTop: 4, marginBottom: 0 }}>
                首批唯一处理方式：UNKNOWN 永不阻断（证据不足的请求不实断）。
              </Typography.Paragraph>
            </Form.Item>
          </Form>
        </>
      ) : null}

      {step === 3 ? (
        impact ? (
          <>
            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label="接口" span={2}>
                <Typography.Text code>{impact.endpoint_key}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="对象段"><Typography.Text code>{impact.object_segment}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="评估窗口">近 {impact.window_days} 天</Descriptions.Item>
              <Descriptions.Item label="观测违规">{impact.observe_violation_count} 次</Descriptions.Item>
              <Descriptions.Item label="涉及主体">{impact.distinct_principal_count} 个</Descriptions.Item>
              <Descriptions.Item label="业务负责人">{elements?.enforcement_owner ?? '—'}</Descriptions.Item>
              <Descriptions.Item label="证据来源">{elements?.evidence_source ?? '—'}</Descriptions.Item>
            </Descriptions>
            <Card size="small" title="确认语义（确认文案 v1）">
              <Typography.Paragraph style={{ marginBottom: 0 }}>{confirmText}</Typography.Paragraph>
            </Card>
            <Alert type="info" showIcon message={SINGLE_OPERATOR_NOTE} />
            <Space direction="vertical" size={8}>
              <Checkbox checked={ackChecked} onChange={(e) => setAckChecked(e.target.checked)}>
                我已阅读并确认
              </Checkbox>
              <Space>
                <Button
                  type="primary"
                  disabled={!ackChecked || signed || !canManage || !impact.confirm_token}
                  loading={signMut.isPending}
                  onClick={() => {
                    if (bounceIfTokenExpired()) return
                    if (elements && impact.confirm_token) signMut.mutate({ token: impact.confirm_token, values: elements })
                  }}
                >
                  提交签署
                </Button>
                {signed ? <Tag color="green">已签署（signed_at 已落库）</Tag> : null}
              </Space>
            </Space>
          </>
        ) : (
          <Alert type="warning" showIcon message="缺少影响评估结果，请返回影响评估步骤重新评估。" />
        )
      ) : null}

      {step === 4 ? (
        <>
          {submitPhase === 'idle' || submitPhase === 'submitting' ? (
            <>
              <Alert type="warning" showIcon message="提交后将 PATCH enforcement=PROTECT 并触发全站发布；确认单随 PATCH 同事务消费（一次性）。" />
              <Descriptions size="small" column={2} bordered>
                <Descriptions.Item label="接口" span={2}>
                  <Typography.Text code>{impact?.endpoint_key ?? selected?.endpoint_key ?? '—'}</Typography.Text>
                </Descriptions.Item>
                <Descriptions.Item label="对象段"><Typography.Text code>{selected?.object_segment ?? '—'}</Typography.Text></Descriptions.Item>
                <Descriptions.Item label="业务负责人">{elements?.enforcement_owner ?? '—'}</Descriptions.Item>
                <Descriptions.Item label="证据来源">{elements?.evidence_source ?? '—'}</Descriptions.Item>
                <Descriptions.Item label="on_unknown">ALLOW_UNKNOWN（UNKNOWN 永不阻断）</Descriptions.Item>
              </Descriptions>
              <Button
                type="primary"
                danger
                disabled={!signed || !selected}
                loading={submitMut.isPending || publishMut.isPending}
                onClick={() => {
                  if (bounceIfTokenExpired()) return
                  setSubmitPhase('submitting')
                  submitMut.mutate('PROTECT')
                }}
              >
                确认提交切换
              </Button>
            </>
          ) : null}

          {submitPhase === 'publishing' ? (
            <Card size="small" title="发布中">
              <Space direction="vertical" size={8} style={{ width: '100%' }}>
                <Space>
                  <Spin size="small" />
                  <Typography.Text>{task?.current_step || '等待执行'}（每 1.5 秒自动刷新；LOCK_BUSY 自动退避重试）</Typography.Text>
                </Space>
              </Space>
            </Card>
          ) : null}

          {submitPhase === 'success' ? (
            <Alert
              type="success"
              showIcon
              message={submitAction === 'PROTECT' ? '已生效：端点已进入 PROTECT（实断）' : '已切回 OBSERVE'}
              description={
                submitAction === 'PROTECT' ? (
                  <>
                    资格全真（VERIFIED_VIOLATION）的请求将被 403 实断；UNKNOWN 永不阻断。前往{' '}
                    <Link to="/api-authz" onClick={onClose}>授权决策列表</Link>
                    按「已验证违规（实断）」过滤查看。
                  </>
                ) : (
                  '端点已回到观测模式；历史确认单与审计记录留存（回滚不回退事实）。'
                )
              }
            />
          ) : null}

          {submitPhase === 'failed' && failure ? (
            <Space direction="vertical" size={12} style={{ width: '100%' }}>
              <Alert
                type="error"
                showIcon
                message="配置与生效不一致"
                description={
                  <>
                    <Typography.Paragraph style={{ marginBottom: 8 }}>
                      enforcement 已落库 {submitAction}，但节点未应用（{failure.code}）。管理面配置与网关生效状态当前不一致。
                    </Typography.Paragraph>
                    <Typography.Paragraph code copyable style={{ whiteSpace: 'pre-wrap' }}>
                      {failure.code}: {failure.message}
                    </Typography.Paragraph>
                    <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
                      修复指引：能力门缺口（CAP_MISSING，如 detectors.authzdecide required=az/3）请升级网关节点至 az/3 后重新发布；
                      其他失败请按失败消息处理后重新发布，或切回 OBSERVE。
                    </Typography.Paragraph>
                  </>
                }
              />
              <Space>
                <Popconfirm
                  title="切回 OBSERVE 不要求签署令牌"
                  description="端点将回到观测模式（回滚不回退事实，确认单留存）。"
                  okText="立即切回"
                  cancelText="取消"
                  onConfirm={() => submitMut.mutate('OBSERVE')}
                >
                  <Button danger loading={submitMut.isPending}>立即切回 OBSERVE</Button>
                </Popconfirm>
                <Button onClick={() => { setFailure(null); setSubmitPhase('publishing'); lockBusyRetries.current = 0; publishMut.mutate() }}>
                  重新发布
                </Button>
              </Space>
            </Space>
          ) : null}
        </>
      ) : null}

      <Space style={{ display: 'flex', justifyContent: 'space-between' }}>
        <Button onClick={onClose}>关闭</Button>
        <Space>
          {step > 0 && submitPhase !== 'publishing' ? (
            <Button onClick={() => setStep((s) => Math.max(0, s - 1))}>上一步</Button>
          ) : null}
          {step === 0 ? (
            <Button type="primary" disabled={!selectedId} onClick={() => setStep(1)}>下一步</Button>
          ) : null}
          {step === 1 ? (
            <Button type="primary" disabled={!impact || !impact.confirm_token} onClick={() => setStep(2)}>下一步</Button>
          ) : null}
          {step === 2 ? (
            <Button type="primary" onClick={() => void goNextFromElements()}>下一步</Button>
          ) : null}
          {step === 3 ? (
            <Button type="primary" disabled={!signed} onClick={() => setStep(4)}>下一步：提交切换</Button>
          ) : null}
        </Space>
      </Space>
    </Space>
  )
}
