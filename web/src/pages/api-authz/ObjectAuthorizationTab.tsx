import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Col,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Row,
  Select,
  Space,
  Statistic,
  Tabs,
  Tag,
  Timeline,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { applicationsApi } from '../../api/applications'
import {
  apiAuthzApi,
  type ApiAuthzDecision,
  type ApiAuthzObjectRelation,
  type ApiAuthzObjectRelationType,
  type ApiAuthzRelationCandidate,
} from '../../api/apiAuthz'
import { ApiError } from '../../api/client'
import { AuthzEnforcementBlock } from '../../components/AuthzEnforcement'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { RELATION_SOURCE_META, extractAuthzEnforcement } from '../../utils/authzEnforcement'
import { formatDateTime } from '../../utils/format'
import {
  AUTHZ_DECISION_META,
  COMMON_DETAIL_FIELD_LABELS,
  formatAuthzReasonCode,
} from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { validateReauthorizationWindow } from './reauthorization'

const candidateStatus = {
  PENDING: { color: 'gold', label: '待确认' },
  CONFIRMED: { color: 'green', label: '已确认' },
  REJECTED: { color: 'default', label: '已拒绝' },
  FROZEN: { color: 'orange', label: '已冻结' },
} as const

const decisionStatus = {
  ALLOW: { color: 'green', label: '允许' },
  OBSERVE_VIOLATION: { color: 'red', label: '观测到违反' },
  UNKNOWN: { color: 'gold', label: '证据不足' },
  // NG-AZ-03 D7：资格全真且端点 PROTECT 的实断决策
  VERIFIED_VIOLATION: { color: 'red', label: '已验证违规（实断）' },
} as const

const relationStatus = {
  CONFIRMED: { color: 'green', label: '已确认' },
  REVOKED: { color: 'red', label: '已撤销' },
  EXPIRED: { color: 'default', label: '已过期' },
} as const

const relationKind = {
  OWNER: { color: 'blue', label: '所有者' },
  SHARED_WITH: { color: 'purple', label: '共享接收人' },
} as const

function relationLabel(value?: string) {
  return (value && relationKind[value as ApiAuthzObjectRelationType]?.label) || value || '对象'
}

/** OBSERVE 形态降级留痕（NG-AZ-03 §1.1）：checks 中任一检查携带 proposed_decision=VERIFIED_VIOLATION */
function hasProposedVerifiedViolation(checks: unknown[]): boolean {
  return checks.some(
    (c) => typeof c === 'object' && c !== null && (c as Record<string, unknown>).proposed_decision === 'VERIFIED_VIOLATION',
  )
}

const CHECK_FIELD_LABELS: Record<string, string> = {
  stage: '阶段',
  step: '步骤',
  check: '检查项',
  rule: '规则',
  name: '名称',
  decision: '决策',
  proposed_decision: '拟结论',
  reason_code: '原因码',
  reason: '原因',
  message: '说明',
  matched: '命中',
  passed: '通过',
}

function renderDecisionCheck(check: unknown, index: number) {
  if (typeof check !== 'object' || check === null || Array.isArray(check)) {
    return <Typography.Text>{`${index + 1}. ${String(check)}`}</Typography.Text>
  }
  const obj = check as Record<string, unknown>
  const decision = typeof obj.decision === 'string' ? obj.decision : undefined
  const proposed = typeof obj.proposed_decision === 'string' ? obj.proposed_decision : undefined
  const reasonCode = typeof obj.reason_code === 'string' ? obj.reason_code : undefined
  const rule =
    (typeof obj.rule === 'string' && obj.rule) ||
    (typeof obj.check === 'string' && obj.check) ||
    (typeof obj.stage === 'string' && obj.stage) ||
    (typeof obj.step === 'string' && obj.step) ||
    (typeof obj.name === 'string' && obj.name) ||
    ''
  const messageText =
    (typeof obj.message === 'string' && obj.message) ||
    (typeof obj.reason === 'string' && obj.reason) ||
    ''
  const handled = new Set(['decision', 'proposed_decision', 'reason_code', 'rule', 'check', 'stage', 'step', 'name', 'message', 'reason'])
  const extras = Object.entries(obj).filter(([k, v]) => !handled.has(k) && v !== undefined && v !== null && v !== '')

  return (
    <Space wrap size={[8, 4]}>
      <Typography.Text strong>步骤 {index + 1}</Typography.Text>
      {rule ? <Tag>{rule}</Tag> : null}
      {decision ? <StatusTag value={decision} map={AUTHZ_DECISION_META} /> : null}
      {proposed ? (
        <Tag color="gold">拟结论：{AUTHZ_DECISION_META[proposed]?.label ?? proposed}</Tag>
      ) : null}
      {reasonCode ? (
        <Typography.Text type="secondary">原因：{formatAuthzReasonCode(reasonCode)}</Typography.Text>
      ) : null}
      {messageText ? <Typography.Text>{messageText}</Typography.Text> : null}
      {extras.map(([k, v]) => {
        const label = CHECK_FIELD_LABELS[k] ?? COMMON_DETAIL_FIELD_LABELS[k] ?? k
        const text = typeof v === 'boolean' ? (v ? '是' : '否') : typeof v === 'object' ? JSON.stringify(v) : String(v)
        return (
          <Typography.Text key={k} type="secondary">
            {label}：{text}
          </Typography.Text>
        )
      })}
    </Space>
  )
}

function shortRef(value?: string | null) {
  if (!value) return '-'
  return value.length > 28 ? `${value.slice(0, 15)}…${value.slice(-8)}` : value
}

function percent(value?: number) {
  return Number.isFinite(value) ? Number(((value ?? 0) * 100).toFixed(1)) : 0
}

interface ReviewValues {
  reason: string
  valid_until?: { toISOString: () => string }
}

interface CreateRelationValues {
  relation: ApiAuthzObjectRelationType
  object_type: string
  object_ref: string
  principal_id: string
  tenant_id?: string
  valid_from?: { toISOString: () => string }
  valid_until?: { toISOString: () => string }
  evidence_ref?: string
  reason: string
}

interface RevokeValues {
  reason: string
}

interface ReauthorizeValues {
  reason: string
  valid_from: { toISOString: () => string }
  valid_until?: { toISOString: () => string }
}

interface ReviewMutationVariables {
  candidate: ApiAuthzRelationCandidate
  action: 'confirm' | 'reject'
  values: ReviewValues
}

export default function ObjectAuthorizationTab() {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_authorization.relation_manage')
  const canReadEvidence = hasPermission(permissions, 'api_authorization.evidence_read')
  const canReadApps = hasPermission(permissions, 'applications.read')
  const [applicationId, setApplicationId] = useState<string>()
  const [candidateStatusFilter, setCandidateStatusFilter] = useState('PENDING')
  const [relationStatusFilter, setRelationStatusFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState<string>()
  const [candidatePage, setCandidatePage] = useState(1)
  const [relationPage, setRelationPage] = useState(1)
  const [decisionPage, setDecisionPage] = useState(1)
  const [reviewing, setReviewing] = useState<{ candidate: ApiAuthzRelationCandidate; action: 'confirm' | 'reject' } | null>(null)
  const [creating, setCreating] = useState(false)
  const [revoking, setRevoking] = useState<ApiAuthzObjectRelation | null>(null)
  const [reauthorizing, setReauthorizing] = useState<ApiAuthzObjectRelation | null>(null)
  const [decisionDetail, setDecisionDetail] = useState<ApiAuthzDecision | null>(null)
  const [form] = Form.useForm<ReviewValues>()
  const [createForm] = Form.useForm<CreateRelationValues>()
  const [revokeForm] = Form.useForm<RevokeValues>()
  const [reauthForm] = Form.useForm<ReauthorizeValues>()

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'api-authz-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: canReadApps,
  })
  const applicationOptions = useMemo(
    () => (applicationsQuery.data?.items ?? []).map((app) => ({ value: app.id, label: `${app.name}（${app.code}）` })),
    [applicationsQuery.data],
  )

  const coverageQuery = useQuery({
    queryKey: ['api-authz', 'coverage', applicationId],
    queryFn: () => apiAuthzApi.getAuthorizationCoverage(applicationId!),
    enabled: Boolean(applicationId),
  })
  const candidatesQuery = useQuery({
    queryKey: ['api-authz', 'relation-candidates', applicationId, candidateStatusFilter, candidatePage],
    queryFn: () => apiAuthzApi.listRelationCandidates({ application_id: applicationId!, status: candidateStatusFilter || undefined, page: candidatePage, page_size: 20 }),
    enabled: Boolean(applicationId),
  })
  const relationsQuery = useQuery({
    queryKey: ['api-authz', 'object-relations', applicationId, relationStatusFilter, relationPage],
    queryFn: () => apiAuthzApi.listObjectRelations({ application_id: applicationId!, status: relationStatusFilter || undefined, page: relationPage, page_size: 20 }),
    enabled: Boolean(applicationId),
  })
  const decisionsQuery = useQuery({
    queryKey: ['api-authz', 'authorization-decisions', applicationId, decisionFilter, decisionPage],
    queryFn: () => apiAuthzApi.listAuthorizationDecisions({ application_id: applicationId!, decision: decisionFilter, page: decisionPage, page_size: 20 }),
    enabled: Boolean(applicationId),
  })

  const invalidate = () => {
    void qc.invalidateQueries({ queryKey: ['api-authz', 'relation-candidates'] })
    void qc.invalidateQueries({ queryKey: ['api-authz', 'object-relations'] })
    void qc.invalidateQueries({ queryKey: ['api-authz', 'coverage'] })
  }
  const reviewMutation = useMutation<ApiAuthzObjectRelation | ApiAuthzRelationCandidate, unknown, ReviewMutationVariables>({
    mutationFn: ({ candidate, action, values }) =>
      action === 'confirm'
        ? apiAuthzApi.confirmRelationCandidate(candidate.id, {
            relation: 'OWNER',
            reason: values.reason.trim(),
            valid_until: values.valid_until?.toISOString(),
          })
        : apiAuthzApi.rejectRelationCandidate(candidate.id, values.reason.trim()),
    onSuccess: (_, variables) => {
      message.success(variables.action === 'confirm' ? '候选已确认为所有者关系' : '候选已拒绝')
      setReviewing(null)
      form.resetFields()
      invalidate()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '审核失败'),
  })

  const createMutation = useMutation<ApiAuthzObjectRelation, unknown, CreateRelationValues>({
    mutationFn: (values) => {
      if (!applicationId) throw new Error('请选择应用')
      return apiAuthzApi.createObjectRelation({
        application_id: applicationId,
        object_type: values.object_type.trim(),
        object_ref: values.object_ref.trim(),
        principal_id: values.principal_id.trim(),
        tenant_id: values.tenant_id?.trim() || undefined,
        relation: values.relation,
        source: 'MANUAL',
        valid_from: values.valid_from?.toISOString(),
        valid_until: values.valid_until?.toISOString(),
        evidence_ref: values.evidence_ref?.trim() || undefined,
        reason: values.reason.trim(),
      })
    },
    onSuccess: (relation) => {
      message.success(relation.relation === 'SHARED_WITH' ? '共享关系已创建' : '所有者关系已创建')
      setCreating(false)
      createForm.resetFields()
      invalidate()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '创建对象关系失败'),
  })

  const revokeMutation = useMutation<ApiAuthzObjectRelation, unknown, { relation: ApiAuthzObjectRelation; values: RevokeValues }>({
    mutationFn: ({ relation, values }) => apiAuthzApi.revokeObjectRelation(relation.id, { reason: values.reason.trim() }),
    onSuccess: () => {
      message.success('对象关系已撤销')
      setRevoking(null)
      revokeForm.resetFields()
      invalidate()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '撤销对象关系失败'),
  })

  const reauthorizeMutation = useMutation<ApiAuthzObjectRelation, unknown, { relation: ApiAuthzObjectRelation; values: ReauthorizeValues }>({
    mutationFn: ({ relation, values }) =>
      apiAuthzApi.reauthorizeObjectRelation(relation.id, {
        reason: values.reason.trim(),
        valid_from: values.valid_from.toISOString(),
        valid_until: values.valid_until?.toISOString(),
      }),
    onSuccess: () => {
      message.success('关系已重新授权')
      setReauthorizing(null)
      reauthForm.resetFields()
      invalidate()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '重新授权失败'),
  })

  const candidateColumns: ColumnsType<ApiAuthzRelationCandidate> = [
    { title: '状态', dataIndex: 'status', width: 100, render: (value: keyof typeof candidateStatus) => <Tag color={candidateStatus[value]?.color}>{candidateStatus[value]?.label ?? value}</Tag> },
    { title: '对象类型', dataIndex: 'object_type', width: 140, ellipsis: true },
    { title: '对象引用', dataIndex: 'object_ref', width: 230, render: (value: string) => <Typography.Text code title={value}>{shortRef(value)}</Typography.Text> },
    { title: '可信主体', dataIndex: 'principal_id', width: 210, render: (value: string | null, record) => record.legacy_identity_fingerprint ? <Tag>历史指纹，不可确认</Tag> : <Typography.Text code title={value ?? undefined}>{shortRef(value)}</Typography.Text> },
    { title: '租户', dataIndex: 'tenant_id', width: 140, render: shortRef },
    { title: '观测次数', dataIndex: 'observation_count', width: 100 },
    { title: '最近观测', dataIndex: 'last_seen', width: 170, render: formatDateTime },
    {
      title: '操作', key: 'actions', width: 140, fixed: 'right',
      render: (_, record) => {
        const confirmable = record.status === 'PENDING' && Boolean(record.principal_id) && !record.legacy_identity_fingerprint
        return canManage && record.status === 'PENDING' ? (
          <Space size={0}>
            <Button type="link" size="small" disabled={!confirmable} onClick={() => { form.resetFields(); setReviewing({ candidate: record, action: 'confirm' }) }}>确认</Button>
            <Button type="link" size="small" danger onClick={() => { form.resetFields(); setReviewing({ candidate: record, action: 'reject' }) }}>拒绝</Button>
          </Space>
        ) : null
      },
    },
  ]
  const relationColumns: ColumnsType<ApiAuthzObjectRelation> = [
    { title: '状态', dataIndex: 'status', width: 100, render: (value: keyof typeof relationStatus) => <Tag color={relationStatus[value]?.color}>{relationStatus[value]?.label ?? value}</Tag> },
    { title: '对象类型', dataIndex: 'object_type', width: 140 },
    { title: '对象引用', dataIndex: 'object_ref', width: 230, render: (value: string) => <Typography.Text code title={value}>{shortRef(value)}</Typography.Text> },
    { title: '主体', dataIndex: 'principal_id', width: 210, render: (value: string) => <Typography.Text code title={value}>{shortRef(value)}</Typography.Text> },
    {
      title: '关系', dataIndex: 'relation', width: 130,
      render: (value: ApiAuthzObjectRelationType) => {
        const meta = relationKind[value]
        return <Tag color={meta?.color} title={value}>{meta?.label ?? value}</Tag>
      },
    },
    { title: '来源', dataIndex: 'source', width: 130, render: (value: string) => <StatusTag value={value} map={RELATION_SOURCE_META} /> },
    { title: '确认人', dataIndex: 'confirmed_by', width: 130 },
    { title: '生效时间', dataIndex: 'valid_from', width: 170, render: formatDateTime },
    { title: '失效时间', dataIndex: 'valid_until', width: 170, render: formatDateTime },
    { title: '确认原因', dataIndex: 'reason', width: 220, ellipsis: true },
    {
      title: '操作', key: 'actions', width: 170, fixed: 'right',
      render: (_, record) => canManage ? (
        <Space size={0}>
          {record.status === 'CONFIRMED' ? (
            <Button type="link" size="small" danger onClick={() => { revokeForm.resetFields(); setRevoking(record) }}>撤销</Button>
          ) : null}
          {record.status === 'REVOKED' || record.status === 'EXPIRED' ? (
            <Button type="link" size="small" onClick={() => { reauthForm.resetFields(); setReauthorizing(record) }}>重新授权</Button>
          ) : null}
        </Space>
      ) : null,
    },
  ]
  const decisionColumns: ColumnsType<ApiAuthzDecision> = [
    { title: '结论', dataIndex: 'decision', width: 130, render: (value: keyof typeof decisionStatus) => <Tag color={decisionStatus[value]?.color}>{decisionStatus[value]?.label ?? value}</Tag> },
    { title: '接口', dataIndex: 'endpoint_key', width: 280, ellipsis: true },
    { title: '策略版本', dataIndex: 'policy_version', width: 160, ellipsis: true },
    { title: '时间', dataIndex: 'occurred_at', width: 170, render: formatDateTime },
  ]

  const noApplication = !applicationId
  const coverage = coverageQuery.data
  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Space wrap>
        <Typography.Text strong>应用</Typography.Text>
        <Select
          showSearch
          optionFilterProp="label"
          value={applicationId}
          options={applicationOptions}
          loading={applicationsQuery.isLoading}
          placeholder="选择应用后查看对象授权"
          style={{ width: 320 }}
          onChange={(value) => { setApplicationId(value); setCandidatePage(1); setRelationPage(1); setDecisionPage(1) }}
        />
      </Space>
      <QueryErrorAlert error={applicationsQuery.error ?? coverageQuery.error} message="加载对象授权概览失败" />
      {noApplication ? (
        <Card><Typography.Text type="secondary">请选择应用。所有候选、关系和决策都按应用隔离展示。</Typography.Text></Card>
      ) : (
        <>
          <Row gutter={[12, 12]}>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="已验证身份占比" value={percent(coverage?.verified_identity_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="对象模型覆盖" value={percent(coverage?.model_coverage_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="已确认关系占比" value={percent(coverage?.confirmed_relation_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="证据不足占比" value={percent(coverage?.unknown_rate)} suffix="%" valueStyle={{ color: '#ad6800' }} /></Card></Col>
          </Row>
          <Tabs items={[
            {
              key: 'candidates', label: `候选关系（${coverage?.pending_candidates ?? 0}）`, children: <>
                <Space style={{ marginBottom: 12 }}><Select value={candidateStatusFilter} style={{ width: 150 }} options={[{ value: '', label: '全部状态' }, ...Object.entries(candidateStatus).map(([value, meta]) => ({ value, label: meta.label }))]} onChange={(value) => { setCandidateStatusFilter(value); setCandidatePage(1) }} /></Space>
                <QueryErrorAlert error={candidatesQuery.error} message="加载候选关系失败" />
                <SmartTable<ApiAuthzRelationCandidate> rowKey="id" storageKey="api-authz-relation-candidates" columns={candidateColumns} dataSource={candidatesQuery.data?.items ?? []} loading={candidatesQuery.isLoading} pagination={{ current: candidatePage, pageSize: 20, total: candidatesQuery.data?.total ?? 0, showSizeChanger: false, onChange: setCandidatePage }} scroll={{ x: 1350 }} locale={{ emptyText: '暂无候选关系' }} />
              </>,
            },
            {
              key: 'relations', label: `对象关系（已确认 ${coverage?.confirmed_relations ?? 0}）`, children: <>
                <Space style={{ marginBottom: 12 }} wrap>
                  <Select value={relationStatusFilter} style={{ width: 150 }} options={[{ value: '', label: '全部状态' }, ...Object.entries(relationStatus).map(([value, meta]) => ({ value, label: meta.label }))]} onChange={(value) => { setRelationStatusFilter(value); setRelationPage(1) }} />
                  {canManage ? <Button type="primary" onClick={() => { createForm.resetFields(); createForm.setFieldsValue({ relation: 'SHARED_WITH' }); setCreating(true) }}>手工登记关系</Button> : null}
                </Space>
                <QueryErrorAlert error={relationsQuery.error} message="加载对象关系失败" />
                <SmartTable<ApiAuthzObjectRelation> rowKey="id" storageKey="api-authz-object-relations" columns={relationColumns} dataSource={relationsQuery.data?.items ?? []} loading={relationsQuery.isLoading} pagination={{ current: relationPage, pageSize: 20, total: relationsQuery.data?.total ?? 0, showSizeChanger: false, onChange: setRelationPage }} scroll={{ x: 1720 }} locale={{ emptyText: '暂无对象关系' }} />
              </>,
            },
            {
              key: 'decisions', label: `观察决策（${coverage?.decisions ?? 0}）`, children: <>
                <Space style={{ marginBottom: 12 }}><Select allowClear value={decisionFilter} placeholder="全部结论" style={{ width: 170 }} options={Object.entries(decisionStatus).map(([value, meta]) => ({ value, label: meta.label }))} onChange={(value) => { setDecisionFilter(value); setDecisionPage(1) }} /></Space>
                <QueryErrorAlert error={decisionsQuery.error} message="加载授权决策失败" />
                <SmartTable<ApiAuthzDecision> rowKey="id" storageKey="api-authz-decisions" columns={decisionColumns} dataSource={decisionsQuery.data?.items ?? []} loading={decisionsQuery.isLoading} onRow={(record) => ({ onClick: () => setDecisionDetail(record), style: { cursor: 'pointer' } })} pagination={{ current: decisionPage, pageSize: 20, total: decisionsQuery.data?.total ?? 0, showSizeChanger: false, onChange: setDecisionPage }} locale={{ emptyText: '暂无授权决策' }} />
              </>,
            },
          ]} />
        </>
      )}
      <Modal
        open={reviewing !== null}
        title={reviewing?.action === 'confirm' ? '确认所有者关系' : '拒绝候选关系'}
        okText={reviewing?.action === 'confirm' ? '确认关系' : '确认拒绝'}
        okButtonProps={{ danger: reviewing?.action === 'reject' }}
        confirmLoading={reviewMutation.isPending}
        onCancel={() => setReviewing(null)}
        onOk={async () => {
          try {
            const values = await form.validateFields()
            if (reviewing) reviewMutation.mutate({ ...reviewing, values })
          } catch {
            // 校验失败由表单内联提示
          }
        }}
      >
        <Form form={form} layout="vertical">
          {reviewing?.action === 'confirm' ? <Form.Item label="关系"><Input value="所有者" disabled /></Form.Item> : null}
          <Form.Item name="reason" label="审核原因" rules={[{ required: true, whitespace: true, message: '请填写审核原因' }, { max: 500, message: '最多 500 字符' }]}><Input.TextArea rows={3} /></Form.Item>
          {reviewing?.action === 'confirm' ? <Form.Item name="valid_until" label="失效时间（可选）"><DatePicker showTime style={{ width: '100%' }} /></Form.Item> : null}
        </Form>
      </Modal>
      <Modal
        open={creating}
        title="手工登记对象关系"
        okText="确认登记"
        width={640}
        confirmLoading={createMutation.isPending}
        onCancel={() => setCreating(false)}
        onOk={() => createForm.validateFields().then((values) => createMutation.mutate(values), () => { /* 校验失败由表单内联提示 */ })}
      >
        <Form form={createForm} layout="vertical" initialValues={{ relation: 'SHARED_WITH' }}>
          <Form.Item name="relation" label="关系" rules={[{ required: true, message: '请选择关系' }]}>
            <Select options={Object.entries(relationKind).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))} />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, current) => previous.relation !== current.relation}>
            {({ getFieldValue }) => {
              const shared = getFieldValue('relation') === 'SHARED_WITH'
              return (
                <Typography.Paragraph type="secondary">
                  {shared
                    ? '共享方向：object_ref 是被共享的对象（共享源），principal_id 是共享接收人。普通访问候选不会被确认为共享关系。'
                    : '所有者方向：principal_id 是 object_ref 所引用对象的所有者。'}
                  请使用服务端生成的 HMAC 引用，不要填写对象明文。
                </Typography.Paragraph>
              )
            }}
          </Form.Item>
          <Form.Item name="object_type" label="对象类型" rules={[{ required: true, whitespace: true, message: '请填写对象类型' }, { max: 128, message: '最多 128 字符' }]}>
            <Input placeholder="如 order" autoComplete="off" />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(previous, current) => previous.relation !== current.relation}>
            {({ getFieldValue }) => {
              const shared = getFieldValue('relation') === 'SHARED_WITH'
              return (
                <>
                  <Form.Item
                    name="object_ref"
                    label={shared ? '共享源对象 HMAC 引用（object_ref）' : '对象 HMAC 引用（object_ref）'}
                    rules={[
                      { required: true, whitespace: true, message: '请填写对象 HMAC 引用' },
                      { max: 160, message: '最多 160 字符' },
                      {
                        validator: (_, value?: string) => value && /^objref:.+/.test(value.trim())
                          ? Promise.resolve()
                          : Promise.reject(new Error('请输入 objref: 开头的服务端 HMAC 对象引用')),
                      },
                    ]}
                  >
                    <Input placeholder="objref:…" autoComplete="off" />
                  </Form.Item>
                  <Form.Item name="principal_id" label={shared ? '共享接收人（principal_id）' : '所有者（principal_id）'} rules={[{ required: true, whitespace: true, message: '请填写已验证主体 ID' }, { max: 256, message: '最多 256 字符' }]}>
                    <Input placeholder="已验证主体的 HMAC 引用" autoComplete="off" />
                  </Form.Item>
                </>
              )
            }}
          </Form.Item>
          <Form.Item name="tenant_id" label="租户 ID（可选）" rules={[{ max: 256, message: '最多 256 字符' }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="valid_from" label="生效时间（可选，默认立即）">
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="valid_until"
            label="失效时间（可选）"
            dependencies={['valid_from']}
            rules={[({ getFieldValue }) => ({
              validator: (_, value?: { toISOString: () => string }) => {
                const from = getFieldValue('valid_from') as { toISOString: () => string } | undefined
                const error = validateReauthorizationWindow(from, value)
                return error ? Promise.reject(new Error(error)) : Promise.resolve()
              },
            })]}
          >
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item name="evidence_ref" label="证据引用（可选）" rules={[{ max: 256, message: '最多 256 字符' }]}>
            <Input autoComplete="off" />
          </Form.Item>
          <Form.Item name="reason" label="审计原因" rules={[{ required: true, whitespace: true, message: '请填写审计原因' }, { max: 512, message: '最多 512 字符' }]}>
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        open={revoking !== null}
        title={`撤销${relationLabel(revoking?.relation)}关系`}
        okText="确认撤销"
        okButtonProps={{ danger: true }}
        confirmLoading={revokeMutation.isPending}
        onCancel={() => setRevoking(null)}
        onOk={() => revokeForm.validateFields().then((values) => revoking && revokeMutation.mutate({ relation: revoking, values }), () => { /* 校验失败由表单内联提示 */ })}
      >
        {revoking ? (
          <Typography.Paragraph type="secondary">
            {revoking.relation === 'SHARED_WITH' ? '共享源对象' : '对象'}：<Typography.Text code>{revoking.object_ref}</Typography.Text>；
            {revoking.relation === 'SHARED_WITH' ? '共享接收人' : '所有者'}：<Typography.Text code>{revoking.principal_id}</Typography.Text>。
            撤销后保留历史记录并触发授权配置重新发布。
          </Typography.Paragraph>
        ) : null}
        <Form form={revokeForm} layout="vertical">
          <Form.Item name="reason" label="撤销原因" rules={[{ required: true, whitespace: true, message: '请填写撤销原因' }, { max: 512, message: '最多 512 字符' }]}>
            <Input.TextArea rows={3} />
          </Form.Item>
        </Form>
      </Modal>
      <Modal
        open={reauthorizing !== null}
        title={`重新授权${relationLabel(reauthorizing?.relation)}关系`}
        okText="确认重新授权"
        confirmLoading={reauthorizeMutation.isPending}
        onCancel={() => setReauthorizing(null)}
        onOk={() => reauthForm.validateFields().then((values) => reauthorizing && reauthorizeMutation.mutate({ relation: reauthorizing, values }), () => { /* 校验失败由表单内联提示 */ })}
      >
        <Typography.Paragraph type="secondary">
          仅已撤销/已过期的关系可重新授权；提交后按新的生效窗口恢复为已确认关系。
        </Typography.Paragraph>
        <Form form={reauthForm} layout="vertical">
          <Form.Item name="reason" label="授权原因" rules={[{ required: true, whitespace: true, message: '请填写授权原因' }, { max: 512, message: '最多 512 字符' }]}><Input.TextArea rows={3} /></Form.Item>
          <Form.Item name="valid_from" label="生效时间" rules={[{ required: true, message: '请选择生效时间' }]}><DatePicker showTime style={{ width: '100%' }} /></Form.Item>
          <Form.Item
            name="valid_until"
            label="失效时间（可选）"
            dependencies={['valid_from']}
            rules={[({ getFieldValue }) => ({
              validator: (_, value?: { toISOString: () => string }) => {
                const from = getFieldValue('valid_from') as { toISOString: () => string } | undefined
                const error = validateReauthorizationWindow(from, value)
                return error ? Promise.reject(new Error(error)) : Promise.resolve()
              },
            })]}
          >
            <DatePicker showTime style={{ width: '100%' }} />
          </Form.Item>
        </Form>
      </Modal>
      <Drawer
        title="授权决策详情"
        width={760}
        open={decisionDetail !== null}
        onClose={() => setDecisionDetail(null)}
        destroyOnHidden
      >
        {decisionDetail ? (
          <Space direction="vertical" size={16} style={{ width: '100%' }}>
            <Descriptions size="small" column={2} bordered>
              <Descriptions.Item label="结论">
                <Space size={8}>
                  <Tag color={decisionStatus[decisionDetail.decision]?.color}>{decisionStatus[decisionDetail.decision]?.label ?? decisionDetail.decision}</Tag>
                  {hasProposedVerifiedViolation(decisionDetail.checks ?? []) ? <Tag color="gold">拟实断（当前观察模式不实断）</Tag> : null}
                </Space>
              </Descriptions.Item>
              <Descriptions.Item label="时间">{formatDateTime(decisionDetail.occurred_at)}</Descriptions.Item>
              <Descriptions.Item label="接口" span={2}><Typography.Text code>{decisionDetail.endpoint_key}</Typography.Text></Descriptions.Item>
              <Descriptions.Item label="策略版本">{decisionDetail.policy_version || '—'}</Descriptions.Item>
              <Descriptions.Item label="决策 ID"><Typography.Text code copyable={{ text: decisionDetail.decision_id }}>{decisionDetail.decision_id.slice(0, 18)}…</Typography.Text></Descriptions.Item>
            </Descriptions>
            {(() => {
              const enforcement = extractAuthzEnforcement(decisionDetail.evidence)
              return enforcement ? <AuthzEnforcementBlock evidence={enforcement} /> : null
            })()}
            <div>
              <Typography.Text strong>决策链</Typography.Text>
              <Timeline
                style={{ marginTop: 12 }}
                items={(decisionDetail.checks ?? []).map((check, index) => ({
                  color: decisionDetail.decision === 'UNKNOWN' ? 'gray' : decisionDetail.decision === 'VERIFIED_VIOLATION' ? 'red' : 'blue',
                  children: renderDecisionCheck(check, index),
                }))}
              />
            </div>
            {canReadEvidence && decisionDetail.evidence && Object.keys(decisionDetail.evidence).length > 0 ? (
              <div>
                <Typography.Text strong>脱敏证据</Typography.Text>
                <Typography.Paragraph code copyable>{JSON.stringify(decisionDetail.evidence, null, 2)}</Typography.Paragraph>
              </div>
            ) : null}
          </Space>
        ) : null}
      </Drawer>
    </Space>
  )
}
