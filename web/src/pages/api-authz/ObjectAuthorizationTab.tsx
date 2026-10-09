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

/** OBSERVE 形态降级留痕（NG-AZ-03 §1.1）：checks 中任一检查携带 proposed_decision=VERIFIED_VIOLATION */
function hasProposedVerifiedViolation(checks: unknown[]): boolean {
  return checks.some(
    (c) => typeof c === 'object' && c !== null && (c as Record<string, unknown>).proposed_decision === 'VERIFIED_VIOLATION',
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
  const [applicationId, setApplicationId] = useState<string>()
  const [candidateStatusFilter, setCandidateStatusFilter] = useState('PENDING')
  const [relationStatusFilter, setRelationStatusFilter] = useState('')
  const [decisionFilter, setDecisionFilter] = useState<string>()
  const [candidatePage, setCandidatePage] = useState(1)
  const [relationPage, setRelationPage] = useState(1)
  const [decisionPage, setDecisionPage] = useState(1)
  const [reviewing, setReviewing] = useState<{ candidate: ApiAuthzRelationCandidate; action: 'confirm' | 'reject' } | null>(null)
  const [reauthorizing, setReauthorizing] = useState<ApiAuthzObjectRelation | null>(null)
  const [decisionDetail, setDecisionDetail] = useState<ApiAuthzDecision | null>(null)
  const [form] = Form.useForm<ReviewValues>()
  const [reauthForm] = Form.useForm<ReauthorizeValues>()

  const applicationsQuery = useQuery({
    queryKey: ['applications', 'api-authz-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
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
      message.success(variables.action === 'confirm' ? '候选已确认为 OWNER 关系' : '候选已拒绝')
      setReviewing(null)
      form.resetFields()
      invalidate()
    },
    onError: (error: unknown) => message.error(error instanceof ApiError ? error.message : '审核失败'),
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
    { title: '关系', dataIndex: 'relation', width: 90, render: () => <Tag color="blue">OWNER</Tag> },
    { title: '来源', dataIndex: 'source', width: 130, render: (value: string) => <StatusTag value={value} map={RELATION_SOURCE_META} /> },
    { title: '确认人', dataIndex: 'confirmed_by', width: 130 },
    { title: '生效时间', dataIndex: 'valid_from', width: 170, render: formatDateTime },
    { title: '失效时间', dataIndex: 'valid_until', width: 170, render: formatDateTime },
    { title: '确认原因', dataIndex: 'reason', width: 220, ellipsis: true },
    {
      title: '操作', key: 'actions', width: 110, fixed: 'right',
      render: (_, record) =>
        canManage && (record.status === 'REVOKED' || record.status === 'EXPIRED') ? (
          <Button type="link" size="small" onClick={() => { reauthForm.resetFields(); setReauthorizing(record) }}>重新授权</Button>
        ) : null
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
            <Col xs={12} lg={6}><Card size="small"><Statistic title="VERIFIED 身份占比" value={percent(coverage?.verified_identity_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="对象模型覆盖" value={percent(coverage?.model_coverage_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="已确认关系占比" value={percent(coverage?.confirmed_relation_rate)} suffix="%" /></Card></Col>
            <Col xs={12} lg={6}><Card size="small"><Statistic title="UNKNOWN 率" value={percent(coverage?.unknown_rate)} suffix="%" valueStyle={{ color: '#ad6800' }} /></Card></Col>
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
                <Space style={{ marginBottom: 12 }}><Select value={relationStatusFilter} style={{ width: 150 }} options={[{ value: '', label: '全部状态' }, ...Object.entries(relationStatus).map(([value, meta]) => ({ value, label: meta.label }))]} onChange={(value) => { setRelationStatusFilter(value); setRelationPage(1) }} /></Space>
                <QueryErrorAlert error={relationsQuery.error} message="加载对象关系失败" />
                <SmartTable<ApiAuthzObjectRelation> rowKey="id" storageKey="api-authz-object-relations" columns={relationColumns} dataSource={relationsQuery.data?.items ?? []} loading={relationsQuery.isLoading} pagination={{ current: relationPage, pageSize: 20, total: relationsQuery.data?.total ?? 0, showSizeChanger: false, onChange: setRelationPage }} scroll={{ x: 1650 }} locale={{ emptyText: '暂无对象关系' }} />
              </>,
            },
            {
              key: 'decisions', label: `OBSERVE 决策（${coverage?.decisions ?? 0}）`, children: <>
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
        title={reviewing?.action === 'confirm' ? '确认 OWNER 关系' : '拒绝候选关系'}
        okText={reviewing?.action === 'confirm' ? '确认关系' : '确认拒绝'}
        okButtonProps={{ danger: reviewing?.action === 'reject' }}
        confirmLoading={reviewMutation.isPending}
        onCancel={() => setReviewing(null)}
        onOk={() => form.validateFields().then((values) => reviewing && reviewMutation.mutate({ ...reviewing, values }))}
      >
        <Form form={form} layout="vertical">
          {reviewing?.action === 'confirm' ? <Form.Item label="关系"><Input value="OWNER" disabled /></Form.Item> : null}
          <Form.Item name="reason" label="审核原因" rules={[{ required: true, whitespace: true, message: '请填写审核原因' }, { max: 500, message: '最多 500 字符' }]}><Input.TextArea rows={3} /></Form.Item>
          {reviewing?.action === 'confirm' ? <Form.Item name="valid_until" label="失效时间（可选）"><DatePicker showTime style={{ width: '100%' }} /></Form.Item> : null}
        </Form>
      </Modal>
      <Modal
        open={reauthorizing !== null}
        title="重新授权 OWNER 关系"
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
                  {hasProposedVerifiedViolation(decisionDetail.checks ?? []) ? <Tag color="gold">拟实断（当前 OBSERVE 不实断）</Tag> : null}
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
                  children: <Typography.Text code>{`${index + 1}. ${JSON.stringify(check)}`}</Typography.Text>,
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
