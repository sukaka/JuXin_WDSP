import { useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Select,
  Space,
  Tag,
  Typography,
} from 'antd'
import SmartTable from '../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { SearchOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { aiAnalyzeApi, aiDraftsApi, aiRecommendationsApi } from '../../../api/ai'
import type { AiAnalyzeResult, AiDraft } from '../../../api/ai'
import { exceptionsApi } from '../../../api/exceptions'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime, formatJson } from '../../../utils/format'
import { hasAnyPermission, hasPermission } from '../../../utils/permission'
import { AI_DRAFT_ACTIONABLE_STATUSES, AI_DRAFT_STATUS_META, AI_DRAFT_TARGET_ROUTES, AI_DRAFT_TYPE_META, AI_RISK_META } from '../../../utils/ai'
import {
  WHAT_IF_PARANOIA_LEVEL_OPTIONS,
  WHAT_IF_SCENARIO_OPTIONS,
  WHAT_IF_TIME_RANGE_OPTIONS,
  buildWhatIfBody,
  whatIfSupportsTimeRange,
} from './whatIf'
import type { WhatIfFormValues, WhatIfScenario } from './whatIf'

interface DraftFilters {
  status?: string
  recommendation_type?: string
}

/** remove_exception 例外下拉拉取条数上限（例外量级有限，一次拉取供选择） */
const WHAT_IF_EXCEPTION_PAGE_SIZE = 200

/** AI 草稿查看权限点（任一即可） */
const DRAFT_VIEW_PERMISSIONS = [
  'ai.draft.exception',
  'ai.draft.blacklist',
  'ai.draft.cc_policy',
  'ai.draft.custom_rule',
]

/** 策略建议：AI 策略优化建议 + What-If 策略模拟 + AI 草稿列表（草稿不自动生效） */
export default function PolicyRecommendationPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canWhatIf = hasPermission(permissions, 'ai.what_if.use')
  const canViewDrafts = hasAnyPermission(permissions, DRAFT_VIEW_PERMISSIONS)

  /* ---------- 策略优化建议 ---------- */
  const [policyForm] = Form.useForm<{ question?: string }>()
  const [policyLoading, setPolicyLoading] = useState(false)
  const [policyResult, setPolicyResult] = useState<AiAnalyzeResult | null>(null)

  const onPolicyAnalyze = async () => {
    const question = policyForm.getFieldValue('question')?.trim()
    setPolicyLoading(true)
    setPolicyResult(null)
    try {
      setPolicyResult(
        await aiAnalyzeApi.policyRecommendation({ question: question || undefined }),
      )
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setPolicyLoading(false)
    }
  }

  /* ---------- What-If 策略模拟 ---------- */
  const [whatIfForm] = Form.useForm<WhatIfFormValues>()
  const [whatIfScenario, setWhatIfScenario] = useState<WhatIfScenario>('disable_rule')
  const [whatIfLoading, setWhatIfLoading] = useState(false)
  const [whatIfResult, setWhatIfResult] = useState<AiAnalyzeResult | null>(null)

  // remove_exception 场景例外下拉（拉既有例外列表接口）
  const whatIfExceptionsQuery = useQuery({
    queryKey: ['what-if-exceptions'],
    queryFn: () => exceptionsApi.list({ page: 1, page_size: WHAT_IF_EXCEPTION_PAGE_SIZE }),
    enabled: canWhatIf && whatIfScenario === 'remove_exception',
  })

  const onWhatIfAnalyze = async () => {
    let v: WhatIfFormValues
    try {
      v = await whatIfForm.validateFields()
    } catch {
      // 表单校验未通过，antd 已展示错误提示
      return
    }
    let body
    try {
      body = buildWhatIfBody(v)
    } catch (e) {
      message.error(e instanceof Error ? e.message : '参数校验失败')
      return
    }
    setWhatIfLoading(true)
    setWhatIfResult(null)
    try {
      setWhatIfResult(await aiAnalyzeApi.whatIf(body))
    } catch (e) {
      message.error(e instanceof ApiError ? e.message : '分析执行失败')
    } finally {
      setWhatIfLoading(false)
    }
  }

  /* ---------- AI 草稿 ---------- */
  const [draftFilters, setDraftFilters] = useState<DraftFilters>({})
  const [draftPage, setDraftPage] = useState(1)
  const [draftPageSize, setDraftPageSize] = useState(20)
  // 深链 ?draft_id=xxx（智能审计等入口跳转）：直接打开对应草稿详情
  const [selectedDraftId, setSelectedDraftId] = useState<string | null>(
    () => searchParams.get('draft_id')?.trim() || null,
  )

  const draftsQuery = useQuery({
    queryKey: ['ai-drafts', draftFilters, draftPage, draftPageSize],
    queryFn: () =>
      aiDraftsApi.list({ ...draftFilters, page: draftPage, page_size: draftPageSize }),
    enabled: canViewDrafts,
  })

  const draftDetailQuery = useQuery({
    queryKey: ['ai-draft', selectedDraftId],
    queryFn: () => aiDraftsApi.get(selectedDraftId as string),
    enabled: selectedDraftId !== null,
  })

  const discardMutation = useMutation({
    mutationFn: (id: string) => aiDraftsApi.discard(id),
    onSuccess: () => {
      message.success('草稿已废弃')
      void queryClient.invalidateQueries({ queryKey: ['ai-drafts'] })
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '废弃失败')
    },
  })

  const acceptMutation = useMutation({
    mutationFn: (id: string) => aiRecommendationsApi.accept(id),
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '采纳失败')
    },
  })

  const rejectMutation = useMutation({
    mutationFn: (id: string) => aiRecommendationsApi.reject(id),
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '拒绝失败')
    },
  })

  const invalidateDrafts = (id: string) => {
    void queryClient.invalidateQueries({ queryKey: ['ai-drafts'] })
    void queryClient.invalidateQueries({ queryKey: ['ai-draft', id] })
  }

  /** 采纳：仅标记 ACCEPTED，不创建/发布任何配置；按草稿类型给出人工落地页面入口 */
  const onAccept = (record: AiDraft) => {
    modal.confirm({
      title: '采纳草稿确认',
      content:
        '采纳仅将草稿标记为「已采纳」，不会自动创建或发布任何配置，仍需人工在对应页面完成创建与发布。确认采纳？',
      okText: '采纳',
      cancelText: '取消',
      onOk: () =>
        acceptMutation.mutateAsync(record.id).then(() => {
          invalidateDrafts(record.id)
          const target = AI_DRAFT_TARGET_ROUTES[record.recommendation_type]
          modal.success({
            title: '草稿已采纳（尚未生效）',
            content: (
              <Space direction="vertical" size={12} style={{ display: 'flex' }}>
                <Typography.Text>
                  草稿已标记为「已采纳」，配置不会自动生效。请前往对应业务页面人工创建配置，并按既有流程校验发布。
                </Typography.Text>
                {target && (
                  <Button type="primary" onClick={() => navigate(target.path)}>
                    前往{target.label}页面
                  </Button>
                )}
              </Space>
            ),
          })
        }),
    })
  }

  /** 拒绝：标记 REJECTED，草稿不再进入后续人工流程 */
  const onReject = (record: AiDraft) => {
    modal.confirm({
      title: '拒绝草稿确认',
      content: '拒绝后草稿标记为「已废弃」，不会生效。确认拒绝？',
      okText: '拒绝',
      okButtonProps: { danger: true },
      cancelText: '取消',
      onOk: () =>
        rejectMutation.mutateAsync(record.id).then(() => {
          message.success('草稿已拒绝')
          invalidateDrafts(record.id)
        }),
    })
  }

  const onDiscard = (record: AiDraft) => {
    modal.confirm({
      title: '废弃确认',
      content: '确定废弃该 AI 草稿吗？废弃后不可恢复。',
      okText: '废弃',
      okButtonProps: { danger: true },
      onOk: () => discardMutation.mutate(record.id),
    })
  }

  const draftColumns: ColumnsType<AiDraft> = [
    {
      title: '类型',
      dataIndex: 'recommendation_type',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={AI_DRAFT_TYPE_META} />,
    },
    {
      title: '摘要',
      dataIndex: 'summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AI_RISK_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => <StatusTag value={v} map={AI_DRAFT_STATUS_META} />,
    },
    {
      title: '来源',
      dataIndex: 'created_by_ai',
      width: 90,
      render: (v: boolean) => (v ? <Tag color="purple">AI生成</Tag> : '-'),
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 130,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setSelectedDraftId(record.id)}>
            详情
          </Button>
          <Button
            type="link"
            size="small"
            danger
            disabled={record.status !== 'DRAFT'}
            onClick={() => onDiscard(record)}
          >
            废弃
          </Button>
        </Space>
      ),
    },
  ]

  const draft = draftDetailQuery.data

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card title="策略优化建议">
        <Typography.Paragraph type="secondary">
          由 AI 结合当前策略配置与历史安全数据给出优化建议，可填写关注点（如：例外收敛）聚焦分析方向。
        </Typography.Paragraph>
        <Form form={policyForm} layout="inline" style={{ rowGap: 8 }}>
          <Form.Item name="question" label="关注点">
            <Input placeholder="可选，如：例外收敛" style={{ width: 320 }} allowClear />
          </Form.Item>
          <Form.Item>
            <Button
              type="primary"
              icon={<SearchOutlined />}
              loading={policyLoading}
              onClick={() => void onPolicyAnalyze()}
            >
              生成建议
            </Button>
          </Form.Item>
        </Form>
        {policyLoading && (
          <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
            AI 正在分析，通常需要数秒到数十秒，请稍候...
          </Typography.Paragraph>
        )}
        {policyResult && <AnalyzeResultView result={policyResult} />}
      </Card>

      {canWhatIf && (
        <Card title="情景策略模拟">
          <Typography.Paragraph type="secondary">
            选择模拟场景：关闭/启用规则、修改异常阈值、切换 CRS 执行等级、新增/删除例外、修改 CC
            阈值或调整封禁时长。模拟基于历史事件数据离线统计估算（非逐请求回放），仅供参考。
          </Typography.Paragraph>
          <Form
            form={whatIfForm}
            layout="inline"
            style={{ rowGap: 8 }}
            initialValues={{ scenario: 'disable_rule', time_range: '7d' }}
          >
            <Form.Item name="scenario" label="模拟场景" rules={[{ required: true }]}>
              <Select
                style={{ width: 190 }}
                options={WHAT_IF_SCENARIO_OPTIONS}
                onChange={(v: WhatIfScenario) => setWhatIfScenario(v)}
              />
            </Form.Item>
            {(whatIfScenario === 'disable_rule' ||
              whatIfScenario === 'enable_rule' ||
              whatIfScenario === 'add_exception') && (
              <Form.Item
                name="rule_id"
                label="规则 ID"
                rules={[{ required: true, message: '请输入规则 ID' }]}
              >
                <InputNumber placeholder="如 942100" style={{ width: 200 }} min={1} precision={0} />
              </Form.Item>
            )}
            {whatIfScenario === 'anomaly_threshold' && (
              <Form.Item
                name="anomaly_threshold"
                label="新异常阈值"
                rules={[{ required: true, message: '请输入模拟的异常阈值' }]}
              >
                <InputNumber
                  placeholder="1-10000，如 5"
                  style={{ width: 200 }}
                  min={1}
                  max={10000}
                  precision={0}
                />
              </Form.Item>
            )}
            {whatIfScenario === 'pl_switch' && (
              <Form.Item
                name="paranoia_level"
                label="CRS 执行等级"
                rules={[{ required: true, message: '请选择 CRS 执行等级' }]}
              >
                <Select style={{ width: 260 }} options={WHAT_IF_PARANOIA_LEVEL_OPTIONS} />
              </Form.Item>
            )}
            {whatIfScenario === 'remove_exception' && (
              <Form.Item
                name="exception_id"
                label="例外"
                rules={[{ required: true, message: '请选择要模拟删除的例外' }]}
              >
                <Select
                  showSearch
                  optionFilterProp="label"
                  placeholder="选择例外"
                  style={{ width: 320 }}
                  loading={whatIfExceptionsQuery.isLoading}
                  options={(whatIfExceptionsQuery.data?.items ?? []).map((e) => ({
                    value: e.id,
                    label: `${e.name}（${e.id.slice(0, 8)}）`,
                  }))}
                />
              </Form.Item>
            )}
            {whatIfScenario === 'cc_threshold' && (
              <Form.Item
                name="cc_threshold"
                label="新 CC 阈值"
                rules={[{ required: true, message: '请输入模拟的 CC 阈值' }]}
              >
                <InputNumber
                  placeholder="次/窗口，如 200"
                  style={{ width: 200 }}
                  min={1}
                  max={1000000}
                  precision={0}
                />
              </Form.Item>
            )}
            {whatIfScenario === 'block_duration' && (
              <Form.Item
                name="block_duration_seconds"
                label="新封禁时长"
                rules={[{ required: true, message: '请输入模拟的封禁时长（秒）' }]}
              >
                <InputNumber
                  placeholder="秒，如 3600"
                  style={{ width: 200 }}
                  min={60}
                  max={2592000}
                  precision={0}
                />
              </Form.Item>
            )}
            {whatIfSupportsTimeRange(whatIfScenario) && (
              <Form.Item name="time_range" label="历史数据区间">
                <Select style={{ width: 140 }} options={WHAT_IF_TIME_RANGE_OPTIONS} />
              </Form.Item>
            )}
            <Form.Item>
              <Button
                type="primary"
                icon={<SearchOutlined />}
                loading={whatIfLoading}
                onClick={() => void onWhatIfAnalyze()}
              >
                开始模拟
              </Button>
            </Form.Item>
          </Form>
          {whatIfLoading && (
            <Typography.Paragraph type="secondary" style={{ marginTop: 16 }}>
              AI 正在分析，通常需要数秒到数十秒，请稍候...
            </Typography.Paragraph>
          )}
          {whatIfResult && <AnalyzeResultView result={whatIfResult} />}
        </Card>
      )}

      {canViewDrafts && (
        <Card title="智能草稿">
          <Alert
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message="智能草稿不会自动生效，需经人工审核后进入既有校验发布流程"
          />
          <Space style={{ marginBottom: 16 }} wrap>
            <Select
              placeholder="状态"
              allowClear
              style={{ width: 140 }}
              options={Object.entries(AI_DRAFT_STATUS_META).map(([value, m]) => ({
                value,
                label: m.label,
              }))}
              onChange={(v) => {
                setDraftFilters((f) => ({ ...f, status: v }))
                setDraftPage(1)
              }}
            />
            <Select
              placeholder="类型"
              allowClear
              style={{ width: 140 }}
              options={Object.entries(AI_DRAFT_TYPE_META).map(([value, m]) => ({
                value,
                label: m.label,
              }))}
              onChange={(v) => {
                setDraftFilters((f) => ({ ...f, recommendation_type: v }))
                setDraftPage(1)
              }}
            />
          </Space>
          {draftsQuery.isError ? (
            <QueryErrorAlert error={draftsQuery.error} message="加载 AI 草稿失败" />
          ) : (
            <SmartTable<AiDraft>
              storageKey="ai-policy-recommendation"
              rowKey="id"
              loading={draftsQuery.isLoading}
              columns={draftColumns}
              dataSource={draftsQuery.data?.items}
              scroll={{ x: 1000 }}
              onRow={(record) => ({
                onDoubleClick: () => setSelectedDraftId(record.id),
                style: { cursor: 'pointer' },
              })}
              pagination={{
                current: draftPage,
                pageSize: draftPageSize,
                total: draftsQuery.data?.total ?? 0,
                showSizeChanger: true,
                showTotal: (t) => `共 ${t} 条`,
                onChange: (p, ps) => {
                  setDraftPage(p)
                  setDraftPageSize(ps)
                },
              }}
            />
          )}
        </Card>
      )}

      <Drawer
        title="草稿详情"
        open={selectedDraftId !== null}
        onClose={() => setSelectedDraftId(null)}
        width={640}
        footer={
          draft && AI_DRAFT_ACTIONABLE_STATUSES.includes(draft.status) ? (
            <Space style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <Button
                type="primary"
                loading={acceptMutation.isPending}
                onClick={() => onAccept(draft)}
              >
                采纳
              </Button>
              <Button danger loading={rejectMutation.isPending} onClick={() => onReject(draft)}>
                拒绝
              </Button>
            </Space>
          ) : undefined
        }
      >
        {draftDetailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : draftDetailQuery.isError ? (
          <QueryErrorAlert error={draftDetailQuery.error} message="加载草稿详情失败" />
        ) : draft ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="类型">
                <StatusTag value={draft.recommendation_type} map={AI_DRAFT_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={draft.status} map={AI_DRAFT_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <StatusTag value={draft.risk_level} map={AI_RISK_META} />
              </Descriptions.Item>
              <Descriptions.Item label="来源">
                {draft.created_by_ai ? <Tag color="purple">AI生成</Tag> : '人工'}
              </Descriptions.Item>
              <Descriptions.Item label="草稿 ID" span={2}>
                <Typography.Text code>{draft.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="任务 ID" span={2}>
                {draft.task_id ? <Typography.Text code>{draft.task_id}</Typography.Text> : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="目标类型">
                {draft.target_type || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="目标 ID">{draft.target_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="草稿引用" span={2}>
                {draft.draft_reference || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="审核人">{draft.reviewed_by || '-'}</Descriptions.Item>
              <Descriptions.Item label="审核时间">
                {formatDateTime(draft.reviewed_at)}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间" span={2}>
                {formatDateTime(draft.created_at)}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>摘要</Typography.Title>
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>
              {draft.summary || '-'}
            </Typography.Paragraph>
            <Typography.Title level={5}>证据引用</Typography.Title>
            <pre
              style={{
                background: '#f5f5f5',
                padding: 12,
                borderRadius: 6,
                maxHeight: 320,
                overflow: 'auto',
                fontSize: 12,
              }}
            >
              {formatJson(draft.evidence_references)}
            </pre>
          </>
        ) : null}
      </Drawer>
    </Space>
  )
}
