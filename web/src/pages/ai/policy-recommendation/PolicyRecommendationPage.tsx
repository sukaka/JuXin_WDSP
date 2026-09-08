import { useState } from 'react'
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
import { aiAnalyzeApi, aiDraftsApi } from '../../../api/ai'
import type { AiAnalyzeResult, AiDraft } from '../../../api/ai'
import AnalyzeResultView from '../../../components/ai/AnalyzeResultView'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime, formatJson } from '../../../utils/format'
import { hasAnyPermission, hasPermission } from '../../../utils/permission'
import { AI_DRAFT_STATUS_META, AI_DRAFT_TYPE_META, AI_RISK_META } from '../../../utils/ai'

interface DraftFilters {
  status?: string
  recommendation_type?: string
}

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
  const [whatIfForm] = Form.useForm<{ rule_id: number }>()
  const [whatIfLoading, setWhatIfLoading] = useState(false)
  const [whatIfResult, setWhatIfResult] = useState<AiAnalyzeResult | null>(null)

  const onWhatIfAnalyze = async () => {
    let ruleId: number
    try {
      const v = await whatIfForm.validateFields()
      ruleId = v.rule_id
    } catch {
      // 表单校验未通过，antd 已展示错误提示
      return
    }
    setWhatIfLoading(true)
    setWhatIfResult(null)
    try {
      setWhatIfResult(await aiAnalyzeApi.whatIf({ rule_id: ruleId }))
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
  const [selectedDraftId, setSelectedDraftId] = useState<string | null>(null)

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
            输入规则 ID，模拟启用/调整该规则对历史请求的影响。模拟基于历史数据估算，仅供参考。
          </Typography.Paragraph>
          <Form form={whatIfForm} layout="inline" style={{ rowGap: 8 }}>
            <Form.Item
              name="rule_id"
              label="规则 ID"
              rules={[{ required: true, message: '请输入规则 ID' }]}
            >
              <InputNumber placeholder="如 942100" style={{ width: 200 }} min={1} precision={0} />
            </Form.Item>
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
