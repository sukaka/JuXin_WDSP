import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Segmented,
  Space,
  Typography,
} from 'antd'
import SmartTable from '../../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { useState } from 'react'
import { ApiError } from '../../../../api/client'
import { aiEvaluationsApi, aiFeedbackApi } from '../../../../api/ai'
import type { AiEvalRun, AiEvalSet, AiFeedbackSummaryItem } from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../../../components/RecordDetailDrawer'
import StatusTag from '../../../../components/StatusTag'
import { formatDateTime } from '../../../../utils/format'
import { AI_TASK_STATUS_META, AI_TASK_TYPE_META } from '../../../../utils/ai'
import { useAuthStore } from '../../../../stores/auth'
import { hasPermission } from '../../../../utils/permission'

/** 反馈类型 → 中文标签（与 server chat_handler 允许的 feedback_type 取值一致） */
const FEEDBACK_TYPE_LABEL: Record<string, string> = {
  GENERAL: '一般',
  WRONG_FACT: '事实错误',
  MISSING_EVIDENCE: '缺少依据',
  HALLUCINATION: '幻觉',
  OTHER: '其他',
}

/** AI 质量评估：评估集管理 + 运行记录 */
export default function AiEvaluationsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRun = hasPermission(permissions, 'ai.evaluations.run')
  const canViewFeedback = hasPermission(permissions, 'ai.usage.read')
  const [createOpen, setCreateOpen] = useState(false)
  const [detailSet, setDetailSet] = useState<AiEvalSet | null>(null)
  const [detailRun, setDetailRun] = useState<AiEvalRun | null>(null)
  const [feedbackDays, setFeedbackDays] = useState<7 | 30>(7)
  const [form] = Form.useForm<{
    code: string
    name: string
    description?: string
    cases_json: string
  }>()

  const setsQuery = useQuery({
    queryKey: ['ai-evaluation-sets'],
    queryFn: aiEvaluationsApi.listSets,
  })
  const runsQuery = useQuery({
    queryKey: ['ai-evaluation-runs'],
    queryFn: () => aiEvaluationsApi.listRuns({ page: 1, page_size: 20 }),
  })
  /** 用户反馈聚合（按任务类型 × 反馈类型；不含 comment 明细；后端权限 ai.usage.read） */
  const feedbackQuery = useQuery({
    queryKey: ['ai-feedback-summary', feedbackDays],
    queryFn: () => aiFeedbackApi.summary(feedbackDays),
    enabled: canViewFeedback,
  })

  const createMutation = useMutation({
    mutationFn: aiEvaluationsApi.createSet,
    onSuccess: () => {
      message.success('评估集已创建')
      setCreateOpen(false)
      form.resetFields()
      void queryClient.invalidateQueries({ queryKey: ['ai-evaluation-sets'] })
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '创建失败'),
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => aiEvaluationsApi.run(id),
    onSuccess: (run) => {
      message.success(`评估完成：得分 ${run.score}（${run.passed}/${run.total}）`)
      void queryClient.invalidateQueries({ queryKey: ['ai-evaluation-runs'] })
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '运行失败'),
  })

  const setColumns: ColumnsType<AiEvalSet> = [
    { title: '编码', dataIndex: 'code', width: 160 },
    { title: '名称', dataIndex: 'name' },
    { title: '说明', dataIndex: 'description', ellipsis: true },
    {
      title: '用例数',
      width: 90,
      render: (_, r) => r.cases?.length ?? 0,
    },
    {
      title: '创建时间',
      dataIndex: 'created_at',
      width: 180,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      width: 120,
      render: (_, r) =>
        canRun ? (
          <Button
            type="link"
            size="small"
            loading={runMutation.isPending}
            onClick={() => runMutation.mutate(r.id)}
          >
            运行评估
          </Button>
        ) : (
          '-'
        ),
    },
  ]

  const runColumns: ColumnsType<AiEvalRun> = [
    { title: '评估集', dataIndex: 'set_code', width: 160 },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_TASK_STATUS_META} />,
    },
    {
      title: '得分',
      dataIndex: 'score',
      width: 90,
      render: (v: number | null | undefined) => (v == null ? '-' : v.toFixed(2)),
    },
    {
      title: '开始时间',
      dataIndex: 'started_at',
      width: 180,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '结束时间',
      dataIndex: 'finished_at',
      width: 180,
      render: (v: string | null | undefined) => (v ? formatDateTime(v) : '-'),
    },
  ]

  const feedbackColumns: ColumnsType<AiFeedbackSummaryItem> = [
    {
      title: '任务类型',
      dataIndex: 'task_type',
      width: 160,
      render: (v: string) => AI_TASK_TYPE_META[v]?.label ?? v,
    },
    {
      title: '反馈类型',
      dataIndex: 'feedback_type',
      width: 130,
      render: (v: string) => FEEDBACK_TYPE_LABEL[v] ?? v,
    },
    { title: '反馈总数', dataIndex: 'total', width: 100 },
    {
      title: '负向数',
      dataIndex: 'negative',
      width: 100,
      render: (v: number) =>
        v > 0 ? <Typography.Text type="danger">{v}</Typography.Text> : v,
    },
    {
      title: '负向率',
      dataIndex: 'negative_rate',
      width: 100,
      render: (v: number) => `${v.toFixed(1)}%`,
    },
  ]

  const onCreate = async () => {
    const v = await form.validateFields()
    let cases: { question: string; expected_contains?: string }[] = []
    try {
      const parsed = JSON.parse(v.cases_json) as unknown
      if (!Array.isArray(parsed) || parsed.length === 0) {
        message.warning('用例 JSON 须为非空数组')
        return
      }
      cases = parsed as { question: string; expected_contains?: string }[]
    } catch {
      message.error('用例 JSON 解析失败')
      return
    }
    createMutation.mutate({
      code: v.code.trim(),
      name: v.name.trim(),
      description: v.description?.trim(),
      cases,
    })
  }

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="评估集"
        extra={
          canRun ? (
            <Button type="primary" onClick={() => setCreateOpen(true)}>
              新建评估集
            </Button>
          ) : null
        }
      >
        <Typography.Paragraph type="secondary">
          模型、提示词、智能体或工具变更后应运行回归评估；高风险集未通过不得发布到生产。
        </Typography.Paragraph>
        {setsQuery.isError ? (
          <QueryErrorAlert error={setsQuery.error} message="加载评估集失败" />
        ) : (
          <SmartTable
            storageKey="ai-admin-evaluations"
            rowKey="id"
            size="middle"
            loading={setsQuery.isLoading}
            columns={setColumns}
            dataSource={setsQuery.data ?? []}
            pagination={false}
            onRow={(record) => ({
              onDoubleClick: () => setDetailSet(record),
              style: { cursor: 'pointer' },
            })}
          />
        )}
      </Card>

      <Card title="运行记录">
        {runsQuery.isError ? (
          <QueryErrorAlert error={runsQuery.error} message="加载运行记录失败" />
        ) : (
          <SmartTable
            storageKey="ai-admin-evaluations-2"
            rowKey="id"
            size="middle"
            loading={runsQuery.isLoading}
            columns={runColumns}
            dataSource={runsQuery.data?.items ?? []}
            pagination={false}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRun(record),
              style: { cursor: 'pointer' },
            })}
          />
        )}
      </Card>

      {canViewFeedback && (
        <Card
          title="反馈质量"
          extra={
            <Segmented<7 | 30>
              value={feedbackDays}
              options={[
                { label: '近 7 天', value: 7 },
                { label: '近 30 天', value: 30 },
              ]}
              onChange={setFeedbackDays}
            />
          }
        >
          <Typography.Paragraph type="secondary">
            按任务类型与反馈类型聚合的用户评价（有用/无用）统计，仅展示聚合计数，不含反馈原文。
          </Typography.Paragraph>
          {feedbackQuery.isError ? (
            <QueryErrorAlert error={feedbackQuery.error} message="加载反馈质量统计失败" />
          ) : (
            <SmartTable<AiFeedbackSummaryItem>
              storageKey="ai-admin-feedback-summary"
              rowKey={(r) => `${r.task_type}-${r.feedback_type}`}
              size="middle"
              loading={feedbackQuery.isLoading}
              columns={feedbackColumns}
              dataSource={feedbackQuery.data ?? []}
              pagination={false}
            />
          )}
        </Card>
      )}

      <RecordDetailDrawer
        open={detailSet !== null}
        title="评估集详情"
        record={detailSet as Record<string, unknown> | null}
        onClose={() => setDetailSet(null)}
      />

      <RecordDetailDrawer
        open={detailRun !== null}
        title="评估运行详情"
        record={detailRun as Record<string, unknown> | null}
        onClose={() => setDetailRun(null)}
      />

      <Modal
        title="新建评估集"
        open={createOpen}
        onCancel={() => setCreateOpen(false)}
        onOk={() => void onCreate()}
        confirmLoading={createMutation.isPending}
        width={640}
        destroyOnHidden
      >
        <Form form={form} layout="vertical" initialValues={{ cases_json: '[{"question":"942100 是什么规则","expected_contains":"SQL"}]' }}>
          <Form.Item name="code" label="编码" rules={[{ required: true, message: '必填' }]}>
            <Input placeholder="如 event_analysis_v1" maxLength={50} />
          </Form.Item>
          <Form.Item name="name" label="名称" rules={[{ required: true, message: '必填' }]}>
            <Input maxLength={100} />
          </Form.Item>
          <Form.Item name="description" label="说明">
            <Input.TextArea rows={2} maxLength={500} />
          </Form.Item>
          <Form.Item
            name="cases_json"
            label="用例 JSON"
            rules={[{ required: true, message: '必填' }]}
            extra='数组项字段：question（必填）、expected_contains（可选）'
          >
            <Input.TextArea rows={8} style={{ fontFamily: 'monospace' }} />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  )
}
