import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  Modal,
  Space,
  Typography,
} from 'antd'
import SmartTable from '../../../../components/SmartTable'
import type { ColumnsType } from 'antd/es/table'
import { useState } from 'react'
import { ApiError } from '../../../../api/client'
import { aiEvaluationsApi } from '../../../../api/ai'
import type { AiEvalRun, AiEvalSet } from '../../../../api/ai'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import { formatDateTime } from '../../../../utils/format'
import { useAuthStore } from '../../../../stores/auth'
import { hasPermission } from '../../../../utils/permission'

/** AI 质量评估：评估集管理 + 运行记录 */
export default function AiEvaluationsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRun = hasPermission(permissions, 'ai.evaluations.run')
  const [createOpen, setCreateOpen] = useState(false)
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
    { title: '状态', dataIndex: 'status', width: 100 },
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
          />
        )}
      </Card>

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
