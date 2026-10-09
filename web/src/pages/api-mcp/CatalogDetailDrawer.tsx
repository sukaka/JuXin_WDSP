import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Alert,
  Button,
  Descriptions,
  Drawer,
  Form,
  InputNumber,
  Modal,
  Radio,
  Select,
  Space,
  Switch,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { mcpApi, type McpTool, type McpToolReviewInput } from '../../api/mcp'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  MCP_CATALOG_STATUS_META,
  MCP_DATA_CLASSIFICATION_META,
  MCP_REVIEW_NOTE,
  MCP_REVIEW_STATUS_META,
  MCP_RISK_LEVEL_META,
  allowedCountText,
  shortMcpHash,
} from '../../utils/mcp'

interface ReviewFormValues {
  action: string
  risk_level: string
  data_classification: string
  allowed_principals: string[]
  allowed_roles: string[]
  allowed_tenants: string[]
  approval_required: boolean
  max_calls_per_minute: number
}

/** 审核对话框：APPROVED/REJECTED + 定级 + 允许主体/角色/租户 + 预算 + approval_required */
function ReviewModal({
  catalogId,
  tool,
  onClose,
}: {
  catalogId: string
  tool: McpTool
  onClose: () => void
}) {
  const { message } = AntdApp.useApp()
  const qc = useQueryClient()
  const [form] = Form.useForm<ReviewFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const reviewMut = useMutation({
    mutationFn: (body: McpToolReviewInput) => mcpApi.reviewTool(catalogId, tool.id, body),
    onSuccess: (saved) => {
      message.success(saved.review_status === 'APPROVED' ? `已通过：${saved.tool_name} 进入发布集（catalog_hash 即时变化）` : `已拒绝：${saved.tool_name} 不下发`)
      void qc.invalidateQueries({ queryKey: ['mcp-catalog', catalogId] })
      void qc.invalidateQueries({ queryKey: ['mcp-catalogs'] })
      onClose()
    },
    onError: (e: unknown) => setSubmitError(e instanceof ApiError ? e.message : '审核提交失败'),
  })

  const watchedAction = Form.useWatch('action', form)

  return (
    <Modal
      title={`审核工具：${tool.tool_name}`}
      open
      onCancel={onClose}
      okText="提交审核"
      confirmLoading={reviewMut.isPending}
      onOk={() => form.submit()}
      width={640}
    >
      {submitError ? (
        <Alert type="error" showIcon style={{ marginBottom: 12 }} message="审核失败" description={submitError} />
      ) : null}
      <Alert type="info" showIcon style={{ marginBottom: 16 }} message={MCP_REVIEW_NOTE} />
      <Descriptions size="small" column={2} bordered style={{ marginBottom: 16 }}>
        <Descriptions.Item label="tool_hash" span={2}>
          <Typography.Text code copyable={{ text: tool.tool_hash }} style={{ fontSize: 12 }}>{tool.tool_hash}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="当前状态">
          <StatusTag value={tool.review_status} map={MCP_REVIEW_STATUS_META} />
        </Descriptions.Item>
        <Descriptions.Item label="描述预览">
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>{tool.description_preview || '—'}</Typography.Text>
        </Descriptions.Item>
      </Descriptions>
      <Form<ReviewFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          action: 'APPROVED',
          risk_level: tool.risk_level,
          data_classification: tool.data_classification,
          allowed_principals: tool.allowed_principals ?? [],
          allowed_roles: tool.allowed_roles ?? [],
          allowed_tenants: tool.allowed_tenants ?? [],
          approval_required: tool.approval_required,
          max_calls_per_minute: tool.max_calls_per_minute,
        }}
        onFinish={(values) => {
          setSubmitError(null)
          reviewMut.mutate({
            action: values.action,
            risk_level: values.risk_level,
            data_classification: values.data_classification,
            allowed_principals: values.allowed_principals ?? [],
            allowed_roles: values.allowed_roles ?? [],
            allowed_tenants: values.allowed_tenants ?? [],
            approval_required: values.approval_required,
            max_calls_per_minute: values.max_calls_per_minute ?? 0,
          })
        }}
      >
        <Form.Item name="action" label="审核结论" rules={[{ required: true, message: '请选择审核结论' }]}>
          <Radio.Group>
            <Radio value="APPROVED">通过（APPROVED，进入发布集）</Radio>
            <Radio value="REJECTED">拒绝（REJECTED，不下发）</Radio>
          </Radio.Group>
        </Form.Item>
        {watchedAction === 'REJECTED' ? (
          <Alert type="warning" showIcon style={{ marginBottom: 12 }} message="拒绝后该工具不出现在发布快照——网关侧「不在册」同一不可调用语义。" />
        ) : null}
        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item name="risk_level" label="风险等级（定级）" rules={[{ required: true, message: '请选择风险等级' }]}>
            <Select
              style={{ width: 160 }}
              options={Object.entries(MCP_RISK_LEVEL_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))}
            />
          </Form.Item>
          <Form.Item name="data_classification" label="数据分级" rules={[{ required: true, message: '请选择数据分级' }]}>
            <Select
              style={{ width: 180 }}
              options={Object.entries(MCP_DATA_CLASSIFICATION_META).map(([value, meta]) => ({ value, label: `${meta.label}（${value}）` }))}
            />
          </Form.Item>
          <Form.Item name="max_calls_per_minute" label="调用预算/分钟" extra="0=不限" rules={[{ required: true, message: '预算必填' }]}>
            <InputNumber min={0} precision={0} style={{ width: 140 }} />
          </Form.Item>
          <Form.Item name="approval_required" label="需审批" valuePropName="checked" extra="G1 语义=默认拒绝（同 HIGH）">
            <Switch />
          </Form.Item>
        </Space>
        <Form.Item name="allowed_principals" label="允许主体（空=该维度不约束；非空逐维 AND）">
          <Select mode="tags" placeholder="回车添加（JWT VerifiedPrincipalID 精确值）" open={false} suffixIcon={null} />
        </Form.Item>
        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item name="allowed_roles" label="允许角色（空=不约束）" style={{ width: 300 }}>
            <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
          </Form.Item>
          <Form.Item name="allowed_tenants" label="允许租户（空=不约束）" style={{ width: 300 }}>
            <Select mode="tags" placeholder="回车添加" open={false} suffixIcon={null} />
          </Form.Item>
        </Space>
      </Form>
    </Modal>
  )
}

/**
 * 目录详情抽屉（NG-MCP G1 §1.14 端点 3/6）：工具行表格（review_status 状态机展示）+
 * 审核对话框（审核状态机：APPROVED/REJECTED + 定级/允许维度/预算）。
 */
export default function CatalogDetailDrawer({
  id,
  canManage,
  onClose,
}: {
  id: string
  canManage: boolean
  onClose: () => void
}) {
  const [reviewing, setReviewing] = useState<McpTool | null>(null)
  const detailQuery = useQuery({
    queryKey: ['mcp-catalog', id],
    queryFn: () => mcpApi.getCatalog(id),
  })
  const detail = detailQuery.data

  const columns: ColumnsType<McpTool> = [
    { title: '工具名', dataIndex: 'tool_name', width: 150, ellipsis: true, render: (v: string) => <Typography.Text strong>{v}</Typography.Text> },
    { title: '版本', dataIndex: 'tool_version', width: 90, render: (v: string) => v || '—' },
    { title: '风险等级', dataIndex: 'risk_level', width: 90, render: (v: string) => <StatusTag value={v} map={MCP_RISK_LEVEL_META} /> },
    { title: '数据分级', dataIndex: 'data_classification', width: 90, render: (v: string) => <StatusTag value={v} map={MCP_DATA_CLASSIFICATION_META} /> },
    { title: '审核状态', dataIndex: 'review_status', width: 100, render: (v: string) => <StatusTag value={v} map={MCP_REVIEW_STATUS_META} /> },
    {
      title: 'tool_hash', dataIndex: 'tool_hash', width: 120,
      render: (v: string) => <Typography.Text code title={v}>{shortMcpHash(v)}</Typography.Text>,
    },
    {
      title: '允许维度', key: 'allowed', width: 190,
      render: (_, record) => (
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          主体 {allowedCountText(record.allowed_principals)} · 角色 {allowedCountText(record.allowed_roles)} · 租户 {allowedCountText(record.allowed_tenants)}
        </Typography.Text>
      ),
    },
    { title: '预算/分', dataIndex: 'max_calls_per_minute', width: 80, render: (v: number) => (v > 0 ? v : '不限') },
    {
      title: '需审批', dataIndex: 'approval_required', width: 80,
      render: (v: boolean) => (v ? <Tag color="red">是</Tag> : '否'),
    },
    {
      title: '审核人/时间', key: 'reviewed', width: 180,
      render: (_, record) =>
        record.reviewed_by ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            {record.reviewed_by} · {record.reviewed_at ? formatDateTime(record.reviewed_at) : '—'}
          </Typography.Text>
        ) : (
          <Typography.Text type="secondary">—</Typography.Text>
        ),
    },
    {
      title: '操作', key: 'actions', width: 80, fixed: 'right',
      render: (_, record) =>
        canManage ? (
          <Button type="link" size="small" onClick={() => setReviewing(record)}>审核</Button>
        ) : null,
    },
  ]

  return (
    <Drawer
      title={detail ? `工具目录：${detail.catalog.name}` : '工具目录详情'}
      width={1080}
      open
      onClose={onClose}
      destroyOnHidden
    >
      <QueryErrorAlert error={detailQuery.error} message="加载目录详情失败" />
      {detail ? (
        <Space direction="vertical" size={16} style={{ width: '100%' }}>
          <Descriptions size="small" column={2} bordered>
            <Descriptions.Item label="服务身份"><Typography.Text code>{detail.catalog.service_identity}</Typography.Text></Descriptions.Item>
            <Descriptions.Item label="协议版本">{detail.catalog.protocol_version}</Descriptions.Item>
            <Descriptions.Item label="状态"><StatusTag value={detail.catalog.status} map={MCP_CATALOG_STATUS_META} /></Descriptions.Item>
            <Descriptions.Item label="来源">{detail.catalog.source === 'MANUAL_IMPORT' ? '显式导入' : detail.catalog.source}</Descriptions.Item>
            <Descriptions.Item label="catalog_hash" span={2}>
              <Typography.Text code copyable={{ text: detail.catalog.catalog_hash }} style={{ fontSize: 12 }}>{detail.catalog.catalog_hash}</Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="版本">v{detail.catalog.version}（乐观锁）</Descriptions.Item>
            <Descriptions.Item label="更新时间">{formatDateTime(detail.catalog.updated_at)}</Descriptions.Item>
          </Descriptions>
          <Alert type="info" showIcon message={MCP_REVIEW_NOTE} />
          <SmartTable<McpTool>
            storageKey="mcp-catalog-tools"
            rowKey="id"
            size="small"
            columns={columns}
            dataSource={detail.tools}
            pagination={false}
            scroll={{ x: 1400 }}
            locale={{ emptyText: '空目录（整体再导入可补充工具行）' }}
          />
        </Space>
      ) : (
        <Typography.Text type="secondary">加载中…</Typography.Text>
      )}
      {reviewing ? <ReviewModal catalogId={id} tool={reviewing} onClose={() => setReviewing(null)} /> : null}
    </Drawer>
  )
}
