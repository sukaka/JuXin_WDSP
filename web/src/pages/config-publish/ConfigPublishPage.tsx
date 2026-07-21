import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Progress,
  Space,
  Table,
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  CheckCircleOutlined,
  CloudUploadOutlined,
  ExperimentOutlined,
  ReloadOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { gatewayConfigApi, publishTasksApi } from '../../api/gatewayConfig'
import type { PreviewResult } from '../../api/gatewayConfig'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  PUBLISH_RESULT_META,
  TASK_STATUS_META,
  isTerminalTaskStatus,
  truncateHash,
} from '../../utils/stage3'
import type { BusinessSnapshot, PublishTaskItem } from '../../types'

/** 业务摘要表格（preview 响应对象 / version 字符串两种来源共用） */
export function SnapshotTable({ snapshot }: { snapshot: BusinessSnapshot | null }) {
  if (!snapshot || !snapshot.apps || snapshot.apps.length === 0) {
    return <Typography.Text type="secondary">无应用纳入本次配置</Typography.Text>
  }
  return (
    <Table
      rowKey="code"
      size="small"
      pagination={false}
      dataSource={snapshot.apps}
      columns={[
        { title: '应用编码', dataIndex: 'code' },
        { title: '防护模式', dataIndex: 'mode', width: 110, render: (v: string) => <Tag>{v}</Tag> },
        { title: '域名数', dataIndex: 'domains', width: 90, align: 'right' },
        { title: '源站数', dataIndex: 'upstreams', width: 90, align: 'right' },
      ]}
    />
  )
}

/** 发布任务进度卡（轮询真实任务状态） */
export function PublishTaskProgress({ taskId }: { taskId: string }) {
  const taskQuery = useQuery({
    queryKey: ['publish-task', taskId],
    queryFn: () => publishTasksApi.get(taskId),
    refetchInterval: (query) =>
      query.state.data && isTerminalTaskStatus(query.state.data.status) ? false : 1500,
  })
  const task = taskQuery.data
  if (!task) return <Typography.Text type="secondary">加载任务状态…</Typography.Text>
  const terminal = isTerminalTaskStatus(task.status)
  const progressStatus = task.status === 'SUCCESS' ? 'success' : task.status === 'FAILED' ? 'exception' : 'active'
  return (
    <Card size="small" title={`发布任务 ${task.id.slice(0, 8)}…`} style={{ marginTop: 16 }}>
      <Space direction="vertical" style={{ display: 'flex' }} size={12}>
        <Space>
          <StatusTag value={task.status} map={TASK_STATUS_META} />
          <Typography.Text type="secondary">{task.current_step || '等待执行'}</Typography.Text>
        </Space>
        <Progress percent={task.progress} status={progressStatus} />
        {task.status === 'FAILED' && (
          <Alert
            type="error"
            showIcon
            message={`发布失败（${task.failure_code || '未知原因'}）`}
            description={task.failure_message || task.result_summary}
          />
        )}
        {task.status === 'SUCCESS' && (
          <Alert type="success" showIcon message="发布成功" description={task.result_summary} />
        )}
        {!terminal && <Typography.Text type="secondary">任务执行中，每 1.5 秒自动刷新…</Typography.Text>}
      </Space>
    </Card>
  )
}

export default function ConfigPublishPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [preview, setPreview] = useState<PreviewResult | null>(null)
  const [validateResult, setValidateResult] = useState<{ valid: boolean; error?: string } | null>(null)
  const [activeTaskId, setActiveTaskId] = useState<string | null>(null)
  const [taskPage, setTaskPage] = useState(1)

  const currentQuery = useQuery({
    queryKey: ['gateway-config-current'],
    queryFn: gatewayConfigApi.current,
  })

  const tasksQuery = useQuery({
    queryKey: ['publish-tasks', taskPage],
    queryFn: () => publishTasksApi.list({ page: taskPage, page_size: 10 }),
    retry: 1,
  })

  const previewMutation = useMutation({
    mutationFn: gatewayConfigApi.preview,
    onSuccess: (data) => setPreview(data),
    onError: (e) => message.error(e instanceof ApiError ? e.message : '预览失败'),
  })

  const validateMutation = useMutation({
    mutationFn: gatewayConfigApi.validate,
    onSuccess: (data) => setValidateResult({ valid: data.valid, error: data.error }),
    onError: (e) => message.error(e instanceof ApiError ? e.message : '校验失败'),
  })

  const publishMutation = useMutation({
    mutationFn: () => gatewayConfigApi.publish({ idempotency_key: crypto.randomUUID() }),
    onSuccess: (task) => {
      setActiveTaskId(task.id)
      void queryClient.invalidateQueries({ queryKey: ['gateway-config-current'] })
      void queryClient.invalidateQueries({ queryKey: ['publish-tasks'] })
      void queryClient.invalidateQueries({ queryKey: ['config-versions'] })
      if (task.status === 'SUCCESS') message.success('发布成功')
      else if (task.status === 'FAILED') message.error('发布失败，请查看任务详情')
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '发布失败'),
  })

  const confirmPublish = () => {
    modal.confirm({
      title: '高风险操作确认',
      content:
        '发布将把当前全部已启用应用的配置下发到防护网关并立即生效，失败时会自动回滚。确定执行发布吗？',
      okText: '确认发布',
      okButtonProps: { danger: true },
      onOk: () => publishMutation.mutate(),
    })
  }

  const current = currentQuery.data
  const taskColumns: ColumnsType<PublishTaskItem> = [
    {
      title: '任务',
      dataIndex: 'id',
      width: 110,
      render: (v: string) => <Typography.Text code>{v.slice(0, 8)}</Typography.Text>,
    },
    {
      title: '类型',
      dataIndex: 'task_type',
      width: 90,
      render: (v: string) => (v === 'ROLLBACK' ? <Tag color="orange">回滚</Tag> : <Tag color="blue">发布</Tag>),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={TASK_STATUS_META} />,
    },
    { title: '当前步骤', dataIndex: 'current_step', width: 130, render: (v: string) => v || '-' },
    {
      title: '进度',
      dataIndex: 'progress',
      width: 130,
      render: (v: number, record) => (
        <Progress
          percent={v}
          size="small"
          status={record.status === 'FAILED' ? 'exception' : record.status === 'SUCCESS' ? 'success' : 'active'}
        />
      ),
    },
    {
      title: '发起时间',
      dataIndex: 'requested_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '结果摘要',
      dataIndex: 'result_summary',
      ellipsis: true,
      render: (v: string, record) => (
        <Typography.Text type={record.status === 'FAILED' ? 'danger' : undefined}>
          {v || record.failure_message || '-'}
        </Typography.Text>
      ),
    },
  ]

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title="当前生效版本"
        extra={
          <Button icon={<ReloadOutlined />} onClick={() => void currentQuery.refetch()}>
            刷新
          </Button>
        }
      >
        {currentQuery.isLoading && <Typography.Text type="secondary">加载中…</Typography.Text>}
        {currentQuery.isError && (
          <Alert
            type="error"
            showIcon
            message="加载当前版本失败"
            description={currentQuery.error instanceof ApiError ? currentQuery.error.message : undefined}
          />
        )}
        {current && !current.has_current && (
          <Alert type="warning" showIcon message="网关尚未发布过配置，当前无生效版本" />
        )}
        {current?.has_current && current.version && (
          <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
            <Descriptions.Item label="版本号">{current.version.version_number}</Descriptions.Item>
            <Descriptions.Item label="配置哈希">
              <Typography.Text copyable={{ text: current.version.configuration_hash }} style={{ fontFamily: 'monospace' }}>
                {truncateHash(current.version.configuration_hash)}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="发布结果">
              <StatusTag value={current.version.publish_result} map={PUBLISH_RESULT_META} />
            </Descriptions.Item>
            <Descriptions.Item label="发布时间">
              {formatDateTime(current.version.published_at)}
            </Descriptions.Item>
            <Descriptions.Item label="变更摘要" span={2}>
              {current.version.change_summary || '-'}
            </Descriptions.Item>
          </Descriptions>
        )}
      </Card>

      <Card title="配置操作">
        <Space wrap>
          {hasPermission(permissions, 'gateway_configs.preview') && (
            <Button
              icon={<ExperimentOutlined />}
              loading={previewMutation.isPending}
              onClick={() => previewMutation.mutate()}
            >
              预览配置
            </Button>
          )}
          {hasPermission(permissions, 'gateway_configs.validate') && (
            <Button
              icon={<CheckCircleOutlined />}
              loading={validateMutation.isPending}
              onClick={() => validateMutation.mutate()}
            >
              校验配置
            </Button>
          )}
          {hasPermission(permissions, 'gateway_configs.publish') && (
            <Button
              type="primary"
              danger
              icon={<CloudUploadOutlined />}
              loading={publishMutation.isPending}
              onClick={confirmPublish}
            >
              发布到网关
            </Button>
          )}
        </Space>

        {validateResult && (
          <Alert
            style={{ marginTop: 16 }}
            type={validateResult.valid ? 'success' : 'error'}
            showIcon
            message={validateResult.valid ? '配置校验通过，可以发布' : '配置校验未通过'}
            description={validateResult.valid ? undefined : validateResult.error}
            closable
            onClose={() => setValidateResult(null)}
          />
        )}

        {activeTaskId && <PublishTaskProgress taskId={activeTaskId} />}
      </Card>

      <Card title="发布任务记录">
        {tasksQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载发布任务列表失败"
            description={tasksQuery.error instanceof ApiError ? tasksQuery.error.message : undefined}
          />
        ) : (
          <Table<PublishTaskItem>
            rowKey="id"
            loading={tasksQuery.isLoading}
            columns={taskColumns}
            dataSource={tasksQuery.data?.items}
            pagination={{
              current: taskPage,
              pageSize: 10,
              total: tasksQuery.data?.total ?? 0,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p) => setTaskPage(p),
            }}
          />
        )}
      </Card>

      <Drawer
        title="配置预览"
        open={preview !== null}
        onClose={() => setPreview(null)}
        width={720}
      >
        {preview && (
          <Space direction="vertical" size={16} style={{ display: 'flex' }}>
            <Descriptions column={3} size="small" bordered>
              <Descriptions.Item label="配置哈希">
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {truncateHash(preview.configuration_hash)}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="Server 数">{preview.server_count}</Descriptions.Item>
              <Descriptions.Item label="Route 数">{preview.route_count}</Descriptions.Item>
            </Descriptions>
            <div>
              <Typography.Title level={5}>业务摘要</Typography.Title>
              <SnapshotTable snapshot={preview.business_snapshot} />
            </div>
            <div>
              <Typography.Title level={5}>Caddy 配置 JSON</Typography.Title>
              <Typography.Paragraph>
                <pre
                  style={{
                    maxHeight: 420,
                    overflow: 'auto',
                    background: '#f5f5f5',
                    padding: 12,
                    fontSize: 12,
                  }}
                >
                  {formatJson(preview.config_preview)}
                </pre>
              </Typography.Paragraph>
            </div>
          </Space>
        )}
      </Drawer>
    </Space>
  )
}
