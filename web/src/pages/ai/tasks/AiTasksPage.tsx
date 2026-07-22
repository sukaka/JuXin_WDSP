import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  Select,
  Space,
  Table,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { aiTasksApi } from '../../../api/ai'
import type { AiTask } from '../../../api/ai'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { formatDateTime } from '../../../utils/format'
import { AI_RISK_META, AI_TASK_STATUS_META, AI_TASK_TYPE_META } from '../../../utils/ai'

interface Filters {
  status?: string
  task_type?: string
}

/** 任务耗时：started_at → finished_at 毫秒差，<1s 显示毫秒，否则显示 x.x 秒 */
function formatDuration(record: AiTask): string {
  if (!record.started_at || !record.finished_at) return '-'
  const ms = dayjs(record.finished_at).diff(dayjs(record.started_at))
  if (Number.isNaN(ms) || ms < 0) return '-'
  if (ms < 1000) return `${ms} 毫秒`
  return `${(ms / 1000).toFixed(1)} 秒`
}

/** AI 任务记录：本人 AI 分析执行历史（计划摘要与状态，不含模型私有思维链） */
export default function AiTasksPage() {
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['ai-tasks', filters, page, pageSize],
    queryFn: () => aiTasksApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['ai-task', selectedId],
    queryFn: () => aiTasksApi.get(selectedId as string),
    enabled: selectedId !== null,
  })

  const columns: ColumnsType<AiTask> = [
    {
      title: '任务类型',
      dataIndex: 'task_type',
      width: 130,
      render: (v: string) => <StatusTag value={v} map={AI_TASK_TYPE_META} />,
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_TASK_STATUS_META} />,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AI_RISK_META} />,
    },
    {
      title: '计划摘要',
      dataIndex: 'plan_summary',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '会话',
      dataIndex: 'session_title',
      width: 160,
      ellipsis: true,
      render: (v: string) => v || '-',
    },
    {
      title: '耗时',
      key: 'duration',
      width: 90,
      render: (_, record) => formatDuration(record),
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
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelectedId(record.id)}>
          详情
        </Button>
      ),
    },
  ]

  const detail = detailQuery.data

  return (
    <Card title="智能任务记录">
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <Typography.Text type="secondary">
          任务记录为本人 AI 分析执行历史（含计划摘要与状态），不含模型私有思维链。
        </Typography.Text>
        <Space wrap>
          <Select
            placeholder="状态"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(AI_TASK_STATUS_META).map(([value, m]) => ({
              value,
              label: m.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, status: v }))
              setPage(1)
            }}
          />
          <Select
            placeholder="任务类型"
            allowClear
            style={{ width: 170 }}
            options={Object.entries(AI_TASK_TYPE_META).map(([value, m]) => ({
              value,
              label: m.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, task_type: v }))
              setPage(1)
            }}
          />
        </Space>
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载任务记录失败" />
        ) : (
          <Table<AiTask>
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1100 }}
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
      </Space>

      <Drawer
        title="任务详情"
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载任务详情失败" />
        ) : detail ? (
          <>
            {detail.failure_message && (
              <Alert
                type="error"
                showIcon
                style={{ marginBottom: 16 }}
                message="任务执行失败"
                description={detail.failure_message}
              />
            )}
            <Descriptions column={2} size="small" bordered>
              <Descriptions.Item label="任务 ID" span={2}>
                <Typography.Text code>{detail.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="任务类型">
                <StatusTag value={detail.task_type} map={AI_TASK_TYPE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detail.status} map={AI_TASK_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <StatusTag value={detail.risk_level} map={AI_RISK_META} />
              </Descriptions.Item>
              <Descriptions.Item label="耗时">{formatDuration(detail)}</Descriptions.Item>
              <Descriptions.Item label="会话" span={2}>
                {detail.session_title || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="会话 ID" span={2}>
                {detail.session_id ? (
                  <Typography.Text code>{detail.session_id}</Typography.Text>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="计划摘要" span={2}>
                {detail.plan_summary || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="开始时间">
                {formatDateTime(detail.started_at)}
              </Descriptions.Item>
              <Descriptions.Item label="结束时间">
                {formatDateTime(detail.finished_at)}
              </Descriptions.Item>
              <Descriptions.Item label="失败码">
                {detail.failure_code || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTime(detail.created_at)}
              </Descriptions.Item>
            </Descriptions>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
