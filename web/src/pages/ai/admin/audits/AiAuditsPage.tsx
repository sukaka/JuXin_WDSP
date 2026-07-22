import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  DatePicker,
  Descriptions,
  Drawer,
  Input,
  Select,
  Space,
  Table,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { SafetyOutlined } from '@ant-design/icons'
import type dayjs from 'dayjs'
import { aiAuditsApi } from '../../../../api/ai'
import type { AiAuditRecord } from '../../../../api/ai'
import { ApiError } from '../../../../api/client'
import QueryErrorAlert from '../../../../components/QueryErrorAlert'
import StatusTag from '../../../../components/StatusTag'
import { useAuthStore } from '../../../../stores/auth'
import { AI_TASK_TYPE_META } from '../../../../utils/ai'
import { hasPermission } from '../../../../utils/permission'

interface Filters {
  action?: string
  task_type?: string
  session_id?: string
  start_time?: string
  end_time?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

const TASK_TYPE_OPTIONS = Object.entries(AI_TASK_TYPE_META).map(([value, meta]) => ({
  value,
  label: meta.label,
}))

/** AI 审计：操作记录列表 + 哈希链校验 + 详情抽屉 */
export default function AiAuditsPage() {
  const { message, modal } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selected, setSelected] = useState<AiAuditRecord | null>(null)

  const listQuery = useQuery({
    queryKey: ['ai-audits', filters, page, pageSize],
    queryFn: () => aiAuditsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const verifyMutation = useMutation({
    mutationFn: () => aiAuditsApi.verify(),
    onSuccess: (data) => {
      if (data.ok) {
        modal.success({
          title: '哈希链校验通过',
          content: `共校验 ${data.checked} 条记录，哈希链完整。`,
        })
      } else {
        modal.error({
          title: '哈希链校验未通过',
          content: `发现 ${data.mismatches} 条不一致记录，请立即排查。`,
        })
      }
    },
    onError: (e) => {
      message.error(e instanceof ApiError ? e.message : '校验失败')
    },
  })

  const onRangeChange = (range: RangeValue) => {
    setFilters((f) => ({
      ...f,
      start_time: range?.[0] ? range[0].startOf('day').toISOString() : undefined,
      end_time: range?.[1] ? range[1].endOf('day').toISOString() : undefined,
    }))
    setPage(1)
  }

  const columns: ColumnsType<AiAuditRecord> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 210,
      render: (v: string) => (v ? new Date(v).toLocaleString() : '-'),
    },
    { title: '操作人', dataIndex: 'username', width: 120, render: (v: string) => v || '-' },
    { title: '操作', dataIndex: 'action', width: 140, render: (v: string) => v || '-' },
    {
      title: '任务类型',
      dataIndex: 'task_type',
      width: 120,
      render: (v: string) => (v ? <StatusTag value={v} map={AI_TASK_TYPE_META} /> : '-'),
    },
    { title: 'Agent', dataIndex: 'agent_code', width: 130, render: (v: string) => v || '-' },
    { title: 'Tool', dataIndex: 'tool_code', width: 130, render: (v: string) => v || '-' },
    {
      title: 'Token',
      key: 'tokens',
      width: 110,
      align: 'right',
      render: (_, record) => `${record.input_tokens}+${record.output_tokens}`,
    },
    {
      title: '耗时',
      dataIndex: 'duration_ms',
      width: 100,
      align: 'right',
      render: (v: number) => `${v} 毫秒`,
    },
    {
      title: '操作',
      key: 'actions',
      width: 80,
      fixed: 'right',
      render: (_, record) => (
        <Button type="link" size="small" onClick={() => setSelected(record)}>
          详情
        </Button>
      ),
    },
  ]

  return (
    <Card
      title="AI 审计"
      extra={
        hasPermission(permissions, 'ai.audits.read') && (
          <Button
            icon={<SafetyOutlined />}
            loading={verifyMutation.isPending}
            onClick={() => verifyMutation.mutate()}
          >
            校验哈希链
          </Button>
        )
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <Input.Search
          placeholder="操作"
          allowClear
          style={{ width: 160 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, action: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="任务类型"
          allowClear
          style={{ width: 150 }}
          options={TASK_TYPE_OPTIONS}
          onChange={(v) => {
            setFilters((f) => ({ ...f, task_type: v }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="会话 ID"
          allowClear
          style={{ width: 200 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, session_id: v || undefined }))
            setPage(1)
          }}
        />
        <DatePicker.RangePicker onChange={onRangeChange} />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 AI 审计失败" />
      ) : (
        <Table<AiAuditRecord>
          rowKey={(r) =>
            `${r.occurred_at}-${r.username}-${r.action}-${r.request_summary?.slice(0, 24)}`
          }
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1250 }}
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

      <Drawer
        title="AI 审计详情"
        open={selected !== null}
        onClose={() => setSelected(null)}
        width={720}
      >
        {selected && (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="时间" span={2}>
                {selected.occurred_at ? new Date(selected.occurred_at).toLocaleString() : '-'}
              </Descriptions.Item>
              <Descriptions.Item label="操作人">{selected.username || '-'}</Descriptions.Item>
              <Descriptions.Item label="操作">{selected.action || '-'}</Descriptions.Item>
              <Descriptions.Item label="任务类型">
                {selected.task_type ? (
                  <StatusTag value={selected.task_type} map={AI_TASK_TYPE_META} />
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Agent">{selected.agent_code || '-'}</Descriptions.Item>
              <Descriptions.Item label="Tool">{selected.tool_code || '-'}</Descriptions.Item>
              <Descriptions.Item label="模型">{selected.model_code || '-'}</Descriptions.Item>
              <Descriptions.Item label="Prompt 版本">
                {selected.prompt_version || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="输入 Token">{selected.input_tokens}</Descriptions.Item>
              <Descriptions.Item label="输出 Token">{selected.output_tokens}</Descriptions.Item>
              <Descriptions.Item label="耗时">{selected.duration_ms} 毫秒</Descriptions.Item>
              <Descriptions.Item label="预估成本">
                ¥{selected.estimated_cost.toFixed(4)}
              </Descriptions.Item>
              <Descriptions.Item label="用户 ID">{selected.user_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="确认结果">
                {selected.confirm_result || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="会话 ID" span={2}>
                {selected.session_id || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="任务 ID" span={2}>
                {selected.task_id || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="草稿引用" span={2}>
                {selected.draft_reference || '-'}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>请求摘要</Typography.Title>
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>
              {selected.request_summary || '-'}
            </Typography.Paragraph>
            <Typography.Title level={5}>结果摘要</Typography.Title>
            <Typography.Paragraph style={{ whiteSpace: 'pre-wrap' }}>
              {selected.result_summary || '-'}
            </Typography.Paragraph>
          </>
        )}
      </Drawer>
    </Card>
  )
}
