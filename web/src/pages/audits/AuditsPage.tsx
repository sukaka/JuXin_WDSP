import { useState } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  Alert,
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
  Tag,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { DownloadOutlined, SafetyOutlined } from '@ant-design/icons'
import type dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { auditsApi } from '../../api/audits'
import RiskLevelTag from '../../components/RiskLevelTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime, formatJson } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type { AuditEntry } from '../../types'

interface Filters {
  username?: string
  module?: string
  action?: string
  result?: string
  risk_level?: string
  start_time?: string
  end_time?: string
}

type RangeValue = [dayjs.Dayjs | null, dayjs.Dayjs | null] | null

export default function AuditsPage() {
  const { message, modal } = AntdApp.useApp()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)

  const listQuery = useQuery({
    queryKey: ['audits', filters, page, pageSize],
    queryFn: () => auditsApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['audit', selectedId],
    queryFn: () => auditsApi.detail(selectedId as string),
    enabled: selectedId !== null,
  })

  const verifyMutation = useMutation({
    mutationFn: auditsApi.verifyChain,
    onSuccess: (data) => {
      if (data.valid) {
        modal.success({
          title: '哈希链校验通过',
          content: '审计日志哈希链完整，未发现被篡改的记录。',
        })
      } else {
        modal.error({
          title: '哈希链校验未通过',
          content: (
            <div>
              <p>发现 {data.mismatch_count} 条不一致记录，请立即排查审计数据完整性。</p>
              {data.mismatch_ids.length > 0 && (
                <Typography.Paragraph
                  style={{ fontFamily: 'monospace', fontSize: 12, maxHeight: 200, overflow: 'auto' }}
                >
                  {data.mismatch_ids.join('\n')}
                </Typography.Paragraph>
              )}
            </div>
          ),
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

  const columns: ColumnsType<AuditEntry> = [
    { title: '时间', dataIndex: 'occurred_at', width: 170, render: (v: string) => formatDateTime(v) },
    { title: '操作人', dataIndex: 'username', width: 120 },
    { title: '来源 IP', dataIndex: 'source_ip', width: 130 },
    { title: '模块', dataIndex: 'module', width: 120 },
    { title: '操作', dataIndex: 'action', width: 120 },
    {
      title: '对象',
      key: 'object',
      width: 160,
      render: (_, record) => record.object_name || record.object_id || '-',
    },
    {
      title: '结果',
      dataIndex: 'result',
      width: 90,
      render: (v: string) =>
        v === 'SUCCESS' ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>,
    },
    {
      title: '风险等级',
      dataIndex: 'risk_level',
      width: 100,
      render: (v: string) => <RiskLevelTag level={v} />,
    },
    {
      title: '操作',
      key: 'actions',
      width: 90,
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
    <Card
      title="操作审计"
      extra={
        <Space>
          {hasPermission(permissions, 'audits.read') && (
            <Button
              icon={<SafetyOutlined />}
              loading={verifyMutation.isPending}
              onClick={() => verifyMutation.mutate()}
            >
              校验哈希链
            </Button>
          )}
          {hasPermission(permissions, 'audits.export') && (
            <Button
              icon={<DownloadOutlined />}
              onClick={() => window.open(auditsApi.exportUrl(filters), '_blank')}
            >
              导出 CSV
            </Button>
          )}
        </Space>
      }
    >
      <Space style={{ marginBottom: 16 }} wrap>
        <DatePicker.RangePicker onChange={onRangeChange} />
        <Input.Search
          placeholder="操作人"
          allowClear
          style={{ width: 150 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, username: v || undefined }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="模块"
          allowClear
          style={{ width: 140 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, module: v || undefined }))
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="操作"
          allowClear
          style={{ width: 140 }}
          onSearch={(v) => {
            setFilters((f) => ({ ...f, action: v || undefined }))
            setPage(1)
          }}
        />
        <Select
          placeholder="结果"
          allowClear
          style={{ width: 110 }}
          options={[
            { value: 'SUCCESS', label: '成功' },
            { value: 'FAILURE', label: '失败' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, result: v }))
            setPage(1)
          }}
        />
        <Select
          placeholder="风险等级"
          allowClear
          style={{ width: 120 }}
          options={[
            { value: 'LOW', label: '低' },
            { value: 'MEDIUM', label: '中' },
            { value: 'HIGH', label: '高' },
            { value: 'CRITICAL', label: '严重' },
          ]}
          onChange={(v) => {
            setFilters((f) => ({ ...f, risk_level: v }))
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载操作审计失败"
          description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
        />
      ) : (
        <Table<AuditEntry>
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1150 }}
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
        title="审计详情"
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        width={640}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载审计详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="时间" span={2}>{formatDateTime(detail.occurred_at)}</Descriptions.Item>
              <Descriptions.Item label="操作人">{detail.username}</Descriptions.Item>
              <Descriptions.Item label="来源 IP">{detail.source_ip}</Descriptions.Item>
              <Descriptions.Item label="模块">{detail.module}</Descriptions.Item>
              <Descriptions.Item label="操作">{detail.action}</Descriptions.Item>
              <Descriptions.Item label="对象类型">{detail.object_type || '-'}</Descriptions.Item>
              <Descriptions.Item label="对象名称">{detail.object_name || detail.object_id || '-'}</Descriptions.Item>
              <Descriptions.Item label="结果">
                {detail.result === 'SUCCESS' ? <Tag color="green">成功</Tag> : <Tag color="red">失败</Tag>}
              </Descriptions.Item>
              <Descriptions.Item label="风险等级">
                <RiskLevelTag level={detail.risk_level} />
              </Descriptions.Item>
              {detail.failure_reason && (
                <Descriptions.Item label="失败原因" span={2}>{detail.failure_reason}</Descriptions.Item>
              )}
              <Descriptions.Item label="请求 ID" span={2}>
                <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable={detail.request_id ? { text: detail.request_id } : false}>
                  {detail.request_id || '-'}
                </Typography.Text>
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>变更前</Typography.Title>
            <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 6, maxHeight: 240, overflow: 'auto', fontSize: 12 }}>
              {formatJson(detail.before_summary)}
            </pre>
            <Typography.Title level={5}>变更后</Typography.Title>
            <pre style={{ background: '#f5f5f5', padding: 12, borderRadius: 6, maxHeight: 240, overflow: 'auto', fontSize: 12 }}>
              {formatJson(detail.after_summary)}
            </pre>
          </>
        ) : null}
      </Drawer>
    </Card>
  )
}
