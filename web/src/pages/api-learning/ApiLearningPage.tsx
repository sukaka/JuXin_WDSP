import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { App as AntdApp, Button, Card, Descriptions, Empty, InputNumber, Select, Space, Tag, Typography } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { apiEndpointsApi } from '../../api/apiAssets'
import { apiLearningApi, type ApiLearningSample } from '../../api/apiSecurity'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { formatLearningExcludeReason } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import { API_LEARNING_STATUS_META } from '../../utils/stage8'

/** 学习任务（job）状态，与 server/internal/apiassets LearningJob.Status 枚举一致 */
const LEARNING_JOB_STATUS_META: Record<string, { color: string; label: string }> = {
  RUNNING: { color: 'processing', label: '运行中' },
  STOPPED: { color: 'default', label: '已停止' },
  COMPLETED: { color: 'green', label: '已完成' },
}

/** API 学习中心（WDSP / 阶段8）：按接口查看学习状态、学习任务与采集样本，可启动/停止学习 */
export default function ApiLearningPage() {
  const { message, modal } = AntdApp.useApp()
  const qc = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canStart = hasPermission(permissions, 'api_learning.start')
  const canStop = hasPermission(permissions, 'api_learning.stop')

  const [endpointId, setEndpointId] = useState<string | undefined>()
  const [accepted, setAccepted] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiLearningSample | null>(null)

  /** 接口选择器数据源（学习按接口查看） */
  const endpointsQuery = useQuery({
    queryKey: ['api-endpoints', 'options'],
    queryFn: () => apiEndpointsApi.list({ page: 1, page_size: 100 }),
  })

  /** 接口列表加载后默认选中第一个，避免页面空白 */
  useEffect(() => {
    if (!endpointId && endpointsQuery.data?.items.length) {
      setEndpointId(endpointsQuery.data.items[0].id)
    }
  }, [endpointId, endpointsQuery.data])

  const statusQuery = useQuery({
    queryKey: ['api-learning', 'status', endpointId],
    queryFn: () => apiLearningApi.status(endpointId as string),
    enabled: !!endpointId,
  })

  const samplesQuery = useQuery({
    queryKey: ['api-learning', 'samples', endpointId, accepted, page, pageSize],
    queryFn: () =>
      apiLearningApi.samples(endpointId as string, { accepted, page, page_size: pageSize }),
    enabled: !!endpointId,
  })

  const startMut = useMutation({
    mutationFn: (sampleTarget?: number) =>
      apiLearningApi.start(
        endpointId as string,
        sampleTarget ? { sample_target: sampleTarget } : undefined,
      ),
    onSuccess: (r) => {
      message.success(r.message || '已启动学习')
      void qc.invalidateQueries({ queryKey: ['api-learning'] })
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '启动学习失败'),
  })

  const stopMut = useMutation({
    mutationFn: () => apiLearningApi.stop(endpointId as string),
    onSuccess: (r) => {
      message.success(r.message || '已停止学习')
      void qc.invalidateQueries({ queryKey: ['api-learning'] })
      void qc.invalidateQueries({ queryKey: ['api-endpoints'] })
    },
    onError: (e: unknown) => message.error(e instanceof ApiError ? e.message : '停止学习失败'),
  })

  const selectedEndpoint = endpointsQuery.data?.items.find((e) => e.id === endpointId)
  const learningStatus = statusQuery.data?.learning_status ?? selectedEndpoint?.learning_status ?? ''
  const job = statusQuery.data?.job ?? null

  /** 变更类操作统一二次确认 */
  const startLearning = () => {
    let sampleTarget = 100
    modal.confirm({
      title: '启动学习',
      content: (
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <span>
            确定启动接口「{selectedEndpoint?.endpoint_key ?? '-'}」的模型学习吗？
          </span>
          <span>
            样本目标：
            <InputNumber
              min={10}
              max={100000}
              defaultValue={100}
              onChange={(v) => {
                sampleTarget = typeof v === 'number' ? v : 100
              }}
            />
          </span>
          <Typography.Text type="secondary">
            有效样本达到目标后自动完成学习并生成模型候选（候选仍需人工完善并确认后才生效）。
          </Typography.Text>
        </Space>
      ),
      onOk: () => startMut.mutate(sampleTarget),
    })
  }

  const stopLearning = () => {
    modal.confirm({
      title: '停止学习',
      content: `确定停止接口「${selectedEndpoint?.endpoint_key ?? '-'}」的模型学习吗？停止后已采集样本保留，可再次启动继续学习。`,
      onOk: () => stopMut.mutate(),
    })
  }

  const columns: ColumnsType<ApiLearningSample> = [
    {
      title: '样本哈希',
      dataIndex: 'sample_hash',
      width: 140,
      render: (v: string) => (v ? <Typography.Text code>{v.slice(0, 10)}…</Typography.Text> : '-'),
    },
    {
      title: '响应状态码',
      dataIndex: 'response_status',
      width: 110,
      render: (v?: number | null) => (v ?? '-'),
    },
    {
      title: '样本状态',
      dataIndex: 'accepted',
      width: 100,
      render: (v: boolean) => (v ? <Tag color="green">已采纳</Tag> : <Tag>已排除</Tag>),
    },
    {
      title: '排除原因',
      dataIndex: 'exclude_reason',
      ellipsis: true,
      render: (v: string) => formatLearningExcludeReason(v),
    },
    {
      title: '采集时间',
      dataIndex: 'collected_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
  ]

  return (
    <Card
      title="API 学习中心"
      extra={
        <Space>
          {canStart && learningStatus !== 'LEARNING' ? (
            <Button type="primary" onClick={startLearning} loading={startMut.isPending} disabled={!endpointId}>
              启动学习
            </Button>
          ) : null}
          {canStop && learningStatus === 'LEARNING' ? (
            <Button danger onClick={stopLearning} loading={stopMut.isPending} disabled={!endpointId}>
              停止学习
            </Button>
          ) : null}
        </Space>
      }
    >
      <Typography.Paragraph type="secondary">
        选择接口后查看其学习状态、学习任务与采集样本；启动学习后网关按样本目标采集流量，样本经有效性校验后用于生成模型候选。
      </Typography.Paragraph>
      <QueryErrorAlert error={endpointsQuery.error ?? statusQuery.error ?? samplesQuery.error} />
      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="选择接口"
          showSearch
          optionFilterProp="label"
          style={{ width: 320 }}
          loading={endpointsQuery.isLoading}
          value={endpointId}
          options={(endpointsQuery.data?.items ?? []).map((e) => ({
            value: e.id,
            label: e.endpoint_key,
          }))}
          onChange={(v) => {
            setEndpointId(v)
            setPage(1)
          }}
        />
        <Select
          placeholder="样本状态"
          allowClear
          style={{ width: 140 }}
          value={accepted}
          options={[
            { value: 'true', label: '已采纳' },
            { value: 'false', label: '已排除' },
          ]}
          onChange={(v) => {
            setAccepted(v)
            setPage(1)
          }}
        />
        {learningStatus ? (
          <span>
            学习状态：<StatusTag value={learningStatus} map={API_LEARNING_STATUS_META} />
          </span>
        ) : null}
      </Space>

      <Card size="small" title="学习任务" style={{ marginBottom: 16 }}>
        {job ? (
          <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }}>
            <Descriptions.Item label="任务状态">
              <StatusTag value={job.status} map={LEARNING_JOB_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="样本目标">{job.sample_target}</Descriptions.Item>
            <Descriptions.Item label="已采集">{job.collected_count}</Descriptions.Item>
            <Descriptions.Item label="有效">{job.valid_count}</Descriptions.Item>
            <Descriptions.Item label="排除">{job.excluded_count}</Descriptions.Item>
            <Descriptions.Item label="最近错误">{job.last_error || '-'}</Descriptions.Item>
          </Descriptions>
        ) : (
          <Empty description="暂无学习任务，启动学习后此处展示任务进度" />
        )}
      </Card>

      <SmartTable<ApiLearningSample>
        storageKey="api-learning"
        rowKey="id"
        loading={samplesQuery.isLoading}
        columns={columns}
        dataSource={samplesQuery.data?.items ?? []}
        locale={endpointId ? undefined : { emptyText: '请先选择接口查看样本' }}
        scroll={{ x: 1000 }}
        onRow={(record) => ({
          onDoubleClick: () => setDetailRecord(record),
          style: { cursor: 'pointer' },
        })}
        pagination={{
          current: page,
          pageSize,
          total: samplesQuery.data?.total ?? 0,
          showSizeChanger: true,
          showTotal: (t) => `共 ${t} 条`,
          onChange: (p, ps) => {
            setPage(p)
            setPageSize(ps)
          },
        }}
      />
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="学习样本详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Card>
  )
}
