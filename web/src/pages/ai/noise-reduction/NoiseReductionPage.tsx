import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Drawer,
  Form,
  InputNumber,
  List,
  Modal,
  Popconfirm,
  Row,
  Select,
  Space,
  Statistic,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import SmartTable from '../../../components/SmartTable'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { ApiError } from '../../../api/client'
import { aiNoiseApi } from '../../../api/ai'
import type { AiNoiseCluster, AiNoiseSettings, AiNoiseSweepRun } from '../../../api/ai'
import { useAuthStore } from '../../../stores/auth'
import { hasPermission } from '../../../utils/permission'
import { formatDateTime } from '../../../utils/format'
import {
  AI_NOISE_SOURCE_META,
  AI_NOISE_STATUS_META,
  AI_NOISE_SWEEP_STATUS_META,
  AI_NOISE_VERDICT_META,
} from '../../../utils/ai'

// 取值范围与 server/internal/ainoise/worker.go 常量保持一致
const INTERVAL_RANGE = { min: 30, max: 86400 }
const WINDOW_RANGE = { min: 1, max: 1440 }
const THRESHOLD_RANGE = { min: 1, max: 100000 }

interface Filters {
  source?: string
  status?: string
  verdict?: string
}

/** AI 置信度（0-1 小数）→ 百分比文本 */
function formatConfidence(value?: number | null): string {
  if (value === null || value === undefined) return '-'
  return `${(value * 100).toFixed(0)}%`
}

/** 规则标识：WAF 簇展示 rule_id，接口簇展示 detector_code */
function formatRule(record: AiNoiseCluster): string {
  if (record.rule_id !== null && record.rule_id !== undefined) return `#${record.rule_id}`
  return record.detector_code || '-'
}

/** 设置表单字段（与 AiNoiseSettings 一一对应） */
type SettingsFormValues = AiNoiseSettings

/** AI 自动降噪：重复告警指纹聚簇折叠，降低事件噪音；抑制/解决只改簇状态 */
export default function NoiseReductionPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'ai.noise_reduction.manage')

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [sweepsOpen, setSweepsOpen] = useState(false)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [settingsForm] = Form.useForm<SettingsFormValues>()

  const statsQuery = useQuery({
    queryKey: ['ai-noise-stats'],
    queryFn: () => aiNoiseApi.stats(),
  })

  const listQuery = useQuery({
    queryKey: ['ai-noise-clusters', filters, page, pageSize],
    queryFn: () => aiNoiseApi.listClusters({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['ai-noise-cluster', selectedId],
    queryFn: () => aiNoiseApi.getCluster(selectedId as string),
    enabled: selectedId !== null,
  })

  const sweepsQuery = useQuery({
    queryKey: ['ai-noise-sweeps'],
    queryFn: () => aiNoiseApi.listSweeps({ page: 1, page_size: 20 }),
    enabled: sweepsOpen,
  })

  const settingsQuery = useQuery({
    queryKey: ['ai-noise-settings'],
    queryFn: () => aiNoiseApi.getSettings(),
    enabled: settingsOpen && canManage,
  })

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ['ai-noise-clusters'] })
    void queryClient.invalidateQueries({ queryKey: ['ai-noise-cluster'] })
    void queryClient.invalidateQueries({ queryKey: ['ai-noise-stats'] })
    void queryClient.invalidateQueries({ queryKey: ['ai-noise-sweeps'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const transitionMutation = useMutation({
    mutationFn: ({ action, id }: { action: 'suppress' | 'resolve'; id: string }) =>
      action === 'suppress' ? aiNoiseApi.suppressCluster(id) : aiNoiseApi.resolveCluster(id),
    onSuccess: (_, { action }) => {
      message.success(action === 'suppress' ? '簇已抑制' : '簇已恢复解决')
      invalidateAll()
    },
    onError,
  })

  const sweepMutation = useMutation({
    mutationFn: () => aiNoiseApi.triggerSweep(),
    onSuccess: (s) => {
      if (s.status === 'FAILED') {
        message.error(`扫描失败：${s.error || '未知错误'}`)
      } else {
        message.success(
          `扫描完成：扫描事件 ${s.scanned_events} 条，新增簇 ${s.new_clusters} 个，更新簇 ${s.updated_clusters} 个`,
        )
      }
      invalidateAll()
    },
    onError,
  })

  const settingsMutation = useMutation({
    mutationFn: (body: Partial<AiNoiseSettings>) => aiNoiseApi.putSettings(body),
    onSuccess: () => {
      message.success('降噪设置已保存')
      setSettingsOpen(false)
      void queryClient.invalidateQueries({ queryKey: ['ai-noise-settings'] })
    },
    onError,
  })

  const openSettings = () => {
    // Modal destroyOnHidden 保证每次打开时表单按最新设置重挂载
    setSettingsOpen(true)
  }

  const columns: ColumnsType<AiNoiseCluster> = [
    {
      title: '来源',
      dataIndex: 'source',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_NOISE_SOURCE_META} />,
    },
    { title: '主机', dataIndex: 'host', width: 160, ellipsis: true, render: (v: string) => v || '-' },
    {
      title: '归一化 URI',
      dataIndex: 'normalized_uri',
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <Typography.Text style={{ fontFamily: 'monospace' }}>{v}</Typography.Text>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '规则/检测器',
      key: 'rule',
      width: 130,
      render: (_, record) => <Typography.Text code>{formatRule(record)}</Typography.Text>,
    },
    { title: '客户端 IP', dataIndex: 'client_ip', width: 130, render: (v: string) => v || '-' },
    { title: '折叠事件数', dataIndex: 'event_count', width: 100, align: 'right' },
    {
      title: '状态',
      dataIndex: 'status',
      width: 90,
      render: (v: string) => <StatusTag value={v} map={AI_NOISE_STATUS_META} />,
    },
    {
      title: 'AI 研判',
      dataIndex: 'ai_verdict',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_NOISE_VERDICT_META} />,
    },
    {
      title: '置信度',
      dataIndex: 'ai_confidence',
      width: 90,
      align: 'right',
      render: (v?: number | null) => formatConfidence(v),
    },
    {
      title: '最近发生',
      dataIndex: 'last_seen',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: 170,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0} wrap>
          <Button type="link" size="small" onClick={() => setSelectedId(record.id)}>
            详情
          </Button>
          {record.status === 'ACTIVE' && (
            <Popconfirm
              title="抑制该降噪簇"
              description="抑制后该簇的重复事件将继续折叠，确定抑制吗？"
              okText="确定"
              cancelText="取消"
              onConfirm={() => transitionMutation.mutate({ action: 'suppress', id: record.id })}
            >
              <Button type="link" size="small" danger>
                抑制
              </Button>
            </Popconfirm>
          )}
          {record.status === 'SUPPRESSED' && (
            <Popconfirm
              title="恢复该降噪簇"
              description="恢复后该簇标记为已解决，确定恢复吗？"
              okText="确定"
              cancelText="取消"
              onConfirm={() => transitionMutation.mutate({ action: 'resolve', id: record.id })}
            >
              <Button type="link" size="small">
                恢复
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  const sweepColumns: ColumnsType<AiNoiseSweepRun> = [
    { title: '开始时间', dataIndex: 'started_at', width: 170, render: (v: string) => formatDateTime(v) },
    {
      title: '结束时间',
      dataIndex: 'finished_at',
      width: 170,
      render: (v?: string | null) => formatDateTime(v),
    },
    { title: '扫描事件', dataIndex: 'scanned_events', width: 90, align: 'right' },
    { title: '新增簇', dataIndex: 'new_clusters', width: 80, align: 'right' },
    { title: '更新簇', dataIndex: 'updated_clusters', width: 80, align: 'right' },
    { title: 'LLM 调用', dataIndex: 'llm_calls', width: 90, align: 'right' },
    {
      title: '状态',
      dataIndex: 'status',
      width: 100,
      render: (v: string) => <StatusTag value={v} map={AI_NOISE_SWEEP_STATUS_META} />,
    },
    {
      title: '错误',
      dataIndex: 'error',
      ellipsis: true,
      render: (v: string) => v || '-',
    },
  ]

  const detail = detailQuery.data

  return (
    <Card
      title="AI 自动降噪"
      extra={
        <Space wrap>
          {canManage && (
            <Button
              type="primary"
              loading={sweepMutation.isPending}
              onClick={() => sweepMutation.mutate()}
            >
              立即扫描
            </Button>
          )}
          <Button onClick={() => setSweepsOpen(true)}>扫描历史</Button>
          {canManage && <Button onClick={openSettings}>设置</Button>}
        </Space>
      }
    >
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        <Typography.Text type="secondary">
          按攻击指纹将重复告警聚簇折叠，降低事件噪音；抑制/解决只调整簇状态，不影响事件处置与防护策略。
        </Typography.Text>
        {statsQuery.isError ? (
          <QueryErrorAlert error={statsQuery.error} message="加载降噪统计失败" />
        ) : (
          <Row gutter={16}>
            <Col xs={12} md={6}>
              <Card>
                <Statistic
                  title="活跃簇数"
                  value={statsQuery.data?.active_clusters ?? 0}
                  loading={statsQuery.isLoading}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card>
                <Statistic
                  title="已折叠事件总数"
                  value={statsQuery.data?.folded_events ?? 0}
                  loading={statsQuery.isLoading}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card>
                <Statistic
                  title="疑似误报簇数"
                  value={statsQuery.data?.likely_false_positive_clusters ?? 0}
                  loading={statsQuery.isLoading}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card>
                <Statistic
                  title="已抑制簇数"
                  value={statsQuery.data?.suppressed_clusters ?? 0}
                  loading={statsQuery.isLoading}
                />
              </Card>
            </Col>
          </Row>
        )}
        <Space wrap>
          <Select
            aria-label="来源筛选"
            placeholder="来源"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(AI_NOISE_SOURCE_META).map(([value, m]) => ({
              value,
              label: m.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, source: v }))
              setPage(1)
            }}
          />
          <Select
            aria-label="状态筛选"
            placeholder="状态"
            allowClear
            style={{ width: 130 }}
            options={Object.entries(AI_NOISE_STATUS_META).map(([value, m]) => ({
              value,
              label: m.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, status: v }))
              setPage(1)
            }}
          />
          <Select
            aria-label="研判筛选"
            placeholder="AI 研判"
            allowClear
            style={{ width: 140 }}
            options={Object.entries(AI_NOISE_VERDICT_META).map(([value, m]) => ({
              value,
              label: m.label,
            }))}
            onChange={(v) => {
              setFilters((f) => ({ ...f, verdict: v }))
              setPage(1)
            }}
          />
        </Space>
        {listQuery.isError ? (
          <QueryErrorAlert error={listQuery.error} message="加载降噪簇失败" />
        ) : (
          <SmartTable<AiNoiseCluster>
            storageKey="ai-noise-clusters"
            rowKey="id"
            loading={listQuery.isLoading}
            columns={columns}
            dataSource={listQuery.data?.items}
            scroll={{ x: 1400 }}
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
        title="降噪簇详情"
        open={selectedId !== null}
        onClose={() => setSelectedId(null)}
        width={720}
      >
        {detailQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : detailQuery.isError ? (
          <QueryErrorAlert error={detailQuery.error} message="加载降噪簇详情失败" />
        ) : detail ? (
          <>
            <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
              <Descriptions.Item label="簇 ID" span={2}>
                <Typography.Text code>{detail.cluster.id}</Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="指纹" span={2}>
                <Typography.Text code style={{ wordBreak: 'break-all' }}>
                  {detail.cluster.fingerprint_hash}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="来源">
                <StatusTag value={detail.cluster.source} map={AI_NOISE_SOURCE_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detail.cluster.status} map={AI_NOISE_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="主机">{detail.cluster.host || '-'}</Descriptions.Item>
              <Descriptions.Item label="客户端 IP">{detail.cluster.client_ip || '-'}</Descriptions.Item>
              <Descriptions.Item label="归一化 URI" span={2}>
                <Typography.Text style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>
                  {detail.cluster.normalized_uri || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="规则/检测器">
                {formatRule(detail.cluster)}
              </Descriptions.Item>
              <Descriptions.Item label="折叠事件数">{detail.cluster.event_count}</Descriptions.Item>
              <Descriptions.Item label="AI 研判">
                <StatusTag value={detail.cluster.ai_verdict} map={AI_NOISE_VERDICT_META} />
              </Descriptions.Item>
              <Descriptions.Item label="AI 置信度">
                {formatConfidence(detail.cluster.ai_confidence)}
              </Descriptions.Item>
              <Descriptions.Item label="证据摘要" span={2}>
                {detail.cluster.ai_summary || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="首次发生">
                {formatDateTime(detail.cluster.first_seen)}
              </Descriptions.Item>
              <Descriptions.Item label="最近发生">
                {formatDateTime(detail.cluster.last_seen)}
              </Descriptions.Item>
            </Descriptions>
            <Typography.Title level={5}>代表事件</Typography.Title>
            <List
              size="small"
              bordered
              dataSource={detail.events ?? []}
              locale={{ emptyText: '暂无代表事件' }}
              renderItem={(ev) => (
                <List.Item>
                  <Space wrap>
                    <Typography.Text code>{ev.event_id}</Typography.Text>
                    <StatusTag value={ev.source} map={AI_NOISE_SOURCE_META} />
                    {ev.is_representative && <Tag color="geekblue">代表事件</Tag>}
                    <Typography.Text type="secondary">{formatDateTime(ev.created_at)}</Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          </>
        ) : null}
      </Drawer>

      <Modal
        title="扫描历史"
        open={sweepsOpen}
        onCancel={() => setSweepsOpen(false)}
        footer={null}
        width={900}
      >
        {sweepsQuery.isError ? (
          <QueryErrorAlert error={sweepsQuery.error} message="加载扫描历史失败" />
        ) : (
          <Table<AiNoiseSweepRun>
            rowKey="id"
            size="small"
            loading={sweepsQuery.isLoading}
            columns={sweepColumns}
            dataSource={sweepsQuery.data?.items}
            scroll={{ x: 900 }}
            pagination={{
              total: sweepsQuery.data?.total ?? 0,
              pageSize: 20,
              showTotal: (t) => `共 ${t} 条`,
            }}
          />
        )}
      </Modal>

      <Modal
        title="降噪设置"
        open={settingsOpen}
        onCancel={() => setSettingsOpen(false)}
        confirmLoading={settingsMutation.isPending}
        okText="保存"
        cancelText="取消"
        onOk={() => settingsForm.submit()}
        destroyOnHidden
      >
        {settingsQuery.isLoading ? (
          <Typography.Text type="secondary">加载中...</Typography.Text>
        ) : settingsQuery.isError ? (
          <QueryErrorAlert error={settingsQuery.error} message="加载降噪设置失败" />
        ) : settingsQuery.data ? (
          <Form<SettingsFormValues>
            form={settingsForm}
            layout="vertical"
            initialValues={settingsQuery.data}
            onFinish={(values) => settingsMutation.mutate(values)}
          >
            <Form.Item
              name="enabled"
              label="启用自动降噪"
              valuePropName="checked"
              extra="关闭后后台扫描器空转，不再产生新簇"
            >
              <Switch />
            </Form.Item>
            <Form.Item
              name="interval_seconds"
              label="扫描间隔（秒）"
              rules={[{ required: true, message: '请输入扫描间隔' }]}
              extra={`取值范围 ${INTERVAL_RANGE.min}-${INTERVAL_RANGE.max} 秒`}
            >
              <InputNumber min={INTERVAL_RANGE.min} max={INTERVAL_RANGE.max} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="sweep_window_minutes"
              label="扫描窗口（分钟）"
              rules={[{ required: true, message: '请输入扫描窗口' }]}
              extra={`取值范围 ${WINDOW_RANGE.min}-${WINDOW_RANGE.max} 分钟`}
            >
              <InputNumber min={WINDOW_RANGE.min} max={WINDOW_RANGE.max} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="min_events_threshold"
              label="成簇最小事件数"
              rules={[{ required: true, message: '请输入最小事件数阈值' }]}
              extra={`取值范围 ${THRESHOLD_RANGE.min}-${THRESHOLD_RANGE.max}，达到该阈值的指纹才折叠成簇`}
            >
              <InputNumber min={THRESHOLD_RANGE.min} max={THRESHOLD_RANGE.max} precision={0} style={{ width: '100%' }} />
            </Form.Item>
            <Form.Item
              name="llm_verdict_enabled"
              label="启用 LLM 误报评分"
              valuePropName="checked"
              extra="开启后对候选簇调用大模型进行误报研判（产生模型调用成本）"
            >
              <Switch />
            </Form.Item>
          </Form>
        ) : null}
      </Modal>
    </Card>
  )
}
