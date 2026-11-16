import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Card,
  Checkbox,
  Col,
  Input,
  Radio,
  Row,
  Space,
  Statistic,
  Tag,
  Tooltip,
  Typography,
  Tabs,
} from 'antd'
import SecurityPoliciesTab from './SecurityPoliciesTab'
import type { ColumnsType } from 'antd/es/table'
import {
  apiLLMApi,
  type ApiLLMObservation,
  type ApiLLMStats,
} from '../../api/apiLLM'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'

/** 可空文本展示：NULL/空串统一占位符 */
function dash(v?: string | number | null): string | number {
  return v === null || v === undefined || v === '' ? '-' : v
}

/** 模型展示名（空串 = 未声明模型，与后端口径一致单列一组） */
function modelLabel(model: string): string {
  return model === '' ? '未声明' : model
}

/** 模型分布图（观测数与命中数同量级，双柱并列；token 量级差异大不入图） */
function modelDistOption(stats?: ApiLLMStats): EChartOption {
  const rows = stats?.by_model ?? []
  return {
    grid: { left: 48, right: 16, top: 40, bottom: 60 },
    tooltip: { trigger: 'axis' },
    legend: { data: ['观测数', '命中观测数'], top: 0 },
    xAxis: {
      type: 'category',
      data: rows.map((r) => modelLabel(r.model)),
      axisLabel: { rotate: rows.length > 4 ? 30 : 0, hideOverlap: true },
    },
    yAxis: { type: 'value', minInterval: 1 },
    series: [
      {
        name: '观测数',
        type: 'bar',
        data: rows.map((r) => r.observations),
        barMaxWidth: 32,
      },
      {
        name: '命中观测数',
        type: 'bar',
        data: rows.map((r) => r.findings),
        itemStyle: { color: '#f5222d' },
        barMaxWidth: 32,
      },
    ],
  }
}

/** findings 单元格：命中逐条标红（rule_id 优先，缺省 detector），多于 2 条折叠为 +N */
function FindingsCell({
  findings,
}: {
  findings: ApiLLMObservation['findings']
}) {
  const list = findings ?? []
  if (list.length === 0)
    return <Typography.Text type="secondary">-</Typography.Text>
  const shown = list.slice(0, 2)
  const tip = list
    .map(
      (f) => `${f.rule_id || f.detector}${f.message ? `：${f.message}` : ''}`,
    )
    .join('\n')
  return (
    <Tooltip title={<span style={{ whiteSpace: 'pre-line' }}>{tip}</span>}>
      <span>
        {shown.map((f, i) => (
          <Tag key={i} color="red" style={{ marginInlineEnd: 4 }}>
            {f.rule_id || f.detector}
          </Tag>
        ))}
        {list.length > 2 ? <Tag color="red">+{list.length - 2}</Tag> : null}
      </span>
    </Tooltip>
  )
}

/**
 * LLM API 观测（WDSP / 阶段8 W15）：网关 llm_observation 事件的观测明细与统计。
 * 只读页面，权限点 api_runtime.read；原始 prompt 不采集（仅长度桶），证据已脱敏。
 */
export default function ApiLLMPage() {
  const [days, setDays] = useState(7)
  const [model, setModel] = useState('')
  const [appliedModel, setAppliedModel] = useState('')
  const [endpointKey, setEndpointKey] = useState('')
  const [appliedEndpointKey, setAppliedEndpointKey] = useState('')
  const [findingsOnly, setFindingsOnly] = useState(false)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<ApiLLMObservation | null>(
    null,
  )

  const statsQuery = useQuery({
    queryKey: ['api-llm-stats', days],
    queryFn: () => apiLLMApi.stats(days),
  })

  const listQuery = useQuery({
    queryKey: [
      'api-llm-observations',
      days,
      appliedModel,
      appliedEndpointKey,
      findingsOnly,
      page,
      pageSize,
    ],
    queryFn: () =>
      apiLLMApi.listObservations({
        days,
        model: appliedModel || undefined,
        endpoint_key: appliedEndpointKey || undefined,
        findings_only: findingsOnly || undefined,
        page,
        page_size: pageSize,
      }),
  })

  const summary = statsQuery.data?.summary

  const columns: ColumnsType<ApiLLMObservation> = [
    {
      title: '时间',
      dataIndex: 'occurred_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '模型',
      dataIndex: 'model',
      width: 150,
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : <Tag>未声明</Tag>,
    },
    {
      title: 'API',
      dataIndex: 'endpoint_key',
      ellipsis: true,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: 'prompt 长度桶',
      dataIndex: 'prompt_len_bucket',
      width: 120,
      render: dash,
    },
    {
      title: 'Token 用量',
      dataIndex: 'total_tokens',
      width: 90,
      render: (v: number) => (v > 0 ? v : '-'),
    },
    {
      title: '流式',
      dataIndex: 'stream',
      width: 70,
      render: (v: boolean) => (v ? <Tag color="purple">流式</Tag> : '-'),
    },
    {
      title: 'MCP 方法',
      dataIndex: 'mcp_method',
      width: 130,
      ellipsis: true,
      render: dash,
    },
    {
      title: '命中项',
      key: 'findings',
      width: 180,
      render: (_, record) => <FindingsCell findings={record.findings} />,
    },
  ]

  return (
    <Card title="AI 大模型安全">
      <Tabs
        defaultActiveKey="observations"
        items={[
          {
            key: 'policies',
            label: '安全策略',
            children: <SecurityPoliciesTab />,
          },
          {
            key: 'observations',
            label: '调用观测',
            children: (
              <>
                <Typography.Paragraph type="secondary">
                  LLM 流量观测（模型/prompt 长度桶/token 用量/流式/MCP 方法）与
                  llm.* 检测命中； 原始 prompt
                  与响应内容不采集，统计窗口与列表明细一致（按发生时间口径）。
                </Typography.Paragraph>
                <QueryErrorAlert error={statsQuery.error} />
                <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
                  <Col flex="1 1 160px">
                    <Card size="small">
                      <Statistic
                        title="观测总数"
                        value={summary?.observations ?? 0}
                        loading={statsQuery.isLoading}
                      />
                    </Card>
                  </Col>
                  <Col flex="1 1 160px">
                    <Card size="small">
                      <Statistic
                        title="命中观测"
                        value={summary?.with_findings ?? 0}
                        loading={statsQuery.isLoading}
                        valueStyle={{ color: '#cf1322' }}
                      />
                    </Card>
                  </Col>
                  <Col flex="1 1 160px">
                    <Card size="small">
                      <Statistic
                        title="token 合计"
                        value={summary?.total_tokens ?? 0}
                        loading={statsQuery.isLoading}
                      />
                    </Card>
                  </Col>
                  <Col flex="1 1 160px">
                    <Card size="small">
                      <Statistic
                        title="流式调用"
                        value={summary?.stream_calls ?? 0}
                        loading={statsQuery.isLoading}
                      />
                    </Card>
                  </Col>
                  <Col flex="1 1 160px">
                    <Card size="small">
                      <Statistic
                        title="涉及模型"
                        value={summary?.distinct_models ?? 0}
                        loading={statsQuery.isLoading}
                      />
                    </Card>
                  </Col>
                </Row>

                <Card
                  size="small"
                  title="模型分布（按观测数）"
                  style={{ marginBottom: 16 }}
                  extra={
                    <Radio.Group
                      value={days}
                      onChange={(e) => setDays(e.target.value as number)}
                      options={[
                        { value: 7, label: '7天' },
                        { value: 14, label: '14天' },
                        { value: 30, label: '30天' },
                      ]}
                      optionType="button"
                      size="small"
                    />
                  }
                >
                  <EChart
                    option={modelDistOption(statsQuery.data)}
                    height={280}
                    ariaLabel="LLM 模型调用分布"
                  />
                </Card>

                <QueryErrorAlert error={listQuery.error} />
                <Space style={{ marginBottom: 16 }} wrap>
                  <Input.Search
                    placeholder="模型（精确匹配，如 gpt-4o）"
                    allowClear
                    style={{ width: 260 }}
                    value={model}
                    onChange={(e) => setModel(e.target.value)}
                    onSearch={(v) => {
                      setAppliedModel(v.trim())
                      setPage(1)
                    }}
                  />
                  <Input.Search
                    placeholder="API 键（精确匹配）"
                    allowClear
                    style={{ width: 320 }}
                    value={endpointKey}
                    onChange={(e) => setEndpointKey(e.target.value)}
                    onSearch={(v) => {
                      setAppliedEndpointKey(v.trim())
                      setPage(1)
                    }}
                  />
                  <Checkbox
                    checked={findingsOnly}
                    onChange={(e) => {
                      setFindingsOnly(e.target.checked)
                      setPage(1)
                    }}
                  >
                    仅看命中观测
                  </Checkbox>
                </Space>
                <SmartTable<ApiLLMObservation>
                  storageKey="api-llm-observations"
                  rowKey="id"
                  loading={listQuery.isLoading}
                  columns={columns}
                  dataSource={listQuery.data?.items ?? []}
                  scroll={{ x: 1200 }}
                  onRow={(record) => ({
                    onDoubleClick: () => setDetailRecord(record),
                    style: { cursor: 'pointer' },
                  })}
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
                <RecordDetailDrawer
                  open={detailRecord !== null}
                  title="LLM 观测详情"
                  record={detailRecord as Record<string, unknown> | null}
                  onClose={() => setDetailRecord(null)}
                />
              </>
            ),
          },
        ]}
      />
    </Card>
  )
}
