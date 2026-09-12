import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  App as AntdApp,
  Button,
  Card,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Switch,
  Table,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../api/client'
import { trafficAgentsApi } from '../../api/trafficAgents'
import type { TrafficPolicy, TrafficPolicyVersion } from '../../api/trafficAgents'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { formatDateTime } from '../../utils/format'

const DIRECTION_OPTIONS = [
  { value: 'both', label: '双向（both）' },
  { value: 'ingress', label: '入站（ingress）' },
  { value: 'egress', label: '出站（egress）' },
]

const OUTPUT_MODE_OPTIONS = [
  { value: 'FLOW', label: 'FLOW（流元数据+HTTP 元数据）' },
  { value: 'RAW', label: 'RAW（原始包，服务端仅校验计数）' },
  { value: 'FLOW_RAW', label: 'FLOW_RAW（同时输出）' },
]

/** 采集等级（Phase 3 契约 §2 语义） */
const CAPTURE_LEVEL_OPTIONS = [
  { value: 'L0', label: 'L0：仅元数据（请求行三元组，无 Header/Body）' },
  { value: 'L1', label: 'L1：L0 + 请求/响应 Header（脱敏后）' },
  { value: 'L2', label: 'L2：L1 + Body（受大小与内容类型限制）' },
  { value: 'L3', label: 'L3：L2 + RAW 原始包通道' },
]

/** 脱敏方式（Phase 3 契约 §5） */
const MASKING_MODE_OPTIONS = [
  { value: 'NONE', label: 'NONE（不脱敏）' },
  { value: 'MASK', label: 'MASK（替换为 ********）' },
  { value: 'HASH', label: 'HASH（sha256 前 16 位）' },
  { value: 'DROP', label: 'DROP（整行/参数删除）' },
]

/** 契约 §5 缺省脱敏名单（既有策略无 masking 段时按缺省值展示） */
const DEFAULT_MASKING_HEADER_NAMES = [
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'proxy-authorization',
]
const DEFAULT_MASKING_PARAM_NAMES = [
  'password',
  'passwd',
  'pwd',
  'token',
  'access_token',
  'refresh_token',
  'secret',
  'api_key',
  'apikey',
]

interface PolicyFormValues {
  name: string
  interfaces: string[]
  direction: string
  ports: number[]
  output_mode: string
  outbound_mbps: number
  capture_level: string
  sampling_enabled: boolean
  sampling_rate: number
  masking_headers_mode: string
  masking_headers_names: string[]
  masking_params_mode: string
  masking_params_names: string[]
}

/** 按表单字段生成策略 config（契约 §3.3 结构；未在表单中的键以既有 JSON 为准） */
function buildPolicyConfig(values: PolicyFormValues, base: Record<string, unknown>) {
  const asRecord = (v: unknown): Record<string, unknown> =>
    typeof v === 'object' && v !== null && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : {}
  const capture = asRecord(base.capture)
  const output = asRecord(base.output)
  const limits = asRecord(base.limits)
  // 脱敏名单归一：去空白、统一小写（契约 §5 匹配大小写不敏感）
  const normNames = (names: string[]) =>
    names.map((n) => String(n).trim().toLowerCase()).filter((n) => n.length > 0)
  return {
    ...base,
    name: values.name,
    capture: {
      protocols: ['tcp'],
      ...capture,
      interfaces: values.interfaces,
      direction: values.direction,
      ports: values.ports,
    },
    capture_level: values.capture_level,
    masking: {
      headers: { mode: values.masking_headers_mode, names: normNames(values.masking_headers_names) },
      params: { mode: values.masking_params_mode, names: normNames(values.masking_params_names) },
    },
    output: { ...output, mode: values.output_mode },
    // 采样（Phase 4 契约 §4）：enabled=false 时 rate 无意义，归一为 1（rate=1 等价关闭）
    sampling: {
      enabled: values.sampling_enabled,
      rate: values.sampling_enabled ? values.sampling_rate : 1,
    },
    limits: {
      max_body_size: 262144,
      cpu_percent: 20,
      memory_mb: 512,
      ...limits,
      outbound_mbps: values.outbound_mbps,
    },
  }
}

/** 从既有 config 反向提取表单初值（缺省按契约 §6 内置默认采集集；masking 缺省按 Phase 3 契约 §5 默认值） */
function extractFormValues(policy: TrafficPolicy | null): PolicyFormValues {
  const config = (policy?.config ?? {}) as Record<string, unknown>
  const capture = (config.capture ?? {}) as Record<string, unknown>
  const output = (config.output ?? {}) as Record<string, unknown>
  const limits = (config.limits ?? {}) as Record<string, unknown>
  const masking = (config.masking ?? {}) as Record<string, unknown>
  const maskingHeaders = (masking.headers ?? {}) as Record<string, unknown>
  const maskingParams = (masking.params ?? {}) as Record<string, unknown>
  const sampling = (config.sampling ?? {}) as Record<string, unknown>
  const asNames = (v: unknown, fallback: string[]) =>
    Array.isArray(v) ? v.map(String) : fallback
  return {
    name: policy?.name ?? '',
    interfaces: Array.isArray(capture.interfaces) ? (capture.interfaces as string[]) : ['eth0'],
    direction: typeof capture.direction === 'string' ? capture.direction : 'both',
    ports: Array.isArray(capture.ports)
      ? (capture.ports as number[]).map(Number).filter((n) => Number.isFinite(n))
      : [80, 443, 8080, 8443],
    output_mode: typeof output.mode === 'string' ? output.mode : 'FLOW',
    outbound_mbps: typeof limits.outbound_mbps === 'number' ? limits.outbound_mbps : 100,
    capture_level: typeof config.capture_level === 'string' ? config.capture_level : 'L0',
    sampling_enabled: sampling.enabled === true,
    sampling_rate: typeof sampling.rate === 'number' ? sampling.rate : 1,
    masking_headers_mode:
      typeof maskingHeaders.mode === 'string' ? maskingHeaders.mode : 'MASK',
    masking_headers_names: asNames(maskingHeaders.names, DEFAULT_MASKING_HEADER_NAMES),
    masking_params_mode: typeof maskingParams.mode === 'string' ? maskingParams.mode : 'MASK',
    masking_params_names: asNames(maskingParams.names, DEFAULT_MASKING_PARAM_NAMES),
  }
}

/** 采集策略面板：列表 + 创建/编辑（常用字段表单 + 完整 JSON）+ 删除（写操作需 traffic.agents.manage） */
export default function PolicyPanel({ canManage }: { canManage: boolean }) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [editorOpen, setEditorOpen] = useState(false)
  const [editing, setEditing] = useState<TrafficPolicy | null>(null)
  const [jsonText, setJsonText] = useState('')
  const [versionsPolicy, setVersionsPolicy] = useState<TrafficPolicy | null>(null)
  const [detailRecord, setDetailRecord] = useState<TrafficPolicy | null>(null)
  const [detailVersion, setDetailVersion] = useState<TrafficPolicyVersion | null>(null)
  const [form] = Form.useForm<PolicyFormValues>()

  const listQuery = useQuery({
    queryKey: ['traffic-agents', 'policies', page, pageSize],
    queryFn: () => trafficAgentsApi.policies({ page, page_size: pageSize }),
  })

  // 版本历史（Phase 2）：打开 Modal 时加载，version 倒序由服务端保证
  const versionsQuery = useQuery({
    queryKey: ['traffic-agents', 'policy-versions', versionsPolicy?.id],
    queryFn: () => trafficAgentsApi.policyVersions(versionsPolicy!.id),
    enabled: versionsPolicy !== null,
  })

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'policies'] })
  }

  const rollbackMutation = useMutation({
    mutationFn: ({ id, version }: { id: string; version: number }) =>
      trafficAgentsApi.rollbackPolicy(id, version),
    onSuccess: (updated) => {
      message.success(`已回滚并生成新版本 v${updated.version}`)
      invalidate()
      void queryClient.invalidateQueries({ queryKey: ['traffic-agents', 'policy-versions'] })
      // 当前版本已变化，同步刷新 Modal 持有的策略行
      setVersionsPolicy((prev) => (prev && prev.id === updated.id ? updated : prev))
    },
    onError,
  })

  const saveMutation = useMutation({
    mutationFn: (body: { name: string; config: Record<string, unknown> }) =>
      editing
        ? trafficAgentsApi.updatePolicy(editing.id, body)
        : trafficAgentsApi.createPolicy(body),
    onSuccess: () => {
      message.success(editing ? '策略已保存' : '策略已创建')
      closeEditor()
      invalidate()
    },
    onError,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => trafficAgentsApi.deletePolicy(id),
    onSuccess: () => {
      message.success('策略已删除')
      invalidate()
    },
    onError,
  })

  const openEditor = (policy: TrafficPolicy | null) => {
    setEditing(policy)
    const values = extractFormValues(policy)
    setJsonText(
      JSON.stringify(policy?.config ?? buildPolicyConfig(values, { sampling: { enabled: false, rate: 1.0 }, buffer: { enabled: true, max_size_mb: 512, max_age_minutes: 30 } }), null, 2),
    )
    setEditorOpen(true)
  }

  const closeEditor = () => {
    setEditorOpen(false)
    setEditing(null)
    setJsonText('')
    form.resetFields()
  }

  const submitEditor = async () => {
    let values: PolicyFormValues
    try {
      values = await form.validateFields()
    } catch {
      // 表单校验未通过，antd 已展示错误提示
      return
    }
    // Select tags 输入为字符串，统一归一为合法端口号
    const ports = values.ports.map(Number)
    if (ports.length === 0 || ports.some((n) => !Number.isInteger(n) || n < 1 || n > 65535)) {
      message.error('端口必须是 1-65535 的整数')
      return
    }
    values.ports = ports
    let parsed: unknown
    try {
      parsed = JSON.parse(jsonText || '{}')
    } catch {
      message.error('策略 JSON 格式不正确，请检查后重试')
      return
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      message.error('策略必须是 JSON 对象')
      return
    }
    // 表单常用字段优先：保存时覆盖 JSON 中对应键，其余高级键（sampling/buffer 等）保留
    const config = buildPolicyConfig(values, parsed as Record<string, unknown>)
    saveMutation.mutate({ name: values.name, config })
  }

  const columns: ColumnsType<TrafficPolicy> = [
    { title: '名称', dataIndex: 'name', width: 180, ellipsis: true },
    {
      title: '版本',
      dataIndex: 'version',
      width: 80,
      render: (v: number) => `v${v}`,
    },
    {
      title: '采集配置',
      key: 'summary',
      ellipsis: true,
      render: (_, r) => {
        const values = extractFormValues(r)
        return `等级 ${values.capture_level} / ${values.interfaces.join(',') || '-'} / ${values.direction} / 端口 ${values.ports.join(',') || '-'} / ${values.output_mode} / 限速 ${values.outbound_mbps} Mbps`
      },
    },
    {
      title: '适配器 / 来源绑定',
      key: 'adapters',
      width: 150,
      render: (_, r) => {
        const config = (r.config ?? {}) as Record<string, unknown>
        const adapters = config.adapters
        const bindings = config.source_bindings
        const hasAdapters =
          typeof adapters === 'object' && adapters !== null &&
          Object.keys(adapters as Record<string, unknown>).length > 0
        const hasBindings = Array.isArray(bindings) && bindings.length > 0
        if (!hasAdapters && !hasBindings) {
          return (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              未配置
            </Typography.Text>
          )
        }
        return (
          <Tooltip title="适配器启用状态与来源绑定由策略 config 的 adapters/source_bindings 键携带，随版本快照不可变保存">
            <Space size={4} wrap>
              {hasAdapters ? <Tag color="blue">适配器已配置</Tag> : null}
              {hasBindings ? <Tag color="purple">来源绑定已配置</Tag> : null}
            </Space>
          </Tooltip>
        )
      },
    },
    {
      title: '更新时间',
      dataIndex: 'updated_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '操作',
      key: 'actions',
      width: canManage ? 190 : 80,
      fixed: 'right' as const,
      render: (_: unknown, record: TrafficPolicy) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setVersionsPolicy(record)}>
            历史
          </Button>
          {canManage ? (
            <>
              <Button type="link" size="small" onClick={() => openEditor(record)}>
                编辑
              </Button>
              <Popconfirm
                title="删除策略"
                description={`确定删除策略「${record.name}」吗？已绑定该策略的 Agent 将改用内置默认采集集。`}
                okText="确认删除"
                okButtonProps={{ danger: true }}
                cancelText="取消"
                onConfirm={() => deleteMutation.mutate(record.id)}
              >
                <Button type="link" size="small" danger>
                  删除
                </Button>
              </Popconfirm>
            </>
          ) : null}
        </Space>
      ),
    },
  ]

  const versionColumns: ColumnsType<TrafficPolicyVersion> = [
    {
      title: '版本',
      dataIndex: 'version',
      width: 110,
      render: (v: number, r) => (
        <Space size={4}>
          <span>v{v}</span>
          {r.current ? <Tag color="blue">当前版本</Tag> : null}
        </Space>
      ),
    },
    {
      title: '生成时间',
      dataIndex: 'created_at',
      width: 165,
      render: (v: string) => formatDateTime(v),
    },
    { title: '操作人', dataIndex: 'created_by', width: 120, render: (v: string) => v || '-' },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 120,
            render: (_: unknown, r: TrafficPolicyVersion) =>
              r.current ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  生效中
                </Typography.Text>
              ) : (
                <Popconfirm
                  title="回滚到此版本"
                  description={`将以 v${r.version} 的配置生成新版本（当前 v${versionsPolicy?.version ?? '-'} → v${(versionsPolicy?.version ?? 0) + 1}），绑定该策略的 Agent 将重新拉取配置。`}
                  okText="确认回滚"
                  okButtonProps={{ danger: true }}
                  cancelText="取消"
                  onConfirm={() =>
                    versionsPolicy &&
                    rollbackMutation.mutate({ id: versionsPolicy.id, version: r.version })
                  }
                >
                  <Button type="link" size="small" danger loading={rollbackMutation.isPending}>
                    回滚
                  </Button>
                </Popconfirm>
              ),
          },
        ]
      : []),
  ]

  return (
    <Card
      size="small"
      title="采集策略"
      extra={
        canManage ? (
          <Button type="primary" onClick={() => openEditor(null)}>
            创建策略
          </Button>
        ) : undefined
      }
    >
      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载策略列表失败" />
      ) : (
        <SmartTable<TrafficPolicy>
          storageKey="traffic-policies"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          locale={{ emptyText: '暂无策略' }}
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
      )}

      <Modal
        title={`版本历史：${versionsPolicy?.name ?? ''}`}
        open={versionsPolicy !== null}
        onCancel={() => setVersionsPolicy(null)}
        footer={
          <Button type="primary" onClick={() => setVersionsPolicy(null)}>
            关闭
          </Button>
        }
        width={640}
        destroyOnHidden
      >
        {versionsQuery.isError ? (
          <QueryErrorAlert error={versionsQuery.error} message="加载版本历史失败" />
        ) : (
          <Table<TrafficPolicyVersion>
            rowKey="version"
            size="small"
            loading={versionsQuery.isLoading}
            columns={versionColumns}
            dataSource={versionsQuery.data?.items}
            pagination={false}
            locale={{ emptyText: '暂无历史版本' }}
            onRow={(record) => ({
              onDoubleClick: () => setDetailVersion(record),
              style: { cursor: 'pointer' },
            })}
          />
        )}
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          策略创建、每次修改与回滚都会生成一个不可变版本快照；回滚以历史版本配置生成新版本，历史链保持不变。
        </Typography.Text>
      </Modal>

      <Modal
        title={editing ? `编辑策略：${editing.name}` : '创建策略'}
        open={editorOpen}
        onCancel={closeEditor}
        onOk={() => void submitEditor()}
        okText="保存"
        cancelText="取消"
        confirmLoading={saveMutation.isPending}
        width={680}
        destroyOnHidden
      >
        <Form<PolicyFormValues>
          // destroyOnHidden 下每次打开重新挂载，initialValues 取自当前编辑目标
          key={editing?.id ?? '__new__'}
          form={form}
          layout="vertical"
          initialValues={extractFormValues(editing)}
        >
          <Form.Item
            name="name"
            label="名称"
            rules={[{ required: true, message: '请填写策略名称' }]}
          >
            <Input placeholder="如 production-web" maxLength={64} />
          </Form.Item>
          <Form.Item
            name="interfaces"
            label="网卡"
            rules={[{ required: true, message: '请至少填写一个网卡' }]}
          >
            <Select mode="tags" placeholder="如 eth0（回车添加多个）" open={false} suffixIcon={null} />
          </Form.Item>
          <Form.Item name="direction" label="方向" rules={[{ required: true }]}>
            <Select options={DIRECTION_OPTIONS} />
          </Form.Item>
          <Form.Item name="ports" label="端口" rules={[{ required: true, message: '请至少填写一个端口' }]}>
            <Select
              mode="tags"
              placeholder="如 80（回车添加多个，1-65535）"
              open={false}
              suffixIcon={null}
              tokenSeparators={[',', ' ']}
            />
          </Form.Item>
          <Form.Item name="output_mode" label="输出模式（output.mode）" rules={[{ required: true }]}>
            <Select options={OUTPUT_MODE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="outbound_mbps"
            label="出站带宽限速（Mbps）"
            rules={[{ required: true, message: '请填写限速' }]}
          >
            <InputNumber min={1} max={100000} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="capture_level"
            label="采集等级（capture_level）"
            rules={[{ required: true }]}
          >
            <Select options={CAPTURE_LEVEL_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="sampling_enabled"
            label="启用采样（sampling.enabled）"
            valuePropName="checked"
            extra="开启后按 flow 级确定性采样：SHA-256(flow_id) 映射 [0,1) < rate 则采集，同流一致；采样外 flow 仅保留计数事件（统计不丢量）"
          >
            <Switch />
          </Form.Item>
          <Form.Item noStyle shouldUpdate={(a, b) => a.sampling_enabled !== b.sampling_enabled}>
            {({ getFieldValue }) =>
              getFieldValue('sampling_enabled') ? (
                <Form.Item
                  name="sampling_rate"
                  label="采样率（sampling.rate，0-1 小数，rate=1 等价关闭）"
                  rules={[{ required: true, message: '请填写采样率' }]}
                >
                  <InputNumber min={0.0001} max={1} step={0.05} style={{ width: '100%' }} />
                </Form.Item>
              ) : null
            }
          </Form.Item>
          <Typography.Text strong>脱敏（masking，Agent 侧离主机前执行）</Typography.Text>
          <Form.Item
            name="masking_headers_mode"
            label="Header 脱敏方式"
            rules={[{ required: true }]}
            style={{ marginTop: 8 }}
          >
            <Select options={MASKING_MODE_OPTIONS} />
          </Form.Item>
          <Form.Item name="masking_headers_names" label="Header 脱敏名单（大小写不敏感）">
            <Select
              mode="tags"
              placeholder="如 authorization（回车添加多个）"
              open={false}
              suffixIcon={null}
              tokenSeparators={[',', ' ']}
            />
          </Form.Item>
          <Form.Item
            name="masking_params_mode"
            label="参数脱敏方式"
            rules={[{ required: true }]}
          >
            <Select options={MASKING_MODE_OPTIONS} />
          </Form.Item>
          <Form.Item
            name="masking_params_names"
            label="参数脱敏名单（query/form/JSON 一级字段，大小写不敏感）"
          >
            <Select
              mode="tags"
              placeholder="如 password（回车添加多个）"
              open={false}
              suffixIcon={null}
              tokenSeparators={[',', ' ']}
            />
          </Form.Item>
        </Form>
        <Typography.Text strong>完整配置 JSON</Typography.Text>
        <Input.TextArea
          style={{ marginTop: 8, fontFamily: 'monospace', fontSize: 12 }}
          rows={10}
          value={jsonText}
          onChange={(e) => setJsonText(e.target.value)}
        />
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          保存时以上方表单字段覆盖 JSON 中对应键（capture.interfaces/direction/ports、capture_level、
          masking.headers/params、output.mode、limits.outbound_mbps）， sampling、buffer
          等高级键按 JSON 原文保留。
        </Typography.Text>
        <Typography.Text type="secondary" style={{ display: 'block', fontSize: 12 }}>
          保存即生成新的策略版本（版本历史链不可变，见「历史」）并提升绑定 Agent
          的服务端目标配置版本；Agent 收到版本与实际加载结果在 Agent
          详情中分离显示（待同步 ≠ 已生效）。适配器 enabled 与来源绑定等 v2
          字段需在 Agent 支持相应能力后方可生效，旧 Agent 侧显示「需升级」。
        </Typography.Text>
      </Modal>

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="策略详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
      <RecordDetailDrawer
        open={detailVersion !== null}
        title="版本详情"
        record={detailVersion as Record<string, unknown> | null}
        onClose={() => setDetailVersion(null)}
      />
    </Card>
  )
}
