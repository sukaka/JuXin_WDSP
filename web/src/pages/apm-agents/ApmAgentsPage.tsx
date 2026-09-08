import { useEffect, useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  AutoComplete,
  Button,
  Card,
  Collapse,
  Descriptions,
  Drawer,
  Form,
  Input,
  InputNumber,
  Modal,
  Popconfirm,
  Select,
  Space,
  Spin,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import dayjs from 'dayjs'
import { ApiError } from '../../api/client'
import { apmApi } from '../../api/apm'
import { applicationsApi } from '../../api/applications'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import { APM_AGENT_STATUS_META, formatRelativeTime } from '../../utils/apm'
import type { ApmAgentItem } from '../../types'

const LANGUAGE_OPTIONS = ['Java', 'Go', '.NET', 'Node.js', 'Python'].map((v) => ({
  value: v,
  label: v,
}))

/** 环境建议值（APM 设计 §8 维度模型：生产、预发布、测试、开发），允许自由输入 */
const ENVIRONMENT_OPTIONS = [
  { value: 'prod', label: '生产（prod）' },
  { value: 'staging', label: '预发布（staging）' },
  { value: 'test', label: '测试（test）' },
  { value: 'dev', label: '开发（dev）' },
]

interface TokenFormValues {
  application_id: string
  environment: string
  languages: string[]
  ttl_minutes: number
}

interface CreatedToken {
  id: string
  token: string
  expires_at: string
}

/** 安装指引：纯静态文案（以 OpenAPI 契约与 OTel 官方零代码插桩为准；详细步骤见 docs/APM_ONBOARDING_GUIDE.md） */
const INSTALL_GUIDE_ITEMS = [
  {
    key: 'flow',
    label: '接入流程与注册接口',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        1. 在上方「创建注册令牌」生成一次性令牌（绑定应用、环境、允许的语言与有效期，原文仅显示一次）。
        <br />
        2. Agent 首次启动时通过 TLS 向管理面注册接口{' '}
        <Typography.Text code>POST /api/v1/apm/agent/register</Typography.Text>{' '}
        提交令牌与 CSR，服务端签发客户端证书（令牌使用即作废）；心跳、策略拉取与证书轮换
        使用该证书做持有证明（PoP）签名认证。
        <br />
        3. 遥测数据经 OTLP 上报至本地 Collector（gRPC 4317 / HTTP 4318，与管理面浏览器会话认证隔离）；
        具体监听地址以部署环境实际配置为准。
        <br />
        4. 说明：OTel 官方零代码 Agent 不内置九章注册客户端，注册/心跳/策略拉取由部署侧接入
        组件完成；分语言开箱 Agent 包在路线图中。
      </Typography.Paragraph>
    ),
  },
  {
    key: 'java',
    label: 'Java',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        使用 OpenTelemetry Java Agent（零代码插桩），启动参数追加{' '}
        <Typography.Text code>-javaagent:/path/opentelemetry-javaagent.jar</Typography.Text>
        ，经 OTEL_EXPORTER_OTLP_ENDPOINT 等环境变量指向本地 Collector；注册令牌经环境变量注入
        （令牌不得写入镜像层或提交至代码库）。
      </Typography.Paragraph>
    ),
  },
  {
    key: 'go',
    label: 'Go',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        Go 采用 SDK 埋点方式：引入 OpenTelemetry Go SDK 与 otelhttp 等插桩库并初始化
        TracerProvider（传入服务名与环境，导出至本地 Collector），重新编译发布后生效；
        九章管理面自身的自埋点实现可作为参考（APM_SELF_TELEMETRY_ENABLED）。
      </Typography.Paragraph>
    ),
  },
  {
    key: 'nodejs',
    label: 'Node.js',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        安装 OpenTelemetry Node.js 自动插桩包后通过启动参数{' '}
        <Typography.Text code>
          node --require @opentelemetry/auto-instrumentations-node/register app.js
        </Typography.Text>{' '}
        预加载；导出地址与注册令牌经环境变量注入。
      </Typography.Paragraph>
    ),
  },
  {
    key: 'dotnet',
    label: '.NET',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        配置 CLR Profiler 环境变量（CORECLR_ENABLE_PROFILING、CORECLR_PROFILER 等）加载探针，
        注册令牌经环境变量注入；IIS/容器部署方式以部署手册为准。
      </Typography.Paragraph>
    ),
  },
  {
    key: 'python',
    label: 'Python',
    children: (
      <Typography.Paragraph style={{ fontSize: 13, marginBottom: 0 }}>
        安装 opentelemetry-distro 与插桩包后使用包装命令启动（如{' '}
        <Typography.Text code>opentelemetry-instrument python app.py</Typography.Text>
        ），或在代码中显式初始化 SDK；注册令牌经环境变量注入。
      </Typography.Paragraph>
    ),
  },
]

/** Agent 管理（权限 apm.agents.manage）：注册令牌、Agent 清单/撤销、基线策略查看编辑、安装指引 */
export default function ApmAgentsPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()

  const [status, setStatus] = useState<string | undefined>()
  const [keyword, setKeyword] = useState<string | undefined>()
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)

  const [detailRecord, setDetailRecord] = useState<ApmAgentItem | null>(null)

  const [tokenModalOpen, setTokenModalOpen] = useState(false)
  const [tokenForm] = Form.useForm<TokenFormValues>()
  const [createdToken, setCreatedToken] = useState<CreatedToken | null>(null)

  const [policyOpen, setPolicyOpen] = useState(false)
  const [policyScope, setPolicyScope] = useState<string | undefined>()
  const [policyText, setPolicyText] = useState('')

  const listQuery = useQuery({
    queryKey: ['apm', 'agents', status, keyword, page, pageSize],
    queryFn: () => apmApi.agents({ status, keyword, page, page_size: pageSize }),
  })

  // 应用下拉（注册令牌表单复用既有应用清单接口）
  const appsQuery = useQuery({
    queryKey: ['applications', 'all-for-apm-agents'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
  })

  // 策略 scope 选项 = 已注册服务清单（远程搜索：keyword 透传后端模糊匹配 service_name/instance_id，
  // 避免仅前 100 条 Agent 可选；输入防抖 300ms）
  const [scopeSearch, setScopeSearch] = useState('')
  const [scopeKeyword, setScopeKeyword] = useState('')
  useEffect(() => {
    const timer = setTimeout(() => setScopeKeyword(scopeSearch.trim()), 300)
    return () => clearTimeout(timer)
  }, [scopeSearch])
  const scopeQuery = useQuery({
    queryKey: ['apm', 'agents', 'policy-scopes', scopeKeyword],
    queryFn: () => apmApi.agents({ keyword: scopeKeyword || undefined, page: 1, page_size: 100 }),
    enabled: policyOpen,
  })
  const scopeOptions = useMemo(() => {
    const names = new Set<string>()
    // 当前选中项始终保留在选项内，避免远程搜索换页后选中值丢 label
    if (policyScope) names.add(policyScope)
    for (const a of scopeQuery.data?.items ?? []) {
      if (a.service_name) names.add(a.service_name)
    }
    return [...names].sort().map((v) => ({ value: v, label: v }))
  }, [scopeQuery.data, policyScope])

  const policyQuery = useQuery({
    queryKey: ['apm', 'policy', policyScope],
    queryFn: () => apmApi.getPolicy(policyScope as string),
    enabled: policyOpen && !!policyScope,
    retry: false,
  })

  // 策略文档加载成功后同步 JSON 编辑草稿
  useEffect(() => {
    if (policyQuery.data) {
      setPolicyText(JSON.stringify(policyQuery.data.policy ?? {}, null, 2))
    }
  }, [policyQuery.data])

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const createTokenMutation = useMutation({
    mutationFn: (values: TokenFormValues) => apmApi.createEnrollmentToken(values),
    onSuccess: (data) => {
      // 令牌原文仅此一次返回：留在 Modal 内一次性展示，关闭后丢弃
      setCreatedToken({ id: data.id, token: data.token, expires_at: data.expires_at })
    },
    onError,
  })

  const revokeMutation = useMutation({
    mutationFn: (id: string) => apmApi.revokeAgent(id),
    onSuccess: () => {
      message.success('Agent 已撤销')
      void queryClient.invalidateQueries({ queryKey: ['apm', 'agents'] })
    },
    onError,
  })

  const putPolicyMutation = useMutation({
    mutationFn: ({ scope, policy, expectedVersion }: { scope: string; policy: Record<string, unknown>; expectedVersion: number }) =>
      apmApi.putPolicy(scope, { policy, expected_version: expectedVersion }),
    onSuccess: () => {
      message.success('策略已保存')
      void queryClient.invalidateQueries({ queryKey: ['apm', 'policy', policyScope] })
    },
    onError: (e) => {
      if (e instanceof ApiError && e.status === 409) {
        message.warning('策略版本冲突：该策略已被其他操作修改，请点击「刷新」加载最新版本后重试')
        return
      }
      onError(e)
    },
  })

  const closeTokenModal = () => {
    setTokenModalOpen(false)
    setCreatedToken(null)
    tokenForm.resetFields()
  }

  const savePolicy = () => {
    if (!policyScope || !policyQuery.data) return
    let parsed: unknown
    try {
      parsed = JSON.parse(policyText)
    } catch {
      message.error('策略 JSON 格式不正确，请检查后重试')
      return
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      message.error('策略必须是 JSON 对象')
      return
    }
    putPolicyMutation.mutate({
      scope: policyScope,
      policy: parsed as Record<string, unknown>,
      expectedVersion: policyQuery.data.version,
    })
  }

  const columns: ColumnsType<ApmAgentItem> = [
    {
      title: '状态',
      dataIndex: 'status',
      width: 120,
      render: (v: string) => <StatusTag value={v} map={APM_AGENT_STATUS_META} />,
    },
    { title: '服务名', dataIndex: 'service_name', width: 150, ellipsis: true },
    {
      title: '实例 ID',
      dataIndex: 'instance_id',
      width: 160,
      ellipsis: true,
      render: (v: string) => (
        <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>{v || '-'}</Typography.Text>
      ),
    },
    { title: '语言', dataIndex: 'language', width: 90 },
    { title: 'Agent 版本', dataIndex: 'agent_version', width: 110 },
    { title: '环境', dataIndex: 'environment', width: 100 },
    {
      title: '最后心跳',
      dataIndex: 'last_heartbeat_at',
      width: 120,
      render: (v: string) => (
        <Tooltip title={formatDateTime(v)}>
          <span>{formatRelativeTime(v)}</span>
        </Tooltip>
      ),
    },
    {
      title: '证书到期',
      dataIndex: 'cert_expires_at',
      width: 165,
      render: (v: string) => {
        const expired = v && dayjs(v).isValid() && dayjs(v).isBefore(dayjs())
        return (
          <Typography.Text type={expired ? 'danger' : undefined}>
            {formatDateTime(v)}
            {expired ? '（已过期）' : ''}
          </Typography.Text>
        )
      },
    },
    {
      title: '操作',
      key: 'actions',
      width: 140,
      fixed: 'right',
      render: (_, record) => (
        <Space size={0}>
          <Button type="link" size="small" onClick={() => setDetailRecord(record)}>
            查看
          </Button>
          {record.status !== 'REVOKED' && (
            <Popconfirm
              title="撤销 Agent"
              description={`确定撤销 ${record.service_name || record.instance_id} 吗？撤销后其证书立即失效，上报数据将被拒绝。`}
              okText="确认撤销"
              okButtonProps={{ danger: true }}
              cancelText="取消"
              onConfirm={() => revokeMutation.mutate(record.id)}
            >
              <Button type="link" size="small" danger>
                撤销
              </Button>
            </Popconfirm>
          )}
        </Space>
      ),
    },
  ]

  return (
    <Card
      title="Agent 管理"
      extra={
        <Space>
          <Button onClick={() => setPolicyOpen(true)}>基线策略</Button>
          <Button
            type="primary"
            onClick={() => {
              setCreatedToken(null)
              tokenForm.resetFields()
              setTokenModalOpen(true)
            }}
          >
            创建注册令牌
          </Button>
        </Space>
      }
    >
      <Collapse
        style={{ marginBottom: 16 }}
        items={[
          {
            key: 'guide',
            label: '安装指引（各语言接入要点与注册接口说明）',
            children: <Collapse ghost items={INSTALL_GUIDE_ITEMS} />,
          },
        ]}
      />

      <Space style={{ marginBottom: 16 }} wrap>
        <Select
          placeholder="状态"
          allowClear
          style={{ width: 160 }}
          options={Object.entries(APM_AGENT_STATUS_META).map(([value, meta]) => ({
            value,
            label: meta.label,
          }))}
          onChange={(v) => {
            setStatus(v)
            setPage(1)
          }}
        />
        <Input.Search
          placeholder="服务名 / 实例 ID"
          allowClear
          style={{ width: 220 }}
          onSearch={(v) => {
            setKeyword(v.trim() || undefined)
            setPage(1)
          }}
        />
      </Space>

      {listQuery.isError ? (
        <QueryErrorAlert error={listQuery.error} message="加载 Agent 列表失败" />
      ) : (
        <SmartTable<ApmAgentItem>
          storageKey="apm-agents"
          rowKey="id"
          loading={listQuery.isLoading}
          columns={columns}
          dataSource={listQuery.data?.items}
          scroll={{ x: 1300 }}
          locale={{ emptyText: '暂无数据' }}
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

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="Agent 详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />

      <Modal
        title="创建注册令牌"
        open={tokenModalOpen}
        onCancel={closeTokenModal}
        footer={
          createdToken ? (
            <Button type="primary" onClick={closeTokenModal}>
              完成
            </Button>
          ) : undefined
        }
        onOk={() => tokenForm.submit()}
        okText="创建"
        confirmLoading={createTokenMutation.isPending}
        destroyOnHidden
      >
        {createdToken ? (
          <Space direction="vertical" size={12} style={{ display: 'flex' }}>
            <Alert
              type="warning"
              showIcon
              message="令牌原文仅显示一次"
              description="请立即复制并妥善保存；关闭本窗口后将无法再次查看，只能重新创建。"
            />
            <Typography.Text
              copyable={{ text: createdToken.token }}
              style={{ fontFamily: 'monospace', fontSize: 13, wordBreak: 'break-all' }}
            >
              {createdToken.token}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              过期时间：{formatDateTime(createdToken.expires_at)}
            </Typography.Text>
          </Space>
        ) : (
          <Form<TokenFormValues>
            form={tokenForm}
            layout="vertical"
            initialValues={{ ttl_minutes: 60, languages: [] }}
            onFinish={(values) => createTokenMutation.mutate(values)}
          >
            <Form.Item
              name="application_id"
              label="应用"
              rules={[{ required: true, message: '请选择应用' }]}
            >
              <Select
                showSearch
                optionFilterProp="label"
                placeholder="选择要接入的应用"
                loading={appsQuery.isLoading}
                options={(appsQuery.data?.items ?? []).map((a) => ({
                  value: a.id,
                  label: `${a.name}（${a.code}）`,
                }))}
              />
            </Form.Item>
            <Form.Item
              name="environment"
              label="环境"
              rules={[{ required: true, message: '请选择或输入环境' }]}
            >
              <AutoComplete
                placeholder="如 prod / staging / test / dev"
                options={ENVIRONMENT_OPTIONS}
              />
            </Form.Item>
            <Form.Item
              name="languages"
              label="允许的语言"
              rules={[{ required: true, message: '请选择至少一种语言' }]}
            >
              <Select mode="multiple" placeholder="Java / Go / .NET / Node.js / Python" options={LANGUAGE_OPTIONS} />
            </Form.Item>
            <Form.Item
              name="ttl_minutes"
              label="有效期（分钟）"
              rules={[{ required: true, message: '请填写有效期' }]}
            >
              <InputNumber min={5} max={10080} style={{ width: '100%' }} />
            </Form.Item>
          </Form>
        )}
      </Modal>

      <Drawer
        title="基线策略"
        open={policyOpen}
        onClose={() => {
          setPolicyOpen(false)
          setPolicyScope(undefined)
          setPolicyText('')
          setScopeSearch('')
          setScopeKeyword('')
        }}
        width={640}
        extra={
          <Space>
            <Button
              size="small"
              onClick={() => void policyQuery.refetch()}
              disabled={!policyScope || policyQuery.isFetching}
            >
              刷新
            </Button>
            <Button
              size="small"
              type="primary"
              onClick={savePolicy}
              loading={putPolicyMutation.isPending}
              disabled={!policyQuery.data}
            >
              保存
            </Button>
          </Space>
        }
      >
        <Space direction="vertical" size={12} style={{ display: 'flex' }}>
          <Select
            placeholder="选择策略作用域（已注册服务，可搜索）"
            style={{ width: 320 }}
            value={policyScope}
            showSearch
            filterOption={false}
            onSearch={setScopeSearch}
            loading={scopeQuery.isLoading || scopeQuery.isFetching}
            options={scopeOptions}
            onChange={(v) => setPolicyScope(v)}
            notFoundContent={
              scopeQuery.isLoading ? '加载中...' : '暂无匹配的已注册服务'
            }
          />
          {!policyScope ? (
            <Typography.Text type="secondary">请选择服务以查看其基线策略</Typography.Text>
          ) : policyQuery.isLoading ? (
            <div style={{ textAlign: 'center', padding: 48 }}>
              <Spin />
            </div>
          ) : policyQuery.isError ? (
            <QueryErrorAlert error={policyQuery.error} message="加载策略失败" />
          ) : policyQuery.data ? (
            <>
              <Descriptions column={2} size="small" bordered>
                <Descriptions.Item label="版本">v{policyQuery.data.version}</Descriptions.Item>
                <Descriptions.Item label="作用域">{policyQuery.data.scope}</Descriptions.Item>
                <Descriptions.Item label="签发时间">
                  {formatDateTime(policyQuery.data.issued_at)}
                </Descriptions.Item>
                <Descriptions.Item label="过期时间">
                  {formatDateTime(policyQuery.data.expires_at)}
                </Descriptions.Item>
                <Descriptions.Item label="签名" span={2}>
                  <Typography.Text
                    ellipsis
                    style={{ fontFamily: 'monospace', fontSize: 12, maxWidth: 480 }}
                  >
                    {policyQuery.data.signature || '-'}
                  </Typography.Text>
                </Descriptions.Item>
              </Descriptions>
              <div>
                <Typography.Text strong>策略内容（JSON，可编辑）</Typography.Text>
                <Input.TextArea
                  style={{ marginTop: 8, fontFamily: 'monospace', fontSize: 12 }}
                  rows={14}
                  value={policyText}
                  onChange={(e) => setPolicyText(e.target.value)}
                />
              </div>
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                保存时携带当前版本号（v{policyQuery.data.version}
                ）做乐观锁校验；若提示版本冲突，请先刷新再修改。
              </Typography.Text>
            </>
          ) : null}
        </Space>
      </Drawer>
    </Card>
  )
}
