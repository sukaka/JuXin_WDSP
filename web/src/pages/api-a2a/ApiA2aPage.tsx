import { useMemo, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import {
  DeleteOutlined,
  EditOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
  ShareAltOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import {
  API_A2A_LIMITS,
  apiA2aApi,
  type A2aAgentCreateBody,
  type A2aAgentItem,
  type A2aAgentStatus,
  type A2aAgentUpdateBody,
  type A2aEventItem,
} from '../../api/apiA2a'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import SmartTable from '../../components/SmartTable'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  A2A_ACTION_TAKEN_META,
  A2A_AGENT_STATUS_META,
  A2A_EVENT_TYPE_META,
  A2A_RULE_ID_META,
  validateAgentUrl,
} from '../../utils/apiA2a'

const AGENT_STATUS_OPTIONS = Object.entries(A2A_AGENT_STATUS_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

const EVENT_TYPE_OPTIONS = Object.entries(A2A_EVENT_TYPE_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

const RULE_ID_OPTIONS = Object.entries(A2A_RULE_ID_META).map(
  ([value, meta]) => ({ value, label: `${meta.label} (${value})` }),
)

interface AppOption {
  value: string
  label: string
}

interface RegisterAgentFormValues {
  application_id: string
  agent_name: string
  agent_url: string
  agent_version: string
  status: A2aAgentStatus
  description: string
  skills: string[]
  allowed_skills: string[]
  auth_schemes: string[]
}

interface EditAgentFormValues {
  status: A2aAgentStatus
  description: string
  allowed_skills: string[]
}

function cleanStringList(items: string[] | undefined): string[] {
  return Array.from(
    new Set((items ?? []).map((v) => v.trim()).filter(Boolean)),
  )
}

/** 登记 Agent 弹窗（AgBOM 预登记） */
function RegisterAgentModal({
  appOptions,
  defaultAppId,
  onClose,
  onCreated,
}: {
  appOptions: AppOption[]
  defaultAppId?: string
  onClose: () => void
  onCreated: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<RegisterAgentFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const createMut = useMutation({
    mutationFn: (body: A2aAgentCreateBody) => apiA2aApi.createAgent(body),
    onSuccess: () => {
      message.success('Agent 资产已登记至 AgBOM')
      onCreated()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '登记 Agent 失败')
    },
  })

  return (
    <Modal
      title="登记 Agent（AgBOM）"
      open
      width={640}
      okText="确认登记"
      cancelText="取消"
      confirmLoading={createMut.isPending}
      onCancel={onClose}
      onOk={() => form.submit()}
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 14 }}
          title={submitError}
        />
      )}
      <Form<RegisterAgentFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          application_id: defaultAppId ?? appOptions[0]?.value ?? '',
          agent_name: '',
          agent_url: '',
          agent_version: '1.0.0',
          status: 'APPROVED',
          description: '',
          skills: [],
          allowed_skills: [],
          auth_schemes: ['bearer'],
        }}
        onFinish={(values) => {
          setSubmitError(null)
          createMut.mutate({
            application_id: values.application_id.trim(),
            agent_name: values.agent_name.trim(),
            agent_url: values.agent_url.trim(),
            agent_version: (values.agent_version ?? '').trim(),
            status: values.status,
            description: (values.description ?? '').trim(),
            skills: cleanStringList(values.skills),
            allowed_skills: cleanStringList(values.allowed_skills),
            auth_schemes: cleanStringList(values.auth_schemes),
          })
        }}
      >
        <Form.Item
          name="application_id"
          label="所属应用"
          rules={[{ required: true, message: '请选择所属应用' }]}
        >
          {appOptions.length > 0 ? (
            <Select
              showSearch
              optionFilterProp="label"
              placeholder="选择应用"
              options={appOptions}
            />
          ) : (
            <Input placeholder="输入应用 ID（UUID）" autoComplete="off" />
          )}
        </Form.Item>

        <Form.Item
          name="agent_name"
          label="Agent 名称"
          rules={[
            { required: true, whitespace: true, message: '请输入 Agent 名称' },
            {
              max: API_A2A_LIMITS.maxAgbomAgentNameLen,
              message: `Agent 名称不能超过 ${API_A2A_LIMITS.maxAgbomAgentNameLen} 字符`,
            },
          ]}
        >
          <Input placeholder="如：billing-agent" autoComplete="off" />
        </Form.Item>

        <Form.Item
          name="agent_url"
          label="Agent Card / 服务地址"
          extra="支持合法 http(s) URL（不含内嵌凭据）或单 / 开头的相对路径"
          rules={[
            {
              validator: (_, raw?: string) => {
                const err = validateAgentUrl(raw)
                return err ? Promise.reject(new Error(err)) : Promise.resolve()
              },
            },
          ]}
        >
          <Input placeholder="如：https://agents.example.com/billing" autoComplete="off" />
        </Form.Item>

        <Space size={16} wrap style={{ display: 'flex' }}>
          <Form.Item
            name="agent_version"
            label="Agent 版本"
            style={{ width: 220 }}
            rules={[
              {
                max: API_A2A_LIMITS.maxAgentVersionLen,
                message: `版本不能超过 ${API_A2A_LIMITS.maxAgentVersionLen} 字符`,
              },
            ]}
          >
            <Input placeholder="如：1.0.0" autoComplete="off" />
          </Form.Item>
          <Form.Item
            name="status"
            label="审批状态"
            style={{ width: 220 }}
            rules={[{ required: true, message: '请选择审批状态' }]}
          >
            <Select options={AGENT_STATUS_OPTIONS} />
          </Form.Item>
        </Space>

        <Form.Item
          name="skills"
          label="声明技能（skills）"
          extra="输入技能标识后回车，如 invoice.read、refund.create"
        >
          <Select
            mode="tags"
            open={false}
            tokenSeparators={[',']}
            placeholder="回车添加技能"
          />
        </Form.Item>

        <Form.Item
          name="allowed_skills"
          label="允许调用技能（allowed_skills）"
          extra="留空表示暂不限制特定技能，非空则按最小权限约束"
        >
          <Select
            mode="tags"
            open={false}
            tokenSeparators={[',']}
            placeholder="回车添加允许技能"
          />
        </Form.Item>

        <Form.Item
          name="auth_schemes"
          label="认证方案（auth_schemes）"
          extra="如 bearer、oauth2、mtls"
        >
          <Select
            mode="tags"
            open={false}
            tokenSeparators={[',']}
            placeholder="回车添加认证方案"
          />
        </Form.Item>

        <Form.Item
          name="description"
          label="用途与安全审批说明"
          rules={[
            {
              max: API_A2A_LIMITS.maxDescriptionLen,
              message: `说明不能超过 ${API_A2A_LIMITS.maxDescriptionLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={3}
            placeholder="记录该 Agent 的业务职责、所属团队与审批结论"
          />
        </Form.Item>
      </Form>
    </Modal>
  )
}

/** AgBOM Agent 审批/编辑抽屉 */
function AgentReviewDrawer({
  agent,
  appName,
  onClose,
  onSaved,
}: {
  agent: A2aAgentItem
  appName: string
  onClose: () => void
  onSaved: () => void
}) {
  const { message } = AntdApp.useApp()
  const [form] = Form.useForm<EditAgentFormValues>()
  const [submitError, setSubmitError] = useState<string | null>(null)

  const updateMut = useMutation({
    mutationFn: (body: A2aAgentUpdateBody) =>
      apiA2aApi.updateAgent(agent.id, body),
    onSuccess: () => {
      message.success('Agent 审批状态与允许技能已更新')
      onSaved()
      onClose()
    },
    onError: (e: unknown) => {
      setSubmitError(e instanceof ApiError ? e.message : '更新 Agent 失败')
    },
  })

  return (
    <Drawer
      title={`审批 / 编辑 Agent：${agent.agent_name}`}
      open
      width={600}
      onClose={onClose}
      extra={
        <Space>
          <Button onClick={onClose}>取消</Button>
          <Button
            type="primary"
            loading={updateMut.isPending}
            onClick={() => form.submit()}
          >
            保存审批
          </Button>
        </Space>
      }
    >
      {submitError && (
        <Alert
          type="error"
          showIcon
          style={{ marginBottom: 16 }}
          title={submitError}
        />
      )}

      <Descriptions
        bordered
        size="small"
        column={1}
        style={{ marginBottom: 20 }}
      >
        <Descriptions.Item label="所属应用">{appName}</Descriptions.Item>
        <Descriptions.Item label="Agent 名称">
          <Typography.Text strong>{agent.agent_name}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="Agent 地址">
          <Typography.Text code style={{ wordBreak: 'break-all' }}>
            {agent.agent_url || '-'}
          </Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="Agent 版本">
          {agent.agent_version || '-'}
        </Descriptions.Item>
        <Descriptions.Item label="已发现技能">
          {agent.skills.length > 0 ? (
            <Space size={4} wrap>
              {agent.skills.map((s) => (
                <Tag key={s} color="geekblue">
                  {s}
                </Tag>
              ))}
              <Button
                type="link"
                size="small"
                style={{ paddingInline: 4 }}
                onClick={() => form.setFieldValue('allowed_skills', agent.skills)}
              >
                全部采纳为允许技能
              </Button>
            </Space>
          ) : (
            <Typography.Text type="secondary">暂无声明技能</Typography.Text>
          )}
        </Descriptions.Item>
        <Descriptions.Item label="认证方案">
          {agent.auth_schemes.length > 0 ? (
            <Space size={4} wrap>
              {agent.auth_schemes.map((s) => (
                <Tag key={s}>{s}</Tag>
              ))}
            </Space>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="观测次数 / 最近发现">
          {`${agent.observed_count} 次${agent.last_seen_at ? ` · ${formatDateTime(agent.last_seen_at)}` : ''}`}
        </Descriptions.Item>
      </Descriptions>

      <Form<EditAgentFormValues>
        form={form}
        layout="vertical"
        initialValues={{
          status: (agent.status as A2aAgentStatus) || 'DISCOVERED',
          description: agent.description ?? '',
          allowed_skills: agent.allowed_skills ?? [],
        }}
        onFinish={(values) => {
          setSubmitError(null)
          updateMut.mutate({
            status: values.status,
            description: (values.description ?? '').trim(),
            allowed_skills: cleanStringList(values.allowed_skills),
          })
        }}
      >
        <Form.Item
          name="status"
          label="审批状态"
          rules={[{ required: true, message: '请选择审批状态' }]}
        >
          <Select options={AGENT_STATUS_OPTIONS} />
        </Form.Item>

        <Form.Item
          name="allowed_skills"
          label="允许技能（allowed_skills）"
          extra="自动发现上报不会覆盖人工审批后的状态、说明与允许技能列表"
        >
          <Select
            mode="tags"
            open={false}
            tokenSeparators={[',']}
            placeholder="输入技能标识后回车"
          />
        </Form.Item>

        <Form.Item
          name="description"
          label="审批备注 / 描述"
          rules={[
            {
              max: API_A2A_LIMITS.maxDescriptionLen,
              message: `描述不能超过 ${API_A2A_LIMITS.maxDescriptionLen} 字符`,
            },
          ]}
        >
          <Input.TextArea
            rows={4}
            placeholder="记录审批依据、责任人或封禁原因"
          />
        </Form.Item>
      </Form>
    </Drawer>
  )
}

/**
 * A2A 协议安全与 Agent 物料清单（AgBOM）治理页（WDSP Phase 9C-1）。
 * 路由：/api-a2a；权限：api_a2a.read（只读）/ api_a2a.manage（登记/审批/删除）。
 */
export default function ApiA2aPage() {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_a2a.manage')
  const canReadApps = hasPermission(permissions, 'applications.read')

  const [activeTab, setActiveTab] = useState<'agents' | 'events'>('agents')

  // Tab 1（AgBOM）筛选与分页
  const [agentAppId, setAgentAppId] = useState<string | undefined>(undefined)
  const [agentStatus, setAgentStatus] = useState<string | undefined>(undefined)
  const [agentKeyword, setAgentKeyword] = useState('')
  const [agentPage, setAgentPage] = useState(1)
  const [agentPageSize, setAgentPageSize] = useState(20)
  const [registerModalOpen, setRegisterModalOpen] = useState(false)
  const [editingAgent, setEditingAgent] = useState<A2aAgentItem | null>(null)

  // Tab 2（安全事件）筛选与分页
  const [eventAppId, setEventAppId] = useState<string | undefined>(undefined)
  const [eventType, setEventType] = useState<string | undefined>(undefined)
  const [eventRuleId, setEventRuleId] = useState<string | undefined>(undefined)
  const [eventPage, setEventPage] = useState(1)
  const [eventPageSize, setEventPageSize] = useState(20)

  const appsQuery = useQuery({
    queryKey: ['applications', 'a2a-options'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 200 }),
    enabled: canReadApps,
  })

  const appOptions = useMemo<AppOption[]>(
    () =>
      (appsQuery.data?.items ?? []).map((a) => ({
        value: a.id,
        label: a.name ? `${a.name} (${a.code})` : a.code,
      })),
    [appsQuery.data?.items],
  )

  const appNameMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const a of appsQuery.data?.items ?? []) {
      map.set(a.id, a.name || a.code)
    }
    return map
  }, [appsQuery.data?.items])

  const resolveAppLabel = (
    appId: string,
    fallbackName?: string,
    fallbackCode?: string,
  ): string => fallbackName || appNameMap.get(appId) || fallbackCode || appId

  const agentsQuery = useQuery({
    queryKey: [
      'api-a2a-agents',
      agentAppId,
      agentStatus,
      agentKeyword.trim(),
      agentPage,
      agentPageSize,
    ],
    queryFn: () =>
      apiA2aApi.listAgents({
        application_id: agentAppId,
        status: agentStatus,
        keyword: agentKeyword.trim() || undefined,
        page: agentPage,
        page_size: agentPageSize,
      }),
  })

  const eventsQuery = useQuery({
    queryKey: [
      'api-a2a-events',
      eventAppId,
      eventType,
      eventRuleId,
      eventPage,
      eventPageSize,
    ],
    queryFn: () =>
      apiA2aApi.listEvents({
        application_id: eventAppId,
        event_type: eventType,
        rule_id: eventRuleId,
        page: eventPage,
        page_size: eventPageSize,
      }),
    enabled: activeTab === 'events',
  })

  const invalidateAgents = () =>
    void queryClient.invalidateQueries({ queryKey: ['api-a2a-agents'] })

  const deleteAgentMut = useMutation({
    mutationFn: (id: string) => apiA2aApi.deleteAgent(id),
    onSuccess: () => {
      message.success('Agent 记录已从 AgBOM 删除')
      invalidateAgents()
    },
    onError: (e: unknown) =>
      message.error(e instanceof ApiError ? e.message : '删除 Agent 失败'),
  })

  const agentColumns: ColumnsType<A2aAgentItem> = [
    {
      title: 'Agent 名称',
      dataIndex: 'agent_name',
      key: 'agent_name',
      width: 210,
      render: (v: string, record) => (
        <Space orientation="vertical" size={2} style={{ maxWidth: 195 }}>
          <Typography.Text strong ellipsis={{ tooltip: v }}>
            {v}
          </Typography.Text>
          <Tag style={{ fontSize: 11, marginInlineEnd: 0 }}>
            {resolveAppLabel(
              record.application_id,
              record.application_name,
              record.application_code,
            )}
          </Tag>
        </Space>
      ),
    },
    {
      title: 'Agent 地址',
      dataIndex: 'agent_url',
      key: 'agent_url',
      width: 240,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text
            code
            ellipsis={{ tooltip: v }}
            style={{ fontSize: 12, maxWidth: 220 }}
          >
            {v}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '版本',
      dataIndex: 'agent_version',
      key: 'agent_version',
      width: 95,
      render: (v: string) => v || '-',
    },
    {
      title: '技能（Skills）',
      dataIndex: 'skills',
      key: 'skills',
      width: 230,
      render: (skills: string[], record) => {
        const list = skills ?? []
        if (list.length === 0) {
          return <Typography.Text type="secondary">-</Typography.Text>
        }
        return (
          <Space size={4} wrap>
            {list.slice(0, 4).map((skill) => {
              const allowed = record.allowed_skills.includes(skill)
              return (
                <Tag
                  key={skill}
                  color={allowed ? 'green' : 'geekblue'}
                  style={{ marginInlineEnd: 0 }}
                >
                  {skill}
                </Tag>
              )
            })}
            {list.length > 4 && (
              <Tooltip title={list.join(', ')}>
                <Tag style={{ marginInlineEnd: 0 }}>+{list.length - 4}</Tag>
              </Tooltip>
            )}
          </Space>
        )
      },
    },
    {
      title: '认证方案',
      dataIndex: 'auth_schemes',
      key: 'auth_schemes',
      width: 145,
      render: (schemes: string[]) =>
        schemes && schemes.length > 0 ? (
          <Space size={4} wrap>
            {schemes.map((s) => (
              <Tag key={s} style={{ marginInlineEnd: 0 }}>
                {s}
              </Tag>
            ))}
          </Space>
        ) : (
          <Typography.Text type="secondary">-</Typography.Text>
        ),
    },
    {
      title: '审批状态',
      dataIndex: 'status',
      key: 'status',
      width: 125,
      render: (v: string) => (
        <StatusTag value={v} map={A2A_AGENT_STATUS_META} />
      ),
    },
    {
      title: '观测次数',
      dataIndex: 'observed_count',
      key: 'observed_count',
      width: 95,
      align: 'right',
    },
    {
      title: '最近观测时间',
      dataIndex: 'last_seen_at',
      key: 'last_seen_at',
      width: 170,
      render: (v?: string | null) => (v ? formatDateTime(v) : '-'),
    },
    ...(canManage
      ? [
          {
            title: '操作',
            key: 'actions',
            width: 155,
            fixed: 'right' as const,
            render: (_: unknown, record: A2aAgentItem) => (
              <Space size={0}>
                <Button
                  type="link"
                  size="small"
                  icon={<EditOutlined />}
                  onClick={() => setEditingAgent(record)}
                >
                  审批/编辑
                </Button>
                <Popconfirm
                  title={`确定删除 Agent「${record.agent_name}」吗？`}
                  description="删除后若网关再次发现该 Agent Card 将按自动发现待审重新录入。"
                  okText="确认删除"
                  okButtonProps={{ danger: true }}
                  onConfirm={() => deleteAgentMut.mutate(record.id)}
                >
                  <Button
                    type="link"
                    size="small"
                    danger
                    icon={<DeleteOutlined />}
                  >
                    删除
                  </Button>
                </Popconfirm>
              </Space>
            ),
          },
        ]
      : []),
  ]

  const eventColumns: ColumnsType<A2aEventItem> = [
    {
      title: '发生时间',
      dataIndex: 'occurred_at',
      key: 'occurred_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '事件类型',
      dataIndex: 'event_type',
      key: 'event_type',
      width: 150,
      render: (v: string) => (
        <StatusTag value={v} map={A2A_EVENT_TYPE_META} />
      ),
    },
    {
      title: 'A2A 方法',
      dataIndex: 'method',
      key: 'method',
      width: 145,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
    {
      title: 'Agent 名称',
      dataIndex: 'agent_name',
      key: 'agent_name',
      width: 180,
      render: (v: string, record) => (
        <Space orientation="vertical" size={2}>
          <Typography.Text strong>{v || '-'}</Typography.Text>
          <Tag style={{ fontSize: 11, marginInlineEnd: 0 }}>
            {resolveAppLabel(
              record.application_id,
              record.application_name,
              record.application_code,
            )}
          </Tag>
        </Space>
      ),
    },
    {
      title: '委派深度',
      dataIndex: 'delegation_depth',
      key: 'delegation_depth',
      width: 95,
      align: 'right',
      render: (v: number) => (
        <Tag color={v > 3 ? 'volcano' : 'default'} style={{ marginInlineEnd: 0 }}>
          {v}
        </Tag>
      ),
    },
    {
      title: '命中规则',
      dataIndex: 'rule_id',
      key: 'rule_id',
      width: 195,
      render: (v: string) =>
        v ? (
          <Tooltip title={v}>
            <span>
              <StatusTag value={v} map={A2A_RULE_ID_META} />
            </span>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '执行动作',
      dataIndex: 'action_taken',
      key: 'action_taken',
      width: 115,
      render: (v: string) =>
        v ? <StatusTag value={v} map={A2A_ACTION_TAKEN_META} /> : '-',
    },
    {
      title: '触发原因',
      dataIndex: 'reason',
      key: 'reason',
      width: 240,
      ellipsis: true,
      render: (v: string) =>
        v ? (
          <Typography.Text ellipsis={{ tooltip: v }} style={{ fontSize: 12 }}>
            {v}
          </Typography.Text>
        ) : (
          '-'
        ),
    },
    {
      title: '客户端 IP',
      dataIndex: 'client_ip',
      key: 'client_ip',
      width: 135,
      render: (v: string) =>
        v ? <Typography.Text code>{v}</Typography.Text> : '-',
    },
  ]

  return (
    <Card
      title={
        <Space>
          <ShareAltOutlined />
          <span>A2A 与 AgBOM 治理</span>
        </Space>
      }
      extra={
        <Tag color="blue" icon={<SafetyCertificateOutlined />}>
          A2A 安全网关 · RFC 8693 委派治理
        </Tag>
      }
    >
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        title="覆盖 A2A Agent Card 自动发现（AgBOM 物料清单审批台账）、RFC 8693 委派链深度与权限递减校验、递归循环熔断及机密读取+外部外传致命三要素阻断；各应用策略可在「网站应用 → 详情 → A2A 安全治理」配置并随发布下发。"
      />

      <Tabs
        activeKey={activeTab}
        onChange={(k) => setActiveTab(k as 'agents' | 'events')}
        items={[
          {
            key: 'agents',
            label: 'Agent 物料清单（AgBOM）',
            children: (
              <>
                <Space
                  style={{
                    marginBottom: 16,
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                  wrap
                >
                  <Space wrap>
                    {appOptions.length > 0 && (
                      <Select
                        allowClear
                        showSearch
                        optionFilterProp="label"
                        placeholder="按应用筛选"
                        value={agentAppId}
                        onChange={(v) => {
                          setAgentAppId(v)
                          setAgentPage(1)
                        }}
                        options={appOptions}
                        style={{ width: 200 }}
                      />
                    )}
                    <Select
                      allowClear
                      placeholder="按审批状态筛选"
                      value={agentStatus}
                      onChange={(v) => {
                        setAgentStatus(v)
                        setAgentPage(1)
                      }}
                      options={AGENT_STATUS_OPTIONS}
                      style={{ width: 160 }}
                    />
                    <Input.Search
                      allowClear
                      placeholder="搜索 Agent 名称、地址或描述"
                      value={agentKeyword}
                      onChange={(e) => {
                        setAgentKeyword(e.target.value)
                        setAgentPage(1)
                      }}
                      style={{ width: 260 }}
                    />
                  </Space>
                  {canManage && (
                    <Button
                      type="primary"
                      icon={<PlusOutlined />}
                      onClick={() => setRegisterModalOpen(true)}
                    >
                      登记 Agent
                    </Button>
                  )}
                </Space>

                {agentsQuery.isError ? (
                  <QueryErrorAlert
                    error={agentsQuery.error}
                    message="加载 Agent 物料清单失败"
                  />
                ) : (
                  <SmartTable<A2aAgentItem>
                    rowKey="id"
                    storageKey="api-a2a-agents"
                    loading={agentsQuery.isLoading}
                    columns={agentColumns}
                    dataSource={agentsQuery.data?.items ?? []}
                    scroll={{ x: 1460 }}
                    onRefresh={() => agentsQuery.refetch()}
                    pagination={{
                      current: agentPage,
                      pageSize: agentPageSize,
                      total: agentsQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 条 Agent 资产`,
                      onChange: (p, ps) => {
                        setAgentPage(p)
                        setAgentPageSize(ps)
                      },
                    }}
                  />
                )}
              </>
            ),
          },
          {
            key: 'events',
            label: 'A2A 安全事件（委派/循环/三要素）',
            children: (
              <>
                <Space
                  style={{
                    marginBottom: 16,
                    display: 'flex',
                    justifyContent: 'space-between',
                  }}
                  wrap
                >
                  <Space wrap>
                    {appOptions.length > 0 && (
                      <Select
                        allowClear
                        showSearch
                        optionFilterProp="label"
                        placeholder="按应用筛选"
                        value={eventAppId}
                        onChange={(v) => {
                          setEventAppId(v)
                          setEventPage(1)
                        }}
                        options={appOptions}
                        style={{ width: 200 }}
                      />
                    )}
                    <Select
                      allowClear
                      placeholder="按事件类型筛选"
                      value={eventType}
                      onChange={(v) => {
                        setEventType(v)
                        setEventPage(1)
                      }}
                      options={EVENT_TYPE_OPTIONS}
                      style={{ width: 185 }}
                    />
                    <Select
                      allowClear
                      placeholder="按命中规则筛选"
                      value={eventRuleId}
                      onChange={(v) => {
                        setEventRuleId(v)
                        setEventPage(1)
                      }}
                      options={RULE_ID_OPTIONS}
                      style={{ width: 260 }}
                    />
                  </Space>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    共 {eventsQuery.data?.total ?? 0} 条安全事件
                  </Typography.Text>
                </Space>

                {eventsQuery.isError ? (
                  <QueryErrorAlert
                    error={eventsQuery.error}
                    message="加载 A2A 安全事件失败"
                  />
                ) : (
                  <SmartTable<A2aEventItem>
                    rowKey="id"
                    storageKey="api-a2a-events"
                    loading={eventsQuery.isLoading}
                    columns={eventColumns}
                    dataSource={eventsQuery.data?.items ?? []}
                    scroll={{ x: 1480 }}
                    onRefresh={() => eventsQuery.refetch()}
                    pagination={{
                      current: eventPage,
                      pageSize: eventPageSize,
                      total: eventsQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 条 A2A 安全事件`,
                      onChange: (p, ps) => {
                        setEventPage(p)
                        setEventPageSize(ps)
                      },
                    }}
                  />
                )}
              </>
            ),
          },
        ]}
      />

      {registerModalOpen && (
        <RegisterAgentModal
          appOptions={appOptions}
          defaultAppId={agentAppId}
          onClose={() => setRegisterModalOpen(false)}
          onCreated={invalidateAgents}
        />
      )}

      {editingAgent && (
        <AgentReviewDrawer
          agent={editingAgent}
          appName={resolveAppLabel(
            editingAgent.application_id,
            editingAgent.application_name,
            editingAgent.application_code,
          )}
          onClose={() => setEditingAgent(null)}
          onSaved={invalidateAgents}
        />
      )}
    </Card>
  )
}
