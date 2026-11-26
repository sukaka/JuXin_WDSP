import { useEffect } from 'react'
import { Link, useInRouterContext } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Form,
  Input,
  InputNumber,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { SafetyCertificateOutlined, ShareAltOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  API_A2A_LIMITS,
  apiA2aApi,
  type A2aPolicyMode,
} from '../../../api/apiA2a'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  A2A_DEFAULT_CONFIDENTIAL_READ_PATTERNS,
  A2A_DEFAULT_EXTERNAL_EGRESS_PATTERNS,
  A2A_DEFAULT_PATH_PREFIXES,
  A2A_MODE_META,
  A2A_STATE_META,
  mapA2aFieldErrorPath,
  validateA2aPathPrefixes,
  validateA2aPatterns,
  validateAllowedCallerAgents,
} from '../../../utils/apiA2a'
import {
  InlineNote,
  ModeCardGroup,
  SectionHeader,
  type ModeCardOption,
} from './DetailTabPrimitives'
import './detailTab.css'

const MODE_CARD_OPTIONS: ModeCardOption<A2aPolicyMode>[] = [
  {
    value: 'OFF',
    label: '关闭（不启用 A2A 安全检测）',
    description: '透传 Agent Card 与 A2A JSON-RPC 流量，不做委派、循环或三要素校验',
    badge: '默认',
    tone: 'neutral',
  },
  {
    value: 'OBSERVE',
    label: '观察（发现 AgBOM 与记录告警，不阻断）',
    description:
      '自动发现 Agent Card 上报 AgBOM，并记录委派越权、递归循环与三要素风险事件',
    badge: '推荐先用',
    badgeColor: 'blue',
    tone: 'info',
  },
  {
    value: 'PROTECT',
    label: '强制执行（在线阻断与熔断）',
    description:
      '强制执行调用方白名单、RFC 8693 委派深度/权限递减校验、递归循环 429 熔断与三要素 403 阻断',
    badge: '在线防护',
    badgeColor: 'green',
    tone: 'success',
  },
]

interface PolicyFormValues {
  mode: A2aPolicyMode
  card_discovery_enabled: boolean
  a2a_path_prefixes: string[]
  allowed_caller_agents: string[]
  max_delegation_depth: number
  enforce_scope_attenuation: boolean
  loop_window_seconds: number
  max_calls_per_task_window: number
  lethal_trifecta_enabled: boolean
  confidential_read_patterns: string[]
  external_egress_patterns: string[]
  reason: string
}

const DEFAULT_VALUES: PolicyFormValues = {
  mode: 'OFF',
  card_discovery_enabled: true,
  a2a_path_prefixes: [...A2A_DEFAULT_PATH_PREFIXES],
  allowed_caller_agents: [],
  max_delegation_depth: API_A2A_LIMITS.defaultDelegationDepth,
  enforce_scope_attenuation: true,
  loop_window_seconds: API_A2A_LIMITS.defaultLoopWindow,
  max_calls_per_task_window: API_A2A_LIMITS.defaultMaxCalls,
  lethal_trifecta_enabled: true,
  confidential_read_patterns: [...A2A_DEFAULT_CONFIDENTIAL_READ_PATTERNS],
  external_egress_patterns: [...A2A_DEFAULT_EXTERNAL_EGRESS_PATTERNS],
  reason: '',
}

function cleanStringList(items: string[] | undefined): string[] {
  return Array.from(
    new Set((items ?? []).map((v) => v.trim()).filter(Boolean)),
  )
}

export default function A2aPolicyTab({
  appId,
  appCode,
}: {
  appId: string
  appCode: string
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const inRouter = useInRouterContext()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'api_a2a.manage')
  const [form] = Form.useForm<PolicyFormValues>()

  const cardDiscoveryWatch =
    Form.useWatch('card_discovery_enabled', form) ?? true
  const scopeAttenuationWatch =
    Form.useWatch('enforce_scope_attenuation', form) ?? true
  const lethalTrifectaWatch =
    Form.useWatch('lethal_trifecta_enabled', form) ?? true

  const policyQuery = useQuery({
    queryKey: ['api-a2a-policy', appId],
    queryFn: () => apiA2aApi.getPolicy(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      card_discovery_enabled: Boolean(policy.card_discovery_enabled),
      a2a_path_prefixes: policy.a2a_path_prefixes ?? [],
      allowed_caller_agents: policy.allowed_caller_agents ?? [],
      max_delegation_depth:
        policy.max_delegation_depth || API_A2A_LIMITS.defaultDelegationDepth,
      enforce_scope_attenuation: Boolean(policy.enforce_scope_attenuation),
      loop_window_seconds:
        policy.loop_window_seconds || API_A2A_LIMITS.defaultLoopWindow,
      max_calls_per_task_window:
        policy.max_calls_per_task_window || API_A2A_LIMITS.defaultMaxCalls,
      lethal_trifecta_enabled: Boolean(policy.lethal_trifecta_enabled),
      confidential_read_patterns: policy.confidential_read_patterns ?? [],
      external_egress_patterns: policy.external_egress_patterns ?? [],
      reason: '',
    })
  }, [policy, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ['api-a2a-policy', appId],
    })

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      apiA2aApi.updatePolicy(appId, {
        mode: values.mode,
        expected_version: policy?.version ?? 0,
        card_discovery_enabled: Boolean(values.card_discovery_enabled),
        a2a_path_prefixes: cleanStringList(values.a2a_path_prefixes),
        allowed_caller_agents: cleanStringList(values.allowed_caller_agents),
        max_delegation_depth: values.max_delegation_depth,
        enforce_scope_attenuation: Boolean(values.enforce_scope_attenuation),
        loop_window_seconds: values.loop_window_seconds,
        max_calls_per_task_window: values.max_calls_per_task_window,
        lethal_trifecta_enabled: Boolean(values.lethal_trifecta_enabled),
        confidential_read_patterns: cleanStringList(
          values.confidential_read_patterns,
        ),
        external_egress_patterns: cleanStringList(
          values.external_egress_patterns,
        ),
        reason: values.reason.trim(),
      }),
    onSuccess: () => {
      message.success('A2A 策略草稿已保存；发布并获节点回执后才会生效')
      invalidate()
    },
    onError: (e: unknown) => {
      if (
        e instanceof ApiError &&
        (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
      ) {
        message.warning('策略已被其他人修改，请刷新后重试')
        invalidate()
        return
      }
      if (e instanceof ApiError && Array.isArray(e.details)) {
        const details = e.details as { field?: string; message?: string }[]
        const fields: { name: (string | number)[]; errors: string[] }[] = []
        const unmapped: string[] = []
        for (const d of details) {
          if (!d.field) continue
          const errMsg = d.message ?? '取值不合法'
          const name = mapA2aFieldErrorPath(d.field)
          if (name) {
            fields.push({ name, errors: [errMsg] })
          } else {
            unmapped.push(`${d.field}: ${errMsg}`)
          }
        }
        if (fields.length > 0) {
          form.setFields(fields as Parameters<typeof form.setFields>[0])
        }
        message.error(
          unmapped.length > 0
            ? `${e.message}（${unmapped.join('；')}）`
            : e.message || '保存失败，请检查输入',
        )
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存失败')
    },
  })

  if (policyQuery.isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
        <Spin />
      </div>
    )
  }

  if (policyQuery.isError || !policy || !summary) {
    return (
      <QueryErrorAlert
        error={policyQuery.error}
        message="加载 A2A 安全治理策略失败"
      />
    )
  }

  const effectiveMode = summary.state === 'PUBLISHED' ? policy.mode : null

  return (
    <div className="jz-detail-tab">
      <Card
        className="jz-detail-card"
        title="策略状态"
        extra={
          <Space size={12}>
            {inRouter && (
              <Link to="/api-a2a">
                <Button type="link" size="small" style={{ paddingInline: 0 }}>
                  查看 AgBOM 与 A2A 安全事件
                </Button>
              </Link>
            )}
            {summary.state === 'DRAFT_PENDING' && inRouter && (
              <Link to="/config-publish">
                <Button type="link" size="small" style={{ paddingInline: 0 }}>
                  前往配置发布
                </Button>
              </Link>
            )}
          </Space>
        }
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用范围">
            <Typography.Text code>{appCode}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="配置状态">
            <StatusTag value={summary.state} map={A2A_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={A2A_MODE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="草稿版本">
            {summary.draft_version > 0 ? (
              <Typography.Text strong>{`v${summary.draft_version}`}</Typography.Text>
            ) : (
              <Typography.Text type="secondary">无草稿</Typography.Text>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="已生效版本">
            {summary.published_version > 0 ? (
              <Typography.Text strong>{`v${summary.published_version}`}</Typography.Text>
            ) : (
              <Typography.Text type="secondary">未随发布下发</Typography.Text>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="最近更新">
            {policy.updated_at
              ? `${formatDateTime(policy.updated_at)}${policy.updated_by ? ` · ${policy.updated_by}` : ''}`
              : '-'}
          </Descriptions.Item>
        </Descriptions>

        {summary.state === 'DRAFT_PENDING' && (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 14 }}
            title="草稿已保存，尚未生效"
            description={`草稿 v${summary.draft_version} 与已生效版本 v${summary.published_version} 存在差异；需经配置发布并获网关节点回执后方可在线生效。`}
            action={
              inRouter ? (
                <Link to="/config-publish">前往配置发布</Link>
              ) : undefined
            }
          />
        )}
        {summary.state === 'PUBLISHED' &&
          effectiveMode &&
          effectiveMode !== 'OFF' && (
            <Alert
              type="success"
              showIcon
              style={{ marginTop: 14 }}
              title={`已生效：${A2A_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="A2A 协议安全治理策略已随最近成功发布快照下发至网关节点运行。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 14 }}
            title="尚未配置 A2A 安全治理策略，当前维持默认透传行为"
            description="开启后可自动采集 /.well-known/agent.json 与 agent-card.json 生成 AgBOM，并基于已验签 JWT 委派链实施深度限制、权限递减、递归循环熔断与致命三要素防护。"
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="A2A 协议安全与委派熔断策略"
        extra={
          <Space size={6}>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              RFC 8693 Delegation
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>AgBOM · Kill-Switch</Tag>
          </Space>
        }
      >
        <InlineNote tooltip="委派链（act 嵌套）与权限集（scope/scp）仅在网关完成 JWT 密码学签名验证后提取，绝不信任未验签令牌；Agent Card 自动发现仅扫描 <= 256KiB 的 2xx 未压缩 JSON 响应，且绝不覆盖人工已批准或已封禁的 AgBOM 状态。">
          网关仅消费经密码学验签的 JWT 委派链与主体身份；支持对{' '}
          <Typography.Text code style={{ fontSize: 12 }}>
            tasks/send
          </Typography.Text>
          、
          <Typography.Text code style={{ fontSize: 12 }}>
            message/send
          </Typography.Text>{' '}
          等 A2A JSON-RPC 方法执行委派深度、权限递减、循环熔断与致命三要素联动防护。
        </InlineNote>

        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          initialValues={DEFAULT_VALUES}
          disabled={!canManage}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <SectionHeader
            title="运行模式"
            description="控制当前应用对 A2A 流量与 Agent Card 响应的检测及阻断强度。"
          />
          <Form.Item name="mode" style={{ marginBottom: 8 }}>
            <ModeCardGroup options={MODE_CARD_OPTIONS} disabled={!canManage} />
          </Form.Item>

          <SectionHeader
            spaced
            title="Agent Card 发现与入口路径"
            description={`最多可配置 ${API_A2A_LIMITS.maxPathPrefixes} 条 A2A 路径前缀（单条 <= ${API_A2A_LIMITS.maxPathLen} 字符）与 ${API_A2A_LIMITS.maxAllowedAgents} 条允许调用方 Agent 白名单。`}
          />
          <div
            className={`jz-detail-switch-tile${cardDiscoveryWatch ? ' jz-detail-switch-tile--active' : ''}`}
            style={{ marginBottom: 14 }}
          >
            <Form.Item
              name="card_discovery_enabled"
              valuePropName="checked"
              className="jz-detail-switch-form-item"
              label={
                <>
                  <span>启用 Agent Card 自动发现（AgBOM）</span>
                  <span className="jz-detail-switch-desc">
                    自动解析 GET /.well-known/agent.json 与 /.well-known/agent-card.json
                    中的 Agent 名称、版本、技能与认证方案并上报至 AgBOM 台账
                  </span>
                </>
              }
            >
              <Switch />
            </Form.Item>
          </div>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="a2a_path_prefixes"
                label="A2A 协议路径前缀"
                extra={`必须以 / 开头，不含 ?# 或空白，最多 ${API_A2A_LIMITS.maxPathPrefixes} 条`}
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateA2aPathPrefixes(val)
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 /a2a、/.well-known/agent.json"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="allowed_caller_agents"
                label="允许调用方 Agent 白名单（空=不限）"
                extra={`匹配已验签 JWT 主体/azp 或 X-A2A-Agent-ID，最多 ${API_A2A_LIMITS.maxAllowedAgents} 条`}
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateAllowedCallerAgents(val)
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="输入 Agent 标识后回车，如 orchestrator-agent"
                />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="RFC 8693 委派链与权限递减"
            description="限制多跳 Agent 委派链深度，并校验子委派权限不得超越父级权限或包含通配符/管理员提权范围。"
          />
          <Row gutter={[16, 12]} align="top">
            <Col xs={24} md={10}>
              <Form.Item
                name="max_delegation_depth"
                label="最大委派链深度"
                extra={`范围 ${API_A2A_LIMITS.minDelegationDepth}~${API_A2A_LIMITS.maxDelegationDepth} 跳（默认 ${API_A2A_LIMITS.defaultDelegationDepth}）`}
                rules={[
                  { required: true, message: '请填写最大委派链深度' },
                  {
                    type: 'number',
                    min: API_A2A_LIMITS.minDelegationDepth,
                    max: API_A2A_LIMITS.maxDelegationDepth,
                    message: `须在 ${API_A2A_LIMITS.minDelegationDepth} 到 ${API_A2A_LIMITS.maxDelegationDepth} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={API_A2A_LIMITS.minDelegationDepth}
                  max={API_A2A_LIMITS.maxDelegationDepth}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={14}>
              <div
                className={`jz-detail-switch-tile${scopeAttenuationWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="enforce_scope_attenuation"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>强制委派权限递减（Scope Attenuation）</span>
                      <span className="jz-detail-switch-desc">
                        校验嵌套 act.scope 必须为父级权限子集，并拒绝深度 ≥1 的委派链携带 *、admin:*、root 等提权范围
                      </span>
                    </>
                  }
                >
                  <Switch />
                </Form.Item>
              </div>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="递归循环熔断（Loop Kill-Switch）"
            description="基于 (应用, 调用主体, 任务/路径) 滑动窗口检测失控 Agent 递归自调用，超阈触发 429 JSON-RPC -32020 熔断。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="loop_window_seconds"
                label="循环检测滑动窗口（秒）"
                extra={`范围 ${API_A2A_LIMITS.minLoopWindow}~${API_A2A_LIMITS.maxLoopWindow} 秒（默认 ${API_A2A_LIMITS.defaultLoopWindow}）`}
                rules={[
                  { required: true, message: '请填写滑动窗口秒数' },
                  {
                    type: 'number',
                    min: API_A2A_LIMITS.minLoopWindow,
                    max: API_A2A_LIMITS.maxLoopWindow,
                    message: `须在 ${API_A2A_LIMITS.minLoopWindow} 到 ${API_A2A_LIMITS.maxLoopWindow} 秒之间`,
                  },
                ]}
              >
                <InputNumber
                  min={API_A2A_LIMITS.minLoopWindow}
                  max={API_A2A_LIMITS.maxLoopWindow}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="max_calls_per_task_window"
                label="窗口内单任务最大调用次数"
                extra={`范围 ${API_A2A_LIMITS.minMaxCalls}~${API_A2A_LIMITS.maxMaxCalls} 次（默认 ${API_A2A_LIMITS.defaultMaxCalls}）`}
                rules={[
                  { required: true, message: '请填写最大调用次数' },
                  {
                    type: 'number',
                    min: API_A2A_LIMITS.minMaxCalls,
                    max: API_A2A_LIMITS.maxMaxCalls,
                    message: `须在 ${API_A2A_LIMITS.minMaxCalls} 到 ${API_A2A_LIMITS.maxMaxCalls} 次之间`,
                  },
                ]}
              >
                <InputNumber
                  min={API_A2A_LIMITS.minMaxCalls}
                  max={API_A2A_LIMITS.maxMaxCalls}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="致命三要素污点熔断（Lethal Trifecta）"
            description="当同一会话/主体先访问机密读取路径或机密 MCP 工具，随后尝试触发外部外传出口动作时，立即阻断数据渗出链。"
          />
          <div
            className={`jz-detail-switch-tile${lethalTrifectaWatch ? ' jz-detail-switch-tile--active' : ''}`}
            style={{ marginBottom: 14 }}
          >
            <Form.Item
              name="lethal_trifecta_enabled"
              valuePropName="checked"
              className="jz-detail-switch-form-item"
              label={
                <>
                  <span>启用致命三要素污点追踪与熔断</span>
                  <span className="jz-detail-switch-desc">
                    联动追踪机密读取（含 CONFIDENTIAL 级 MCP 工具调用）与外部外传动作，PROTECT 下以 403 JSON-RPC -32021 阻断
                  </span>
                </>
              }
            >
              <Switch />
            </Form.Item>
          </div>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="confidential_read_patterns"
                label="机密读取污点标记模式"
                extra={`路径、方法或工具关键词，最多 ${API_A2A_LIMITS.maxPatterns} 条（单条 <= ${API_A2A_LIMITS.maxPatternLen} 字符）`}
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateA2aPatterns(val, '机密读取模式')
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 /api/v1/secrets、read_secret、query_pii"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="external_egress_patterns"
                label="外部外传出口阻断模式"
                extra={`高风险外传工具或动作关键词，最多 ${API_A2A_LIMITS.maxPatterns} 条（单条 <= ${API_A2A_LIMITS.maxPatternLen} 字符）`}
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateA2aPatterns(val, '外部外传模式')
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 send_email、webhook、upload_external"
                />
              </Form.Item>
            </Col>
          </Row>

          {canManage && (
            <div className="jz-detail-audit-submit-box">
              <Form.Item
                name="reason"
                label="变更理由"
                style={{ marginBottom: 10, maxWidth: 760 }}
                extra="必填，进入操作审计与不可变策略版本记录"
                rules={[
                  {
                    required: true,
                    whitespace: true,
                    message: '请填写变更理由',
                  },
                  {
                    max: API_A2A_LIMITS.maxReasonLen,
                    message: `变更理由不能超过 ${API_A2A_LIMITS.maxReasonLen} 字符`,
                  },
                ]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="说明本次变更原因，如：为多智能体编排接口开启 RFC 8693 委派限制与循环熔断"
                />
              </Form.Item>
              <div className="jz-detail-audit-submit-actions">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  <ShareAltOutlined style={{ marginRight: 6 }} />
                  <SafetyCertificateOutlined style={{ marginRight: 4 }} />
                  草稿保存后须前往「配置发布」下发至网关节点方可生效。
                </Typography.Text>
                <Button
                  type="primary"
                  loading={saveMutation.isPending}
                  onClick={() => form.submit()}
                >
                  保存草稿
                </Button>
              </div>
            </div>
          )}
        </Form>
      </Card>
    </div>
  )
}
