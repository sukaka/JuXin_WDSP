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
  Tooltip,
  Typography,
} from 'antd'
import {
  MinusCircleOutlined,
  PlusOutlined,
  RobotOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  AI_CRAWL_LIMITS,
  aiCrawlApi,
  type AiCrawlAction,
  type AiCrawlMode,
  type AiCrawlRule,
} from '../../../api/aiCrawl'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  AI_CRAWL_ACTION_META,
  AI_CRAWL_CATEGORY_META,
  AI_CRAWL_MODE_META,
  AI_CRAWL_STATE_META,
  CONTENT_SIGNAL_PRESETS,
  mapAiCrawlFieldErrorPath,
} from '../../../utils/aiCrawl'
import {
  InlineNote,
  ModeCardGroup,
  SectionHeader,
  type ModeCardOption,
} from './DetailTabPrimitives'
import './detailTab.css'

const MODE_CARD_OPTIONS: ModeCardOption<AiCrawlMode>[] = [
  {
    value: 'OFF',
    label: '关闭（不治理 AI 爬虫）',
    description: '维持既有流量行为，不校验 Web Bot Auth 签名，不触发迷宫或 402',
    badge: '默认',
    tone: 'neutral',
  },
  {
    value: 'OBSERVE',
    label: '观察（识别与记录，不拦截）',
    description: '识别爬虫类别与 Web Bot Auth 签名并记录观测事件，不影响业务响应',
    badge: '推荐先用',
    badgeColor: 'blue',
    tone: 'info',
  },
  {
    value: 'PROTECT',
    label: '强制执行（按策略处置与迷宫拖延）',
    description: '按优先级规则执行放行、限速、挑战、AI 迷宫、HTTP 402 或阻断',
    badge: '在线防护',
    badgeColor: 'green',
    tone: 'success',
  },
]

const CATEGORY_OPTIONS = Object.entries(AI_CRAWL_CATEGORY_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

const ACTION_OPTIONS = Object.entries(AI_CRAWL_ACTION_META).map(
  ([value, meta]) => ({ value, label: meta.label }),
)

interface RuleFormValue {
  id: string
  name: string
  category: string
  agent_id: string
  ua_patterns: string[]
  require_verified_sig: boolean
  action: string
  exempt_bot_challenge: boolean
  rate_limit_rpm: number
  priority: number
}

interface PolicyFormValues {
  mode: AiCrawlMode
  default_ai_action: AiCrawlAction
  content_signal: string
  verify_web_bot_auth: boolean
  labyrinth_enabled: boolean
  labyrinth_inject_links: boolean
  labyrinth_max_depth: number
  labyrinth_max_concurrency: number
  labyrinth_delay_ms: number
  http_402_message: string
  http_402_price_hint: string
  http_402_contact_url: string
  http_402_receipt_header: string
  rules: RuleFormValue[]
  reason: string
}

const DEFAULT_VALUES: PolicyFormValues = {
  mode: 'OFF',
  default_ai_action: 'ALLOW',
  content_signal: AI_CRAWL_LIMITS.defaultContentSignal,
  verify_web_bot_auth: true,
  labyrinth_enabled: false,
  labyrinth_inject_links: false,
  labyrinth_max_depth: AI_CRAWL_LIMITS.defaultLabyrinthMaxDepth,
  labyrinth_max_concurrency: AI_CRAWL_LIMITS.defaultLabyrinthMaxConcurrency,
  labyrinth_delay_ms: AI_CRAWL_LIMITS.defaultLabyrinthDelayMs,
  http_402_message: '',
  http_402_price_hint: '',
  http_402_contact_url: '',
  http_402_receipt_header: '',
  rules: [],
  reason: '',
}

function toRules(values: RuleFormValue[]): AiCrawlRule[] {
  return (values ?? []).map((r, idx) => ({
    id: (r.id ?? '').trim() || `rule-${idx + 1}`,
    name: (r.name ?? '').trim(),
    category: r.category || 'UNKNOWN_BOT',
    agent_id: (r.agent_id ?? '').trim(),
    ua_patterns: Array.from(
      new Set((r.ua_patterns ?? []).map((p) => p.trim()).filter(Boolean)),
    ),
    require_verified_sig: Boolean(r.require_verified_sig),
    action: r.action || 'ALLOW',
    exempt_bot_challenge: Boolean(r.exempt_bot_challenge),
    rate_limit_rpm: r.action === 'RATE_LIMIT' ? (r.rate_limit_rpm ?? 60) : 0,
    priority: r.priority ?? 100,
  }))
}

export default function AiCrawlTab({
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
  const canManage = hasPermission(permissions, 'ai_crawl.manage')
  const [form] = Form.useForm<PolicyFormValues>()
  const labyrinthEnabled = Form.useWatch('labyrinth_enabled', form) ?? false
  const rulesWatch = Form.useWatch('rules', form) ?? []

  const policyQuery = useQuery({
    queryKey: ['ai-crawl-policy', appId],
    queryFn: () => aiCrawlApi.getPolicy(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      default_ai_action: policy.default_ai_action ?? 'ALLOW',
      content_signal: policy.content_signal ?? '',
      verify_web_bot_auth: policy.verify_web_bot_auth ?? true,
      labyrinth_enabled: policy.labyrinth_enabled ?? false,
      labyrinth_inject_links: policy.labyrinth_inject_links ?? false,
      labyrinth_max_depth:
        policy.labyrinth_max_depth ?? AI_CRAWL_LIMITS.defaultLabyrinthMaxDepth,
      labyrinth_max_concurrency:
        policy.labyrinth_max_concurrency ??
        AI_CRAWL_LIMITS.defaultLabyrinthMaxConcurrency,
      labyrinth_delay_ms:
        policy.labyrinth_delay_ms ?? AI_CRAWL_LIMITS.defaultLabyrinthDelayMs,
      http_402_message: policy.http_402?.message ?? '',
      http_402_price_hint: policy.http_402?.price_hint ?? '',
      http_402_contact_url: policy.http_402?.contact_url ?? '',
      http_402_receipt_header: policy.http_402?.receipt_header ?? '',
      rules: (policy.rules ?? []).map((r, idx) => ({
        id: r.id || `rule-${idx + 1}`,
        name: r.name ?? '',
        category: r.category || 'UNKNOWN_BOT',
        agent_id: r.agent_id ?? '',
        ua_patterns: r.ua_patterns ?? [],
        require_verified_sig: Boolean(r.require_verified_sig),
        action: r.action || 'ALLOW',
        exempt_bot_challenge: Boolean(r.exempt_bot_challenge),
        rate_limit_rpm: r.rate_limit_rpm ?? 0,
        priority: r.priority ?? 100,
      })),
      reason: '',
    })
  }, [policy, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ['ai-crawl-policy', appId],
    })

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      aiCrawlApi.updatePolicy(appId, {
        mode: values.mode,
        expected_version: policy?.version ?? 0,
        default_ai_action: values.default_ai_action,
        content_signal: (values.content_signal ?? '').trim(),
        verify_web_bot_auth: Boolean(values.verify_web_bot_auth),
        labyrinth_enabled: Boolean(values.labyrinth_enabled),
        labyrinth_inject_links: Boolean(values.labyrinth_inject_links),
        labyrinth_max_depth:
          values.labyrinth_max_depth ?? AI_CRAWL_LIMITS.defaultLabyrinthMaxDepth,
        labyrinth_max_concurrency:
          values.labyrinth_max_concurrency ??
          AI_CRAWL_LIMITS.defaultLabyrinthMaxConcurrency,
        labyrinth_delay_ms:
          values.labyrinth_delay_ms ?? AI_CRAWL_LIMITS.defaultLabyrinthDelayMs,
        http_402: {
          message: (values.http_402_message ?? '').trim(),
          price_hint: (values.http_402_price_hint ?? '').trim(),
          contact_url: (values.http_402_contact_url ?? '').trim(),
          receipt_header: (values.http_402_receipt_header ?? '').trim(),
        },
        rules: toRules(values.rules),
        reason: values.reason.trim(),
      }),
    onSuccess: () => {
      message.success('草稿已保存；发布并获节点回执后才会生效')
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
          const name = mapAiCrawlFieldErrorPath(d.field)
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
        message="加载 AI 爬虫治理策略失败"
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
              <Link to="/ai-crawl">
                <Button type="link" size="small" style={{ paddingInline: 0 }}>
                  管理爬虫公钥目录
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
            <StatusTag value={summary.state} map={AI_CRAWL_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={AI_CRAWL_MODE_META} />
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
            description={`草稿 v${summary.draft_version} 与已生效版本 v${summary.published_version} 存在差异；保存草稿不等于线上生效，需经配置发布并获节点回执后才生效。`}
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
              title={`已生效：${AI_CRAWL_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="AI 爬虫治理策略已随最近成功发布快照下发至网关节点运行。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 14 }}
            title="尚未配置 AI 爬虫治理策略，当前维持默认行为"
            description="支持 RFC 9421 Web Bot Auth 验签、Content-Signal 声明、离线 AI 迷宫拖延与 HTTP 402 付费告知。"
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="AI 爬虫治理与迷宫配置"
        extra={
          <Space size={6}>
            <Tag color="purple" style={{ marginInlineEnd: 0 }}>
              RFC 9421 Web Bot Auth
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>离线迷宫 · 零外部依赖</Tag>
          </Space>
        }
      >
        <InlineNote tooltip="保留命名空间 /_wdsp/labyrinth/v1/ 在网关本地直接应答，绝不反向代理至源站；IP/URL 白名单与 L7 allow 不会绕过 AI 爬虫治理与强制处置。">
          AI 爬虫治理在 Bot 挑战前执行，白名单与 L7 allow
          不绕过；仅当规则显式开启「豁免 Bot 挑战」且 Web Bot Auth
          验签通过时才跳过 JS 挑战（仍受 JWT / API / WAF 约束）。
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
            description="选择当前应用对 AI 爬虫与自动化抓取流量的识别及处置强度。"
          />
          <Form.Item name="mode" style={{ marginBottom: 8 }}>
            <ModeCardGroup options={MODE_CARD_OPTIONS} disabled={!canManage} />
          </Form.Item>

          <SectionHeader
            spaced
            title="基础声明与 Web Bot Auth 验签"
            description="配置未命中细分规则时的默认 AI 爬虫处置动作、Content-Signal 响应头以及 RFC 9421 签名核验开关。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={8}>
              <Form.Item
                name="default_ai_action"
                label="默认 AI 爬虫动作"
                rules={[{ required: true, message: '请选择默认动作' }]}
              >
                <Select options={ACTION_OPTIONS} />
              </Form.Item>
            </Col>
            <Col xs={24} md={10}>
              <Form.Item
                name="content_signal"
                label="Content-Signal 响应头"
                extra={
                  canManage ? (
                    <Space size={4} wrap style={{ marginTop: 4 }}>
                      {CONTENT_SIGNAL_PRESETS.map((preset) => (
                        <Button
                          key={preset.value}
                          size="small"
                          type="link"
                          style={{ paddingInline: 4, height: 'auto', fontSize: 12 }}
                          onClick={() =>
                            form.setFieldValue('content_signal', preset.value)
                          }
                        >
                          {preset.label}
                        </Button>
                      ))}
                    </Space>
                  ) : (
                    '随响应下发 Content-Signal 头，声明允许搜索/训练/AI 输入边界'
                  )
                }
              >
                <Input
                  placeholder={AI_CRAWL_LIMITS.defaultContentSignal}
                  autoComplete="off"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={6}>
              <Form.Item
                name="verify_web_bot_auth"
                label="Web Bot Auth 签名核验"
                valuePropName="checked"
                extra="按已启用的爬虫公钥目录纯本地校验 RFC 9421 签名"
              >
                <Switch checkedChildren="开启" unCheckedChildren="关闭" />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="离线 AI 迷宫（AI Labyrinth Tarpit）"
            badge={
              <Tag color="purple" style={{ marginInlineEnd: 0 }}>
                保留路径 {AI_CRAWL_LIMITS.reservedLabyrinthNamespace}
              </Tag>
            }
            description="基于 HMAC 签名路径与本地确定性 HTML 合成器消耗恶意抓取算力，内置有界并发信号量防止拖垮网关协程；密钥材料由管理端托管加密存储，不回显前端。"
          />
          <Row gutter={[16, 12]} style={{ marginBottom: 12 }}>
            <Col xs={24} md={12}>
              <div
                className={`jz-detail-switch-tile${labyrinthEnabled ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="labyrinth_enabled"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>启用离线 AI 迷宫</span>
                      <span className="jz-detail-switch-desc">
                        开启后 TARPIT 动作及命中保留迷宫路径的请求将进入受控拖延响应
                      </span>
                    </>
                  }
                >
                  <Switch />
                </Form.Item>
              </div>
            </Col>
            <Col xs={24} md={12}>
              <div className="jz-detail-switch-tile">
                <Form.Item
                  name="labyrinth_inject_links"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>向可疑爬虫注入不可见陷阱链接</span>
                      <span className="jz-detail-switch-desc">
                        对未验证可疑爬虫的 HTML GET 响应在 &lt;/body&gt; 前注入 rel=&quot;nofollow&quot; 隐藏入口
                      </span>
                    </>
                  }
                >
                  <Switch disabled={!canManage || !labyrinthEnabled} />
                </Form.Item>
              </div>
            </Col>
          </Row>
          <Row gutter={[16, 0]}>
            <Col xs={24} sm={8}>
              <Form.Item
                name="labyrinth_max_depth"
                label="迷宫最大深度"
                rules={[
                  {
                    type: 'number',
                    min: AI_CRAWL_LIMITS.minLabyrinthMaxDepth,
                    max: AI_CRAWL_LIMITS.maxLabyrinthMaxDepth,
                    message: `须在 ${AI_CRAWL_LIMITS.minLabyrinthMaxDepth}–${AI_CRAWL_LIMITS.maxLabyrinthMaxDepth} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={AI_CRAWL_LIMITS.minLabyrinthMaxDepth}
                  max={AI_CRAWL_LIMITS.maxLabyrinthMaxDepth}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="labyrinth_max_concurrency"
                label="并发信号量上限"
                rules={[
                  {
                    type: 'number',
                    min: AI_CRAWL_LIMITS.minLabyrinthMaxConcurrency,
                    max: AI_CRAWL_LIMITS.maxLabyrinthMaxConcurrency,
                    message: `须在 ${AI_CRAWL_LIMITS.minLabyrinthMaxConcurrency}–${AI_CRAWL_LIMITS.maxLabyrinthMaxConcurrency} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={AI_CRAWL_LIMITS.minLabyrinthMaxConcurrency}
                  max={AI_CRAWL_LIMITS.maxLabyrinthMaxConcurrency}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} sm={8}>
              <Form.Item
                name="labyrinth_delay_ms"
                label="单跳拖延时长（ms）"
                rules={[
                  {
                    type: 'number',
                    min: AI_CRAWL_LIMITS.minLabyrinthDelayMs,
                    max: AI_CRAWL_LIMITS.maxLabyrinthDelayMs,
                    message: `须在 ${AI_CRAWL_LIMITS.minLabyrinthDelayMs}–${AI_CRAWL_LIMITS.maxLabyrinthDelayMs} ms 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={AI_CRAWL_LIMITS.minLabyrinthDelayMs}
                  max={AI_CRAWL_LIMITS.maxLabyrinthDelayMs}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="HTTP 402 付费抓取告知配置"
            description="当默认动作或命中规则为 HTTP 402 时，按客户端 Accept 头返回结构化 JSON 或 HTML 付费/授权指引。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item name="http_402_message" label="402 提示说明">
                <Input.TextArea
                  rows={2}
                  placeholder="如：商业 AI 数据抓取需先获取授权许可"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Row gutter={[12, 0]}>
                <Col xs={24} sm={12}>
                  <Form.Item name="http_402_price_hint" label="计费提示">
                    <Input
                      placeholder="如 0.001 USD / request"
                      autoComplete="off"
                    />
                  </Form.Item>
                </Col>
                <Col xs={24} sm={12}>
                  <Form.Item
                    name="http_402_receipt_header"
                    label="付费凭据请求头"
                  >
                    <Input
                      placeholder="如 X-Crawl-Receipt"
                      autoComplete="off"
                    />
                  </Form.Item>
                </Col>
                <Col xs={24}>
                  <Form.Item name="http_402_contact_url" label="授权联系地址">
                    <Input
                      placeholder="如 https://example.com/licensing"
                      autoComplete="off"
                    />
                  </Form.Item>
                </Col>
              </Row>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title={`优先级治理规则（最多 ${AI_CRAWL_LIMITS.maxRules} 条）`}
            badge={
              <Tag style={{ marginInlineEnd: 0 }}>
                {rulesWatch.length} / {AI_CRAWL_LIMITS.maxRules}
              </Tag>
            }
            description="规则按优先级（数值越小越优先）顺序匹配，首条命中即生效；未命中任何规则时执行默认 AI 爬虫动作。"
          />
          <Form.List name="rules">
            {(fields, { add, remove }) => (
              <>
                {fields.length === 0 && (
                  <div
                    className="jz-detail-rule-box"
                    style={{ marginBottom: 12 }}
                  >
                    <div className="jz-detail-rule-empty">
                      暂无自定义治理规则；未命中规则的 AI 爬虫流量将按上方「默认
                      AI 爬虫动作」处理
                    </div>
                  </div>
                )}
                {fields.map((field) => {
                  const curRule = rulesWatch?.[field.name]
                  const catMeta =
                    AI_CRAWL_CATEGORY_META[curRule?.category ?? '']
                  const actMeta = AI_CRAWL_ACTION_META[curRule?.action ?? '']
                  return (
                    <div key={field.key} className="jz-detail-subcard">
                      <div className="jz-detail-subcard-head">
                        <div className="jz-detail-subcard-title">
                          <span className="jz-detail-subcard-index">
                            #{field.name + 1}
                          </span>
                          <Typography.Text strong style={{ fontSize: 13 }}>
                            {curRule?.name?.trim() || `治理规则 #${field.name + 1}`}
                          </Typography.Text>
                          <Tag style={{ marginInlineEnd: 0 }}>
                            优先级 {curRule?.priority ?? 100}
                          </Tag>
                          {catMeta && (
                            <Tag
                              color={catMeta.color}
                              style={{ marginInlineEnd: 0 }}
                            >
                              {catMeta.label}
                            </Tag>
                          )}
                          {actMeta && (
                            <Tag
                              color={actMeta.color}
                              style={{ marginInlineEnd: 0 }}
                            >
                              {actMeta.label}
                            </Tag>
                          )}
                        </div>
                        <Tooltip title="删除此规则" placement="left">
                          <Button
                            type="text"
                            danger
                            size="small"
                            icon={<MinusCircleOutlined />}
                            aria-label={`删除规则 #${field.name + 1}`}
                            onClick={() => remove(field.name)}
                          />
                        </Tooltip>
                      </div>

                      <div className="jz-detail-subcard-body">
                        <Form.Item name={[field.name, 'id']} hidden>
                          <Input />
                        </Form.Item>
                        <Row gutter={[16, 0]}>
                          <Col xs={24} md={8}>
                            <Form.Item
                              name={[field.name, 'name']}
                              label="规则名称"
                              rules={[
                                {
                                  required: true,
                                  whitespace: true,
                                  message: '请输入规则名称',
                                },
                                {
                                  max: AI_CRAWL_LIMITS.maxRuleNameLen,
                                  message: `规则名称不能超过 ${AI_CRAWL_LIMITS.maxRuleNameLen} 字符`,
                                },
                              ]}
                            >
                              <Input
                                placeholder="如：允许已验签搜索引擎"
                                autoComplete="off"
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} sm={12} md={6}>
                            <Form.Item
                              name={[field.name, 'category']}
                              label="爬虫类别"
                              rules={[
                                { required: true, message: '请选择爬虫类别' },
                              ]}
                            >
                              <Select options={CATEGORY_OPTIONS} />
                            </Form.Item>
                          </Col>
                          <Col xs={24} sm={12} md={6}>
                            <Form.Item
                              name={[field.name, 'action']}
                              label="处置动作"
                              rules={[
                                { required: true, message: '请选择处置动作' },
                              ]}
                            >
                              <Select options={ACTION_OPTIONS} />
                            </Form.Item>
                          </Col>
                          <Col xs={24} sm={12} md={4}>
                            <Form.Item
                              name={[field.name, 'priority']}
                              label="优先级"
                              initialValue={100}
                              rules={[
                                {
                                  type: 'number',
                                  min: AI_CRAWL_LIMITS.minRulePriority,
                                  max: AI_CRAWL_LIMITS.maxRulePriority,
                                  message: `须在 ${AI_CRAWL_LIMITS.minRulePriority}–${AI_CRAWL_LIMITS.maxRulePriority} 之间`,
                                },
                              ]}
                            >
                              <InputNumber
                                min={AI_CRAWL_LIMITS.minRulePriority}
                                max={AI_CRAWL_LIMITS.maxRulePriority}
                                precision={0}
                                style={{ width: '100%' }}
                              />
                            </Form.Item>
                          </Col>
                        </Row>

                        <Row gutter={[16, 0]}>
                          <Col xs={24} md={8}>
                            <Form.Item
                              name={[field.name, 'agent_id']}
                              label="指定 Agent / Slug（可选）"
                            >
                              <Input
                                placeholder="如 openai-searchbot 或 https://chatgpt.com"
                                autoComplete="off"
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={10}>
                            <Form.Item
                              name={[field.name, 'ua_patterns']}
                              label="User-Agent 匹配特征（可选）"
                            >
                              <Select
                                mode="tags"
                                open={false}
                                placeholder="输入关键词后回车，如 GPTBot、ClaudeBot"
                                tokenSeparators={[',']}
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={6}>
                            <Form.Item
                              noStyle
                              shouldUpdate={(
                                prev: PolicyFormValues,
                                cur: PolicyFormValues,
                              ) =>
                                prev.rules?.[field.name]?.action !==
                                cur.rules?.[field.name]?.action
                              }
                            >
                              {({ getFieldValue }) =>
                                getFieldValue([
                                  'rules',
                                  field.name,
                                  'action',
                                ]) === 'RATE_LIMIT' ? (
                                  <Form.Item
                                    name={[field.name, 'rate_limit_rpm']}
                                    label="限速阈值（次/分）"
                                    initialValue={60}
                                    rules={[
                                      {
                                        required: true,
                                        message: '请填写每分钟限速值',
                                      },
                                    ]}
                                  >
                                    <InputNumber
                                      min={1}
                                      max={AI_CRAWL_LIMITS.maxRateLimitRPM}
                                      precision={0}
                                      style={{ width: '100%' }}
                                    />
                                  </Form.Item>
                                ) : null
                              }
                            </Form.Item>
                          </Col>
                        </Row>

                        <Row gutter={[16, 0]}>
                          <Col xs={24} sm={12}>
                            <Form.Item
                              name={[field.name, 'require_verified_sig']}
                              label="仅匹配 Web Bot Auth 验签通过"
                              valuePropName="checked"
                              initialValue={false}
                            >
                              <Switch
                                checkedChildren="必须验签"
                                unCheckedChildren="不限"
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} sm={12}>
                            <Form.Item
                              name={[field.name, 'exempt_bot_challenge']}
                              label="豁免 Bot JS 挑战"
                              valuePropName="checked"
                              initialValue={false}
                              extra="仅在 Web Bot Auth 验签通过时跳过 Bot JS 挑战，不跳过 JWT/API/WAF"
                            >
                              <Switch
                                checkedChildren="豁免"
                                unCheckedChildren="不豁免"
                              />
                            </Form.Item>
                          </Col>
                        </Row>
                      </div>
                    </div>
                  )
                })}
                <Button
                  block
                  type="dashed"
                  icon={<PlusOutlined />}
                  disabled={fields.length >= AI_CRAWL_LIMITS.maxRules}
                  onClick={() =>
                    add({
                      id: `rule-${Date.now()}-${fields.length + 1}`,
                      name: '',
                      category: 'AI_TRAINING',
                      agent_id: '',
                      ua_patterns: [],
                      require_verified_sig: false,
                      action: 'TARPIT',
                      exempt_bot_challenge: false,
                      rate_limit_rpm: 60,
                      priority: (fields.length + 1) * 10,
                    })
                  }
                >
                  添加治理规则
                </Button>
              </>
            )}
          </Form.List>

          {canManage && (
            <div className="jz-detail-audit-submit-box">
              <Form.Item
                name="reason"
                label="变更理由"
                style={{ marginBottom: 10, maxWidth: 760 }}
                extra="必填，进入操作审计与不可变版本记录"
                rules={[
                  { required: true, message: '请填写变更理由' },
                  {
                    max: AI_CRAWL_LIMITS.maxReasonLen,
                    message: `变更理由不能超过 ${AI_CRAWL_LIMITS.maxReasonLen} 字符`,
                  },
                ]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="说明本次变更原因，如：开启 AI 训练爬虫迷宫拖延与 Content-Signal 声明"
                />
              </Form.Item>
              <div className="jz-detail-audit-submit-actions">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  <RobotOutlined style={{ marginRight: 6 }} />
                  <SafetyCertificateOutlined style={{ marginRight: 4 }} />
                  草稿保存后须前往「配置发布」下发至网关节点方可生效；迷宫密钥由服务端自动生成并加密托管。
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
