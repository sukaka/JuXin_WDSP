import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Collapse,
  Descriptions,
  Form,
  Input,
  InputNumber,
  List,
  Radio,
  Select,
  Space,
  Spin,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  BOT_POLICY_LIMITS,
  BOT_RESERVED_NAMESPACE,
  botPolicyApi,
} from '../../../api/botPolicy'
import type {
  BotPolicyMode,
  BotPreflightResult,
  BotReservationState,
  BotSelector,
  BotSignalRule,
} from '../../../api/botPolicy'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  BOT_CHECK_NAME_LABELS,
  BOT_CHECK_STATUS_META,
  BOT_CONFLICT_TYPE_LABELS,
  BOT_METRIC_OPTIONS,
  BOT_METRIC_SPECS,
  BOT_MODE_META,
  BOT_NODE_SYNC_META,
  BOT_RESERVATION_META,
  BOT_STATE_META,
  mapBotFieldErrorPath,
} from '../../../utils/botPolicy'
import BotChallengePreview from './BotChallengePreview'

const MODE_OPTIONS = [
  { value: 'OFF', label: '关闭（不观测、不挑战，不改变既有流量）' },
  { value: 'OBSERVE', label: '观察（信号判定只记录，不实断）' },
  { value: 'PROTECT', label: '强制挑战（合格浏览器导航签发 JS 挑战）' },
]

const RESERVATION_OPTIONS = [
  { value: 'ENABLED', label: '启用保留路由' },
  { value: 'RESERVED_TOMBSTONE', label: '关闭但保留墓碑（404）' },
  { value: 'RELEASED', label: '解除保留' },
]

/** 表单值：选择器二选一折叠为 match_type+path；信号规则参数按指标拍平 */
interface SelectorFormValue {
  match_type: 'exact' | 'prefix'
  path: string
}

interface RuleFormValue {
  id: string
  metric: string
  family?: string
  method?: string
  class?: string
  tls_field?: string
  tls_equals?: string
  window_seconds: number
  weight: number
  threshold: number
}

interface PolicyFormValues {
  mode: BotPolicyMode
  selectors: SelectorFormValue[]
  rules: RuleFormValue[]
  min_independent_groups: number
  nonce_ttl_seconds: number
  clearance_ttl_seconds: number
  difficulty: number
  max_attempts: number
  key_ref?: string
  reservation_state: BotReservationState
  reason: string
}

const DEFAULT_VALUES: Partial<PolicyFormValues> = {
  mode: 'OFF',
  selectors: [],
  rules: [],
  min_independent_groups: BOT_POLICY_LIMITS.minGroups,
  nonce_ttl_seconds: BOT_POLICY_LIMITS.defaultNonceTTL,
  clearance_ttl_seconds: BOT_POLICY_LIMITS.defaultClearanceTTL,
  difficulty: BOT_POLICY_LIMITS.defaultDifficulty,
  max_attempts: BOT_POLICY_LIMITS.defaultMaxAttempts,
  key_ref: '',
  reservation_state: 'RELEASED',
  reason: '',
}

function toSelectors(values: SelectorFormValue[]): BotSelector[] {
  return (values ?? []).map((s) => ({
    path_exact: s.match_type === 'exact' ? (s.path ?? '') : undefined,
    path_prefix: s.match_type === 'prefix' ? (s.path ?? '') : undefined,
  }))
}

/** 信号规则转换：group 由指标白名单推导（不信任表单携带），params 按指标允许键收集 */
function toRules(values: RuleFormValue[]): BotSignalRule[] {
  return (values ?? []).map((r) => {
    const spec = BOT_METRIC_SPECS[r.metric]
    const params: Record<string, string> = {}
    for (const p of spec?.params ?? []) {
      const v =
        p.key === 'family'
          ? r.family
          : p.key === 'method'
            ? r.method
            : p.key === 'class'
              ? r.class
              : p.key === 'field'
                ? r.tls_field
                : p.key === 'equals'
                  ? r.tls_equals
                  : undefined
      if (v) params[p.key] = v
    }
    return {
      id: (r.id ?? '').trim(),
      group: spec?.group ?? '',
      metric: r.metric ?? '',
      params,
      window_seconds: r.window_seconds ?? BOT_POLICY_LIMITS.defaultWindowSeconds,
      weight: r.weight ?? 1,
      threshold: spec?.threshold === 'none' ? 0 : (r.threshold ?? 0),
    }
  })
}

function buildDraftBody(values: PolicyFormValues) {
  return {
    mode: values.mode,
    selectors: toSelectors(values.selectors),
    signal_rules: {
      min_independent_groups: values.min_independent_groups,
      require_behavior_group: true,
      rules: toRules(values.rules),
    },
    challenge: {
      type: 'JS',
      nonce_ttl_seconds: values.nonce_ttl_seconds,
      clearance_ttl_seconds: values.clearance_ttl_seconds,
      difficulty: values.difficulty,
      max_attempts: values.max_attempts,
      key_ref: values.key_ref?.trim() ?? '',
    },
    route_reservation: {
      state: values.reservation_state,
      namespace: BOT_RESERVED_NAMESPACE,
    },
  }
}

export default function BotPolicyTab({
  appId,
  appCode,
}: {
  appId: string
  appCode: string
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canEdit = hasPermission(permissions, 'bot_policy.edit')
  const [form] = Form.useForm<PolicyFormValues>()
  const mode = Form.useWatch('mode', form) ?? 'OFF'
  const rulesWatch = Form.useWatch('rules', form) ?? []
  const [preflight, setPreflight] = useState<BotPreflightResult | null>(null)

  const policyQuery = useQuery({
    queryKey: ['bot-policy', appId],
    queryFn: () => botPolicyApi.get(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  // GET 回填（含保存后重新拉取的新 version）
  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      selectors: (policy.selectors ?? []).map((s) => ({
        match_type: s.path_exact ? ('exact' as const) : ('prefix' as const),
        path: s.path_exact || s.path_prefix || '',
      })),
      rules: (policy.signal_rules?.rules ?? []).map((r) => ({
        id: r.id,
        metric: r.metric,
        family: r.params?.family,
        method: r.params?.method,
        class: r.params?.class,
        tls_field: r.params?.field,
        tls_equals: r.params?.equals,
        window_seconds: r.window_seconds,
        weight: r.weight,
        threshold: r.threshold,
      })),
      min_independent_groups:
        policy.signal_rules?.min_independent_groups ??
        BOT_POLICY_LIMITS.minGroups,
      nonce_ttl_seconds: policy.challenge?.nonce_ttl_seconds,
      clearance_ttl_seconds: policy.challenge?.clearance_ttl_seconds,
      difficulty: policy.challenge?.difficulty,
      max_attempts: policy.challenge?.max_attempts,
      key_ref: policy.challenge?.key_ref ?? '',
      reservation_state: policy.route_reservation?.state ?? 'RELEASED',
      reason: '',
    })
  }, [policy, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ['bot-policy', appId] })

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      botPolicyApi.update(appId, {
        ...buildDraftBody(values),
        expected_version: policy?.version ?? 0,
        reason: values.reason.trim(),
      }),
    onSuccess: () => {
      // 保存草稿≠线上生效：发布并获节点回执后才生效（任务书 §6/§8）
      message.success('草稿已保存；发布并获节点回执后才会生效')
      setPreflight(null)
      invalidate()
    },
    onError: (e) => {
      if (
        e instanceof ApiError &&
        (e.status === 409 || e.code === 'RESOURCE_CONFLICT')
      ) {
        message.warning('策略已被其他人修改，请刷新后重试')
        invalidate()
        return
      }
      if (e instanceof ApiError && Array.isArray(e.details)) {
        // 后端字段级校验错误（details = [{field, message}]），回显到对应表单项
        const details = e.details as { field?: string; message?: string }[]
        const fields: { name: (string | number)[]; errors: string[] }[] = []
        const unmapped: string[] = []
        for (const d of details) {
          if (!d.field) continue
          const errMsg = d.message ?? '取值不合法'
          const name = mapBotFieldErrorPath(d.field)
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

  const preflightMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      botPolicyApi.preflight(appId, buildDraftBody(values)),
    onSuccess: (data) => setPreflight(data),
    onError: (e) =>
      message.error(e instanceof ApiError ? e.message : '预检失败'),
  })

  const runPreflight = async () => {
    try {
      // 预检不需要变更理由，仅校验策略字段
      const values = await form.validateFields([
        'mode',
        'selectors',
        'rules',
        'min_independent_groups',
        'nonce_ttl_seconds',
        'clearance_ttl_seconds',
        'difficulty',
        'max_attempts',
        'key_ref',
        'reservation_state',
      ])
      setPreflight(null)
      preflightMutation.mutate({ ...form.getFieldsValue(true), ...values })
    } catch {
      message.warning('请先修正表单中的校验错误再执行预检')
    }
  }

  if (policyQuery.isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
        <Spin />
      </div>
    )
  }

  if (policyQuery.isError || !policy || !summary) {
    return (
      <QueryErrorAlert error={policyQuery.error} message="加载 Bot 策略失败" />
    )
  }

  const nodes = summary.nodes ?? []
  const partialNodes =
    summary.published.found && nodes.some((n) => !n.effective)
  const publishMissing = summary.state === 'DRAFT_PENDING'

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card title="策略状态">
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用范围">{appCode}</Descriptions.Item>
          <Descriptions.Item label="配置状态">
            <StatusTag value={summary.state} map={BOT_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="草稿模式">
            <StatusTag value={policy.mode} map={BOT_MODE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="草稿版本">
            {summary.draft_version > 0 ? `v${summary.draft_version}` : '无草稿'}
          </Descriptions.Item>
          <Descriptions.Item label="已发布">
            {summary.published.found
              ? `发布批次 #${summary.published.version_no} · 策略 v${summary.published.policy_version}`
              : '未成功发布'}
          </Descriptions.Item>
          <Descriptions.Item label="保留路由">
            <StatusTag
              value={policy.route_reservation?.state ?? ''}
              map={BOT_RESERVATION_META}
            />
          </Descriptions.Item>
          <Descriptions.Item label="最近更新">
            {policy.updated_at
              ? `${formatDateTime(policy.updated_at)}${policy.updated_by ? ` · ${policy.updated_by}` : ''}`
              : '-'}
          </Descriptions.Item>
        </Descriptions>

        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 12 }}
            message="尚未配置 Bot 策略，当前不观测、不挑战"
            description="默认 OFF 不改变既有流量；建议先以 OBSERVE 采集基线，再由操作者明确启用 PROTECT。"
          />
        )}
        {publishMissing && (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 12 }}
            message="草稿已保存，尚未生效"
            description={
              summary.published.found
                ? `草稿 v${summary.draft_version} 与已发布版本 v${summary.published.policy_version} 存在差异；保存草稿不等于线上生效，发布失败时旧版本继续运行（不回退草稿）。`
                : `草稿 v${summary.draft_version} 尚未随任何成功发布下发；保存草稿不等于线上生效。`
            }
            action={
              <Space>
                {canEdit && (
                  <Button size="small" onClick={() => void runPreflight()}>
                    重新预检
                  </Button>
                )}
                <Link to="/config-publish">前往配置发布</Link>
              </Space>
            }
          />
        )}
        {summary.state === 'PUBLISHED' && (
          <Alert
            type="success"
            showIcon
            style={{ marginTop: 12 }}
            message={`已发布：策略 v${summary.published.policy_version}（批次 #${summary.published.version_no}）`}
            description="节点级生效以各节点同步回执为准；部分节点未同步到新批次时该节点仍运行旧版本，不能计为保护成功。"
          />
        )}
        {partialNodes && (
          <Alert
            type="warning"
            showIcon
            style={{ marginTop: 12 }}
            message="部分节点未生效"
            description="存在未同步到最新成功发布批次的节点，这些节点仍运行旧配置；请前往配置发布查看同步结果并重试。"
            action={<Link to="/config-publish">前往配置发布</Link>}
          />
        )}

        {nodes.length > 0 && (
          <List
            size="small"
            style={{ marginTop: 12 }}
            header={<Typography.Text strong>节点同步状态</Typography.Text>}
            dataSource={nodes}
            renderItem={(n) => (
              <List.Item>
                <Space wrap>
                  <Typography.Text>{n.node_name}</Typography.Text>
                  <StatusTag
                    value={n.last_sync_result || 'UNKNOWN'}
                    map={BOT_NODE_SYNC_META}
                  />
                  {n.effective ? (
                    <Tag color="success">已生效最新批次</Tag>
                  ) : (
                    <Tag color="warning">未同步到最新批次</Tag>
                  )}
                </Space>
              </List.Item>
            )}
          />
        )}
      </Card>

      <Card
        title="策略配置"
        extra={
          canEdit && (
            <Space>
              <Button
                loading={preflightMutation.isPending}
                onClick={() => void runPreflight()}
              >
                发布预检
              </Button>
              <Button
                type="primary"
                loading={saveMutation.isPending}
                onClick={() => form.submit()}
              >
                保存草稿
              </Button>
            </Space>
          )
        }
      >
        <Alert
          type="info"
          showIcon
          style={{ marginBottom: 16 }}
          message="挑战仅覆盖下方选择器路径上的 HTTPS GET 浏览器文档导航；HEAD/POST/JSON API/上传/WebSocket/gRPC 不返回挑战页。"
          description="提出挑战需至少 2 个独立信号组同时满足且至少 1 个行为观测组；UA/TLS 声明为可伪造弱信号，不能单独构成挑战依据。挑战通过仅放行 Bot 步骤，不绕过 JWT、API 动态防护与 WAF。"
        />
        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          initialValues={DEFAULT_VALUES}
          disabled={!canEdit}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="mode"
            label="策略模式"
            extra={
              mode === 'PROTECT' ? (
                <Typography.Text type="warning">
                  强制挑战要求共享状态存储（Valkey）已配置、签名密钥已就绪且目标节点无已知同步失败，否则发布将被拒绝（防全站
                  fail-closed 503）
                </Typography.Text>
              ) : undefined
            }
          >
            <Radio.Group options={MODE_OPTIONS} />
          </Form.Item>

          <Typography.Title level={5} style={{ marginTop: 0 }}>
            挑战适用范围（选择器）
          </Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            仅 GET 浏览器文档导航；不同选择器之间为或（OR）关系；路径前缀按完整路径段匹配（/docs
            匹配 /docs 与 /docs/a，不匹配
            /docsx）；禁止正则、百分号编码、全站通配与保留命名空间
            {BOT_RESERVED_NAMESPACE}。
            {mode !== 'OFF' && '非关闭模式下至少需要一条选择器。'}
          </Typography.Paragraph>
          <Form.List name="selectors">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Space
                    key={field.key}
                    style={{ display: 'flex', marginBottom: 8 }}
                    align="baseline"
                    wrap
                  >
                    <Form.Item
                      name={[field.name, 'match_type']}
                      style={{ marginBottom: 0 }}
                      initialValue="prefix"
                    >
                      <Radio.Group
                        options={[
                          { value: 'exact', label: '精确路径' },
                          { value: 'prefix', label: '路径前缀' },
                        ]}
                        optionType="button"
                        buttonStyle="solid"
                        size="small"
                      />
                    </Form.Item>
                    <Form.Item
                      name={[field.name, 'path']}
                      style={{ marginBottom: 0 }}
                      rules={[
                        { required: mode !== 'OFF', message: '请输入路径' },
                        {
                          validator: (_, v: string) => {
                            if (!v) return Promise.resolve()
                            if (!v.startsWith('/'))
                              return Promise.reject(
                                new Error('路径必须以 / 开头'),
                              )
                            if (v.includes('?') || v.includes('#'))
                              return Promise.reject(
                                new Error('路径不得包含 query 或 fragment'),
                              )
                            if (v.includes('%'))
                              return Promise.reject(
                                new Error('路径按解码后形式配置，不得包含百分号编码'),
                              )
                            return Promise.resolve()
                          },
                        },
                      ]}
                    >
                      <Input
                        placeholder="如 /docs 或 /account/login"
                        style={{ width: 280 }}
                        autoComplete="off"
                        maxLength={BOT_POLICY_LIMITS.maxSelectorPathLen}
                      />
                    </Form.Item>
                    <Tooltip title="删除此选择器">
                      <Button
                        type="text"
                        danger
                        icon={<MinusCircleOutlined />}
                        aria-label="删除此选择器"
                        onClick={() => remove(field.name)}
                      />
                    </Tooltip>
                  </Space>
                ))}
                <Button
                  block
                  type="dashed"
                  icon={<PlusOutlined />}
                  disabled={fields.length >= BOT_POLICY_LIMITS.maxSelectors}
                  onClick={() => add({ match_type: 'prefix', path: '' })}
                >
                  添加选择器
                </Button>
              </>
            )}
          </Form.List>

          <Typography.Title level={5} style={{ marginTop: 24 }}>
            信号规则（提出挑战的组合条件）
          </Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            组满足 = 组内已触发规则权重和 ≥1；提出挑战需满足的独立信号组数（当前
            <Typography.Text code>最少独立信号组数</Typography.Text>
            ）且至少 1 个行为组；同源计数派生指标不重复计权。
            {mode !== 'OFF' && '非关闭模式下至少需要一条信号规则。'}
          </Typography.Paragraph>
          <Form.Item
            name="min_independent_groups"
            label="最少独立信号组数"
            style={{ maxWidth: 220 }}
            rules={[{ required: true, message: '请输入最少独立信号组数' }]}
          >
            <InputNumber
              min={BOT_POLICY_LIMITS.minGroups}
              max={BOT_POLICY_LIMITS.maxGroups}
              precision={0}
              style={{ width: '100%' }}
            />
          </Form.Item>
          <Form.List name="rules">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => {
                  const metric: string | undefined =
                    rulesWatch?.[field.name]?.metric
                  const spec = metric ? BOT_METRIC_SPECS[metric] : undefined
                  return (
                    <Card
                      key={field.key}
                      size="small"
                      style={{ marginBottom: 12 }}
                      title={`信号规则 #${field.name + 1}`}
                      extra={
                        <Tooltip title="删除此规则">
                          <Button
                            type="text"
                            danger
                            icon={<MinusCircleOutlined />}
                            aria-label={`删除信号规则 #${field.name + 1}`}
                            onClick={() => remove(field.name)}
                          />
                        </Tooltip>
                      }
                    >
                      <Space size="middle" wrap style={{ display: 'flex' }}>
                        <Form.Item
                          name={[field.name, 'id']}
                          label="规则 ID"
                          style={{ width: 220 }}
                          rules={[
                            {
                              required: mode !== 'OFF',
                              message: '请输入规则 ID',
                            },
                            {
                              pattern: /^[a-z][a-z0-9_]{0,63}$/,
                              message:
                                '小写字母开头的小写字母/数字/下划线（1~64 字符）',
                            },
                          ]}
                        >
                          <Input
                            placeholder="如 high_4xx_ratio"
                            autoComplete="off"
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'metric']}
                          label="信号指标"
                          style={{ minWidth: 300 }}
                          rules={[
                            {
                              required: mode !== 'OFF',
                              message: '请选择信号指标',
                            },
                          ]}
                        >
                          <Select
                            options={BOT_METRIC_OPTIONS}
                            placeholder="选择指标（信号组由指标决定）"
                            showSearch
                            optionFilterProp="label"
                          />
                        </Form.Item>
                      </Space>
                      {spec && (
                        <Typography.Paragraph
                          type="secondary"
                          style={{ fontSize: 12 }}
                        >
                          {spec.description}
                        </Typography.Paragraph>
                      )}
                      <Space size="middle" wrap style={{ display: 'flex' }}>
                        {(spec?.params ?? []).map((p) => (
                          <Form.Item
                            key={p.key}
                            name={[
                              field.name,
                              p.key === 'field'
                                ? 'tls_field'
                                : p.key === 'equals'
                                  ? 'tls_equals'
                                  : p.key,
                            ]}
                            label={p.label}
                            rules={[
                              {
                                required: mode !== 'OFF',
                                message: `请填写${p.label}`,
                              },
                            ]}
                          >
                            {p.options ? (
                              <Select
                                options={p.options.map((o) => ({
                                  value: o,
                                  label: o,
                                }))}
                                style={{ minWidth: 160 }}
                                placeholder={`选择${p.label}`}
                              />
                            ) : (
                              <Input
                                placeholder={p.placeholder}
                                autoComplete="off"
                                style={{ width: 200 }}
                                maxLength={128}
                              />
                            )}
                          </Form.Item>
                        ))}
                        <Form.Item
                          name={[field.name, 'window_seconds']}
                          label="窗口（秒）"
                          initialValue={BOT_POLICY_LIMITS.defaultWindowSeconds}
                          rules={[{ required: true, message: '请输入窗口' }]}
                        >
                          <InputNumber
                            min={BOT_POLICY_LIMITS.minWindowSeconds}
                            max={BOT_POLICY_LIMITS.maxWindowSeconds}
                            precision={0}
                            style={{ width: 130 }}
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'weight']}
                          label="权重"
                          initialValue={1}
                          rules={[{ required: true, message: '请输入权重' }]}
                        >
                          <InputNumber
                            min={0.1}
                            max={BOT_POLICY_LIMITS.maxRuleWeight}
                            step={0.1}
                            style={{ width: 110 }}
                          />
                        </Form.Item>
                        <Form.Item
                          name={[field.name, 'threshold']}
                          label={
                            spec?.threshold === 'ratio_lte'
                              ? '阈值（≤ 触发）'
                              : '阈值（≥ 触发）'
                          }
                          initialValue={spec?.defaultThreshold ?? 0}
                          tooltip={
                            spec?.threshold === 'none'
                              ? '声明匹配类指标命中即触发，阈值恒 0'
                              : spec?.threshold === 'count_gte'
                                ? '计数类：1~100'
                                : spec?.threshold === 'ratio_lte'
                                  ? '占比类：[0,1)'
                                  : '占比类：(0,1]'
                          }
                          rules={[
                            {
                              required:
                                mode !== 'OFF' && spec?.threshold !== 'none',
                              message: '请输入阈值',
                            },
                          ]}
                        >
                          <InputNumber
                            disabled={!spec || spec.threshold === 'none'}
                            min={0}
                            max={spec?.threshold === 'count_gte' ? 100 : 1}
                            step={
                              spec?.threshold === 'count_gte' ? 1 : 0.05
                            }
                            style={{ width: 130 }}
                          />
                        </Form.Item>
                      </Space>
                    </Card>
                  )
                })}
                <Button
                  block
                  type="dashed"
                  icon={<PlusOutlined />}
                  disabled={fields.length >= BOT_POLICY_LIMITS.maxSignalRules}
                  onClick={() =>
                    add({
                      id: '',
                      metric: undefined,
                      window_seconds: BOT_POLICY_LIMITS.defaultWindowSeconds,
                      weight: 1,
                      threshold: 0,
                    })
                  }
                >
                  添加信号规则
                </Button>
              </>
            )}
          </Form.List>

          <Typography.Title level={5} style={{ marginTop: 24 }}>
            挑战参数（第一方 JS 挑战）
          </Typography.Title>
          <Space size="middle" wrap style={{ display: 'flex' }}>
            <Form.Item
              name="nonce_ttl_seconds"
              label="挑战有效期（秒）"
              rules={[{ required: true, message: '请输入挑战有效期' }]}
            >
              <InputNumber
                min={BOT_POLICY_LIMITS.minNonceTTL}
                max={BOT_POLICY_LIMITS.maxNonceTTL}
                precision={0}
                style={{ width: 150 }}
              />
            </Form.Item>
            <Form.Item
              name="clearance_ttl_seconds"
              label="通行有效期（秒）"
              rules={[{ required: true, message: '请输入通行有效期' }]}
            >
              <InputNumber
                min={BOT_POLICY_LIMITS.minClearanceTTL}
                max={BOT_POLICY_LIMITS.maxClearanceTTL}
                precision={0}
                style={{ width: 150 }}
              />
            </Form.Item>
            <Form.Item
              name="difficulty"
              label="计算难度（bit）"
              tooltip="SHA-256 前导零比特数；越大浏览器计算越久，只能增加自动化成本，不能证明真人"
              rules={[{ required: true, message: '请输入计算难度' }]}
            >
              <InputNumber
                min={BOT_POLICY_LIMITS.minDifficulty}
                max={BOT_POLICY_LIMITS.maxDifficulty}
                precision={0}
                style={{ width: 150 }}
              />
            </Form.Item>
            <Form.Item
              name="max_attempts"
              label="单题最多验证次数"
              rules={[{ required: true, message: '请输入验证次数上限' }]}
            >
              <InputNumber
                min={BOT_POLICY_LIMITS.minMaxAttempts}
                max={BOT_POLICY_LIMITS.maxMaxAttempts}
                precision={0}
                style={{ width: 150 }}
              />
            </Form.Item>
            <Form.Item
              name="key_ref"
              label="签名密钥引用名"
              tooltip="仅引用系统设置中预置的 Bot 签名密钥（gateway_runtime.bot_signing_keys）；不接受、不显示任何密钥材料"
              rules={[
                {
                  pattern: /^[a-z0-9][a-z0-9_.-]{0,63}$/,
                  message:
                    '小写字母/数字/._-，小写字母或数字开头，1~64 字符；仅引用名',
                },
              ]}
            >
              <Input
                placeholder="如 bot-hmac-2026"
                autoComplete="off"
                style={{ width: 220 }}
                maxLength={BOT_POLICY_LIMITS.maxKeyRefLen}
              />
            </Form.Item>
          </Space>

          <Form.Item
            name="reservation_state"
            label="保留路由状态"
            extra={
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                保留命名空间 {BOT_RESERVED_NAMESPACE}：从已启用状态关闭时应保留
                404 墓碑（防旧挑战提交打到业务源站）；确认无存量挑战流量后才解除保留。PROTECT
                要求启用保留路由。
              </Typography.Text>
            }
          >
            <Radio.Group options={RESERVATION_OPTIONS} />
          </Form.Item>

          {canEdit && (
            <Form.Item
              name="reason"
              label="变更理由"
              style={{ marginTop: 8, maxWidth: 720 }}
              extra="必填，进入操作审计与不可变版本记录；升级为强制挑战（PROTECT）属高风险审计"
              rules={[
                { required: true, message: '请填写变更理由' },
                {
                  max: BOT_POLICY_LIMITS.maxReasonLen,
                  message: `变更理由不能超过 ${BOT_POLICY_LIMITS.maxReasonLen} 字符`,
                },
              ]}
            >
              <Input.TextArea
                rows={2}
                placeholder="说明本次变更原因，如：对 /docs 开启 Bot 挑战观察"
              />
            </Form.Item>
          )}
        </Form>
      </Card>

      {preflight && (
        <Card
          title="发布预检结果"
          extra={
            canEdit && (
              <Button
                size="small"
                loading={preflightMutation.isPending}
                onClick={() => void runPreflight()}
              >
                重新预检
              </Button>
            )
          }
        >
          <Alert
            type={preflight.publishable ? 'success' : 'error'}
            showIcon
            style={{ marginBottom: 16 }}
            message={
              preflight.publishable
                ? '预检通过，可经配置发布通道发布'
                : '存在未通过项，发布链路将以同口径拒绝'
            }
            description="预检为管理端视角，不代表节点实际运行态；节点实际生效以发布回执为准。预检不保存、不发布。修复依赖或冲突后可重新预检。"
          />
          <List
            size="small"
            header={<Typography.Text strong>检查项</Typography.Text>}
            dataSource={preflight.checks}
            renderItem={(c) => (
              <List.Item>
                <Space direction="vertical" size={2} style={{ width: '100%' }}>
                  <Space>
                    <StatusTag value={c.status} map={BOT_CHECK_STATUS_META} />
                    <Typography.Text strong>
                      {BOT_CHECK_NAME_LABELS[c.name] ?? c.name}
                    </Typography.Text>
                  </Space>
                  <Typography.Text
                    type="secondary"
                    style={{
                      fontSize: 12,
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}
                  >
                    {c.message}
                  </Typography.Text>
                </Space>
              </List.Item>
            )}
          />
          {preflight.conflicts.length > 0 && (
            <List
              size="small"
              style={{ marginTop: 12 }}
              header={
                <Typography.Text strong>
                  保留路由冲突（FAIL 阻断发布，WARN 仅提示）
                </Typography.Text>
              }
              dataSource={preflight.conflicts}
              renderItem={(c) => (
                <List.Item>
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    <Space wrap>
                      <StatusTag value={c.status} map={BOT_CHECK_STATUS_META} />
                      <Tag>
                        {BOT_CONFLICT_TYPE_LABELS[c.type] ?? c.type}
                      </Tag>
                      {c.ref && (
                        <Typography.Text code style={{ fontSize: 12 }}>
                          {c.ref}
                        </Typography.Text>
                      )}
                    </Space>
                    <Typography.Text
                      type="secondary"
                      style={{
                        fontSize: 12,
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}
                    >
                      {c.message}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}
        </Card>
      )}

      <Collapse
        items={[
          {
            key: 'challenge-preview',
            label:
              '终端用户挑战页体验预览（静态示意：等待 / 手动重试 / JS 不可用 / 服务故障）',
            children: <BotChallengePreview />,
          },
        ]}
      />
    </Space>
  )
}
