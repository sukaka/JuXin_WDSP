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
  DeploymentUnitOutlined,
  ReloadOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  SEMANTIC_GUARD_LIMITS,
  semanticGuardApi,
  type SemanticGuardFailPolicy,
  type SemanticGuardMode,
} from '../../../api/semanticGuard'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  formatShortSha256,
  mapSemanticGuardFieldErrorPath,
  SEMANTIC_GUARD_BACKEND_META,
  SEMANTIC_GUARD_FAIL_POLICY_META,
  SEMANTIC_GUARD_MODE_META,
  SEMANTIC_GUARD_STATE_META,
  validateSemanticSocketPath,
} from '../../../utils/semanticGuard'
import {
  InlineNote,
  ModeCardGroup,
  SectionHeader,
  type ModeCardOption,
} from './DetailTabPrimitives'
import './detailTab.css'

const MODE_CARD_OPTIONS: ModeCardOption<SemanticGuardMode>[] = [
  {
    value: 'OFF',
    label: '关闭（不启用本地语义检测）',
    description: '透传所有请求与响应，不调用本地 ONNX/SLM 语义推理 Sidecar',
    badge: '默认',
    tone: 'neutral',
  },
  {
    value: 'OBSERVE',
    label: '观察（仅语义评分与记录告警，不阻断）',
    description:
      '对启用通道执行本地语义推理，达到观察阈值记录 SEMANTIC_OBSERVED 事件，不阻断业务请求',
    badge: '推荐先用',
    badgeColor: 'blue',
    tone: 'info',
  },
  {
    value: 'PROTECT',
    label: '强制执行（高置信语义攻击在线阻断）',
    description:
      '达到观察阈值记录观测，达到阻断阈值返回 403 阻断并记录 SEMANTIC_BLOCKED；Sidecar 不可用按降级策略处置',
    badge: '在线防护',
    badgeColor: 'green',
    tone: 'success',
  },
]

const FAIL_POLICY_OPTIONS: {
  value: SemanticGuardFailPolicy
  label: string
}[] = [
  {
    value: 'FAIL_OPEN',
    label: SEMANTIC_GUARD_FAIL_POLICY_META.FAIL_OPEN.label,
  },
  {
    value: 'FAIL_CLOSED',
    label: SEMANTIC_GUARD_FAIL_POLICY_META.FAIL_CLOSED.label,
  },
]

interface PolicyFormValues {
  mode: SemanticGuardMode
  inspect_llm_prompts: boolean
  inspect_mcp_content: boolean
  inspect_web_grayzone: boolean
  observe_threshold: number
  block_threshold: number
  socket_path: string
  timeout_ms: number
  max_concurrency: number
  max_input_runes: number
  fail_policy: SemanticGuardFailPolicy
  circuit_failure_threshold: number
  circuit_open_seconds: number
  reason: string
}

const DEFAULT_VALUES: PolicyFormValues = {
  mode: 'OFF',
  inspect_llm_prompts: true,
  inspect_mcp_content: true,
  inspect_web_grayzone: true,
  observe_threshold: SEMANTIC_GUARD_LIMITS.defaultObserveThreshold,
  block_threshold: SEMANTIC_GUARD_LIMITS.defaultBlockThreshold,
  socket_path: SEMANTIC_GUARD_LIMITS.defaultSocketPath,
  timeout_ms: SEMANTIC_GUARD_LIMITS.defaultTimeoutMs,
  max_concurrency: SEMANTIC_GUARD_LIMITS.defaultMaxConcurrency,
  max_input_runes: SEMANTIC_GUARD_LIMITS.defaultMaxInputRunes,
  fail_policy: 'FAIL_OPEN',
  circuit_failure_threshold:
    SEMANTIC_GUARD_LIMITS.defaultCircuitFailureThreshold,
  circuit_open_seconds: SEMANTIC_GUARD_LIMITS.defaultCircuitOpenSeconds,
  reason: '',
}

export default function SemanticGuardTab({
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
  const canManage = hasPermission(permissions, 'semantic_guard.manage')
  const [form] = Form.useForm<PolicyFormValues>()

  const modeWatch = Form.useWatch('mode', form) ?? 'OFF'
  const failPolicyWatch = Form.useWatch('fail_policy', form) ?? 'FAIL_OPEN'
  const inspectLlmWatch = Form.useWatch('inspect_llm_prompts', form) ?? false
  const inspectMcpWatch = Form.useWatch('inspect_mcp_content', form) ?? false
  const inspectWebWatch = Form.useWatch('inspect_web_grayzone', form) ?? false

  const policyQuery = useQuery({
    queryKey: ['semantic-guard-policy', appId],
    queryFn: () => semanticGuardApi.getPolicy(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  const customSocketPath =
    policy?.socket_path &&
    policy.socket_path !== SEMANTIC_GUARD_LIMITS.defaultSocketPath &&
    validateSemanticSocketPath(policy.socket_path) === null
      ? policy.socket_path
      : undefined

  const statusQuery = useQuery({
    queryKey: ['semantic-guard-status', customSocketPath ?? 'default'],
    queryFn: () => semanticGuardApi.getStatus(customSocketPath),
  })

  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      inspect_llm_prompts: Boolean(policy.inspect_llm_prompts),
      inspect_mcp_content: Boolean(policy.inspect_mcp_content),
      inspect_web_grayzone: Boolean(policy.inspect_web_grayzone),
      observe_threshold:
        policy.observe_threshold ??
        SEMANTIC_GUARD_LIMITS.defaultObserveThreshold,
      block_threshold:
        policy.block_threshold ?? SEMANTIC_GUARD_LIMITS.defaultBlockThreshold,
      socket_path:
        policy.socket_path || SEMANTIC_GUARD_LIMITS.defaultSocketPath,
      timeout_ms: policy.timeout_ms || SEMANTIC_GUARD_LIMITS.defaultTimeoutMs,
      max_concurrency:
        policy.max_concurrency || SEMANTIC_GUARD_LIMITS.defaultMaxConcurrency,
      max_input_runes:
        policy.max_input_runes || SEMANTIC_GUARD_LIMITS.defaultMaxInputRunes,
      fail_policy:
        policy.fail_policy === 'FAIL_CLOSED' ? 'FAIL_CLOSED' : 'FAIL_OPEN',
      circuit_failure_threshold:
        policy.circuit_failure_threshold ||
        SEMANTIC_GUARD_LIMITS.defaultCircuitFailureThreshold,
      circuit_open_seconds:
        policy.circuit_open_seconds ||
        SEMANTIC_GUARD_LIMITS.defaultCircuitOpenSeconds,
      reason: '',
    })
  }, [policy, form])

  const invalidate = () => {
    void queryClient.invalidateQueries({
      queryKey: ['semantic-guard-policy', appId],
    })
    void queryClient.invalidateQueries({
      queryKey: ['semantic-guard-status'],
    })
  }

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      semanticGuardApi.updatePolicy(appId, {
        mode: values.mode,
        expected_version: policy?.version ?? 0,
        socket_path: values.socket_path.trim(),
        timeout_ms: values.timeout_ms,
        max_concurrency: values.max_concurrency,
        max_input_runes: values.max_input_runes,
        block_threshold: values.block_threshold,
        observe_threshold: values.observe_threshold,
        fail_policy: values.fail_policy,
        inspect_llm_prompts: Boolean(values.inspect_llm_prompts),
        inspect_mcp_content: Boolean(values.inspect_mcp_content),
        inspect_web_grayzone: Boolean(values.inspect_web_grayzone),
        circuit_failure_threshold: values.circuit_failure_threshold,
        circuit_open_seconds: values.circuit_open_seconds,
        reason: values.reason.trim(),
      }),
    onSuccess: () => {
      message.success('本地语义防火墙策略草稿已保存；发布并获节点回执后才会生效')
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
          const name = mapSemanticGuardFieldErrorPath(d.field)
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
        message="加载本地语义防火墙策略失败"
      />
    )
  }

  const sidecar = statusQuery.data
  const effectiveMode = summary.state === 'PUBLISHED' ? policy.mode : null

  return (
    <div className="jz-detail-tab">
      <Card
        className="jz-detail-card"
        title="本地语义推理引擎状态（Sidecar）"
        extra={
          <Space size={8}>
            {sidecar && (
              <Tag
                color={sidecar.available ? 'success' : 'warning'}
                style={{ marginInlineEnd: 0 }}
              >
                {sidecar.available ? '在线' : '未部署 / 离线'}
              </Tag>
            )}
            <Button
              size="small"
              icon={<ReloadOutlined />}
              loading={statusQuery.isFetching}
              onClick={() => void statusQuery.refetch()}
            >
              刷新状态
            </Button>
          </Space>
        }
      >
        {statusQuery.isLoading ? (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Spin size="small" />
            <Typography.Text type="secondary">
              正在通过 Unix Socket 探测本地语义推理引擎状态…
            </Typography.Text>
          </div>
        ) : statusQuery.isError ? (
          <Alert
            type="warning"
            showIcon
            title="本地语义推理引擎状态探测失败"
            description={
              statusQuery.error instanceof ApiError
                ? `${statusQuery.error.message}。系统不会伪装在线状态，请确认 Sidecar 服务与管理面访问权限后点击「刷新状态」重试。`
                : '无法连接管理面状态探测接口；系统不会伪装在线状态，请稍后重试。'
            }
          />
        ) : sidecar?.available ? (
          <>
            <Alert
              type={
                sidecar.backend === 'onnxruntime' ? 'success' : 'info'
              }
              showIcon
              style={{ marginBottom: 14 }}
              title={
                sidecar.backend === 'onnxruntime'
                  ? '本地 ONNX 语义推理引擎在线就绪'
                  : '本地语义推理引擎在线（启发式降级模式）'
              }
              description={
                sidecar.backend === 'onnxruntime'
                  ? 'Sidecar 已完成离线模型 SHA-256 完整性校验并监听本地 Unix Socket，可为网关提供零外网依赖的低延迟语义分类。'
                  : '当前 Sidecar 运行在零依赖启发式降级后端（未挂载 ONNX 模型）；如需深度语义推理，请挂载经 SHA-256 清单校验的离线 INT8 ONNX 模型。'
              }
            />
            <Descriptions column={{ xs: 1, sm: 2, md: 4 }} size="small">
              <Descriptions.Item label="推理后端">
                <StatusTag
                  value={sidecar.backend || 'unknown'}
                  map={SEMANTIC_GUARD_BACKEND_META}
                />
              </Descriptions.Item>
              <Descriptions.Item label="模型标识">
                <Typography.Text code>
                  {sidecar.model_id || '-'}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="模型 SHA-256">
                {sidecar.model_sha256 ? (
                  <Tooltip title={sidecar.model_sha256}>
                    <Typography.Text
                      code
                      copyable={{ text: sidecar.model_sha256 }}
                    >
                      {formatShortSha256(sidecar.model_sha256)}
                    </Typography.Text>
                  </Tooltip>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                )}
              </Descriptions.Item>
              <Descriptions.Item label="Unix Socket 路径">
                <Typography.Text code>{sidecar.socket_path}</Typography.Text>
              </Descriptions.Item>
            </Descriptions>
          </>
        ) : (
          <Alert
            type="warning"
            showIcon
            title="本地语义推理引擎未部署或当前离线"
            description={`探测路径：${sidecar?.socket_path || SEMANTIC_GUARD_LIMITS.defaultSocketPath}${sidecar?.error ? `；原因：${sidecar.error}` : ''}。本地语义 Sidecar 为可选离线组件，离线时仍可保存策略草稿；若在「强制执行」模式下启用 FAIL_CLOSED，Sidecar 不可用时网关将返回 HTTP 503（不会伪装为 403 攻击拦截）。`}
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="策略状态"
        extra={
          summary.state === 'DRAFT_PENDING' && inRouter ? (
            <Link to="/config-publish">
              <Button type="link" size="small" style={{ paddingInline: 0 }}>
                前往配置发布
              </Button>
            </Link>
          ) : undefined
        }
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用范围">
            <Typography.Text code>{appCode}</Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="配置状态">
            <StatusTag value={summary.state} map={SEMANTIC_GUARD_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={SEMANTIC_GUARD_MODE_META} />
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
              title={`已生效：${SEMANTIC_GUARD_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="本地语义防火墙策略已随最近成功发布快照下发至网关节点运行。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 14 }}
            title="尚未配置本地语义防火墙策略，当前维持默认透传行为"
            description="启用后可通过本机 Unix Socket 调用离线 ONNX/SLM 语义推理 Sidecar，对 LLM 提示词、MCP 工具入参/返回及 Web 灰区样本进行零外网依赖语义防御。"
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="本地离线 ONNX/SLM 语义防火墙策略"
        extra={
          <Space size={6}>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              Unix Socket Only
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>Offline ONNX / SLM</Tag>
          </Space>
        }
      >
        <InlineNote tooltip="网关仅通过本机受控目录（/var/run/caddy/sidecars/ 或 /run/jiuzhang/）下的 Unix Domain Socket 调用语义推理 Sidecar，强制单次硬超时、非阻塞并发信号量与熔断器保护；绝不转发 Cookie/Authorization 认证头，且审计证据仅保留通道、标签、分值、模型 ID、耗时与输入字符数，绝不落盘原始提示词或报文正文。">
          全链路离线本地推理，无外部云模型调用；支持按通道启用 LLM 提示词、MCP
          内容及 Web 灰区复检，并由硬超时、并发信号量与熔断器保障网关稳定性。
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
            description="控制当前应用调用本地语义推理引擎后的处置强度（建议先开启「观察」验证延迟与误报后再切换「强制执行」）。"
          />
          <Form.Item name="mode" style={{ marginBottom: 8 }}>
            <ModeCardGroup options={MODE_CARD_OPTIONS} disabled={!canManage} />
          </Form.Item>

          <SectionHeader
            spaced
            title="检测通道"
            description="按业务形态精细选择送入本地语义推理 Sidecar 的流量通道，正常未命中的 Web 流量可保持零推理开销。"
          />
          <Row gutter={[12, 12]}>
            <Col xs={24} md={8}>
              <div
                className={`jz-detail-switch-tile${inspectLlmWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="inspect_llm_prompts"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>LLM 提示词语义检测</span>
                      <span className="jz-detail-switch-desc">
                        对已识别的 LLM 请求提示词执行本地提示词注入与越狱语义分类
                      </span>
                    </>
                  }
                >
                  <Switch />
                </Form.Item>
              </div>
            </Col>
            <Col xs={24} md={8}>
              <div
                className={`jz-detail-switch-tile${inspectMcpWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="inspect_mcp_content"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>MCP 工具/返回语义检测</span>
                      <span className="jz-detail-switch-desc">
                        对 MCP tools/call 入参及缓冲返回文本检测间接提示词注入
                      </span>
                    </>
                  }
                >
                  <Switch />
                </Form.Item>
              </div>
            </Col>
            <Col xs={24} md={8}>
              <div
                className={`jz-detail-switch-tile${inspectWebWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="inspect_web_grayzone"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>Web 灰区样本复检</span>
                      <span className="jz-detail-switch-desc">
                        仅对已有风险分值（≥10）或命中观察规则且未硬阻断的灰区请求复检，干净流量零开销
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
            title="语义评分阈值"
            description="推理分值介于观察阈值与阻断阈值之间时仅记录观测事件；达到阻断阈值且处于「强制执行」模式时触发 403 阻断。须满足：观察阈值 ≤ 阻断阈值。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="observe_threshold"
                label="观察阈值"
                dependencies={['block_threshold']}
                extra={`范围 ${SEMANTIC_GUARD_LIMITS.minObserveThreshold.toFixed(2)}~${SEMANTIC_GUARD_LIMITS.maxObserveThreshold.toFixed(2)}（默认 ${SEMANTIC_GUARD_LIMITS.defaultObserveThreshold.toFixed(2)}），且不得高于阻断阈值`}
                rules={[
                  { required: true, message: '请填写观察阈值' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minObserveThreshold,
                    max: SEMANTIC_GUARD_LIMITS.maxObserveThreshold,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minObserveThreshold.toFixed(2)} 到 ${SEMANTIC_GUARD_LIMITS.maxObserveThreshold.toFixed(2)} 之间`,
                  },
                  ({ getFieldValue }) => ({
                    validator(_, value?: number) {
                      const blockVal = getFieldValue('block_threshold') as
                        | number
                        | undefined
                      if (
                        typeof value === 'number' &&
                        typeof blockVal === 'number' &&
                        value > blockVal
                      ) {
                        return Promise.reject(
                          new Error('观察阈值不能高于阻断阈值'),
                        )
                      }
                      return Promise.resolve()
                    },
                  }),
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minObserveThreshold}
                  max={SEMANTIC_GUARD_LIMITS.maxObserveThreshold}
                  step={0.01}
                  precision={2}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="block_threshold"
                label="阻断阈值"
                dependencies={['observe_threshold']}
                extra={`范围 ${SEMANTIC_GUARD_LIMITS.minBlockThreshold.toFixed(2)}~${SEMANTIC_GUARD_LIMITS.maxBlockThreshold.toFixed(2)}（默认 ${SEMANTIC_GUARD_LIMITS.defaultBlockThreshold.toFixed(2)}），且不得低于观察阈值`}
                rules={[
                  { required: true, message: '请填写阻断阈值' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minBlockThreshold,
                    max: SEMANTIC_GUARD_LIMITS.maxBlockThreshold,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minBlockThreshold.toFixed(2)} 到 ${SEMANTIC_GUARD_LIMITS.maxBlockThreshold.toFixed(2)} 之间`,
                  },
                  ({ getFieldValue }) => ({
                    validator(_, value?: number) {
                      const observeVal = getFieldValue('observe_threshold') as
                        | number
                        | undefined
                      if (
                        typeof value === 'number' &&
                        typeof observeVal === 'number' &&
                        observeVal > value
                      ) {
                        return Promise.reject(
                          new Error('阻断阈值不能低于观察阈值'),
                        )
                      }
                      return Promise.resolve()
                    },
                  }),
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minBlockThreshold}
                  max={SEMANTIC_GUARD_LIMITS.maxBlockThreshold}
                  step={0.01}
                  precision={2}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
          </Row>

          <SectionHeader
            spaced
            title="运行时与熔断器护栏"
            description="限制本地 Unix Socket 路径边界、单次推理硬超时、并发信号量上限与连续失败熔断窗口，确保推理异常绝不拖垮网关转发链路。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={14}>
              <Form.Item
                name="socket_path"
                label="本地 Unix Socket 路径"
                extra={`仅允许 /var/run/caddy/sidecars/ 或 /run/jiuzhang/ 下的规范文件路径（≤ ${SEMANTIC_GUARD_LIMITS.maxSocketPathLen} 字符），禁止 .. 与 HTTP/TCP 地址`}
                rules={[
                  {
                    validator: (_, val?: string) => {
                      const err = validateSemanticSocketPath(val)
                      return err
                        ? Promise.reject(new Error(err))
                        : Promise.resolve()
                    },
                  },
                ]}
              >
                <Input
                  placeholder={SEMANTIC_GUARD_LIMITS.defaultSocketPath}
                  maxLength={SEMANTIC_GUARD_LIMITS.maxSocketPathLen}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={10}>
              <Form.Item
                name="fail_policy"
                label="Sidecar 异常降级策略"
                extra="当 Sidecar 离线、超时、并发饱和或熔断开启时的处置策略"
                rules={[{ required: true, message: '请选择异常降级策略' }]}
              >
                <Select options={FAIL_POLICY_OPTIONS} />
              </Form.Item>
            </Col>
          </Row>

          {modeWatch === 'PROTECT' && failPolicyWatch === 'FAIL_CLOSED' && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title="强制执行 + 故障闭环（FAIL_CLOSED）提示"
              description="当本地 Sidecar 不可用、单次推理超时、并发打满或熔断器开启时，网关将返回 HTTP 503（semantic_guard_unavailable）并记录 SEMANTIC_UNAVAILABLE 事件，绝不伪装为 403 攻击拦截。"
            />
          )}

          <Row gutter={[16, 0]}>
            <Col xs={24} md={8}>
              <Form.Item
                name="timeout_ms"
                label="单次推理超时（毫秒）"
                extra={`范围 ${SEMANTIC_GUARD_LIMITS.minTimeoutMs}~${SEMANTIC_GUARD_LIMITS.maxTimeoutMs} ms（默认 ${SEMANTIC_GUARD_LIMITS.defaultTimeoutMs}）`}
                rules={[
                  { required: true, message: '请填写单次推理超时' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minTimeoutMs,
                    max: SEMANTIC_GUARD_LIMITS.maxTimeoutMs,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minTimeoutMs} 到 ${SEMANTIC_GUARD_LIMITS.maxTimeoutMs} 毫秒之间`,
                  },
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minTimeoutMs}
                  max={SEMANTIC_GUARD_LIMITS.maxTimeoutMs}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name="max_concurrency"
                label="最大并发推理数"
                extra={`范围 ${SEMANTIC_GUARD_LIMITS.minMaxConcurrency}~${SEMANTIC_GUARD_LIMITS.maxMaxConcurrency}（默认 ${SEMANTIC_GUARD_LIMITS.defaultMaxConcurrency}）`}
                rules={[
                  { required: true, message: '请填写最大并发推理数' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minMaxConcurrency,
                    max: SEMANTIC_GUARD_LIMITS.maxMaxConcurrency,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minMaxConcurrency} 到 ${SEMANTIC_GUARD_LIMITS.maxMaxConcurrency} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minMaxConcurrency}
                  max={SEMANTIC_GUARD_LIMITS.maxMaxConcurrency}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={8}>
              <Form.Item
                name="max_input_runes"
                label="单次最大输入字符数"
                extra={`范围 ${SEMANTIC_GUARD_LIMITS.minMaxInputRunes}~${SEMANTIC_GUARD_LIMITS.maxMaxInputRunes}（默认 ${SEMANTIC_GUARD_LIMITS.defaultMaxInputRunes}）`}
                rules={[
                  { required: true, message: '请填写单次最大输入字符数' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minMaxInputRunes,
                    max: SEMANTIC_GUARD_LIMITS.maxMaxInputRunes,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minMaxInputRunes} 到 ${SEMANTIC_GUARD_LIMITS.maxMaxInputRunes} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minMaxInputRunes}
                  max={SEMANTIC_GUARD_LIMITS.maxMaxInputRunes}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="circuit_failure_threshold"
                label="熔断连续失败阈值（次）"
                extra={`连续失败达阈后熔断器打开，范围 ${SEMANTIC_GUARD_LIMITS.minCircuitFailureThreshold}~${SEMANTIC_GUARD_LIMITS.maxCircuitFailureThreshold}（默认 ${SEMANTIC_GUARD_LIMITS.defaultCircuitFailureThreshold}）`}
                rules={[
                  { required: true, message: '请填写熔断连续失败阈值' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minCircuitFailureThreshold,
                    max: SEMANTIC_GUARD_LIMITS.maxCircuitFailureThreshold,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minCircuitFailureThreshold} 到 ${SEMANTIC_GUARD_LIMITS.maxCircuitFailureThreshold} 之间`,
                  },
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minCircuitFailureThreshold}
                  max={SEMANTIC_GUARD_LIMITS.maxCircuitFailureThreshold}
                  precision={0}
                  style={{ width: '100%' }}
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="circuit_open_seconds"
                label="熔断开启持续时间（秒）"
                extra={`熔断冷却后转半开探测，范围 ${SEMANTIC_GUARD_LIMITS.minCircuitOpenSeconds}~${SEMANTIC_GUARD_LIMITS.maxCircuitOpenSeconds} 秒（默认 ${SEMANTIC_GUARD_LIMITS.defaultCircuitOpenSeconds}）`}
                rules={[
                  { required: true, message: '请填写熔断开启持续时间' },
                  {
                    type: 'number',
                    min: SEMANTIC_GUARD_LIMITS.minCircuitOpenSeconds,
                    max: SEMANTIC_GUARD_LIMITS.maxCircuitOpenSeconds,
                    message: `须在 ${SEMANTIC_GUARD_LIMITS.minCircuitOpenSeconds} 到 ${SEMANTIC_GUARD_LIMITS.maxCircuitOpenSeconds} 秒之间`,
                  },
                ]}
              >
                <InputNumber
                  min={SEMANTIC_GUARD_LIMITS.minCircuitOpenSeconds}
                  max={SEMANTIC_GUARD_LIMITS.maxCircuitOpenSeconds}
                  precision={0}
                  style={{ width: '100%' }}
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
                    max: SEMANTIC_GUARD_LIMITS.maxReasonLen,
                    message: `变更理由不能超过 ${SEMANTIC_GUARD_LIMITS.maxReasonLen} 字符`,
                  },
                ]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="说明本次变更原因，如：为 LLM 与 MCP 入口开启本地离线语义防火墙观察模式"
                />
              </Form.Item>
              <div className="jz-detail-audit-submit-actions">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  <DeploymentUnitOutlined style={{ marginRight: 6 }} />
                  <SafetyCertificateOutlined style={{ marginRight: 4 }} />
                  {`乐观锁基线版本 v${policy.version}；草稿保存后须前往「配置发布」下发至网关节点方可生效。`}
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
