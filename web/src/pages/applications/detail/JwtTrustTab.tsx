import { useEffect, useRef, useState } from 'react'
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
  Radio,
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
  KeyOutlined,
  LinkOutlined,
  MinusCircleOutlined,
  PlusOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  JWT_DPOP_ALGS,
  JWT_TRUST_LIMITS,
  jwtTrustApi,
  jwksHasPrivateMaterial,
  validateStaticJwks,
} from '../../../api/jwtTrust'
import type {
  JwtTokenBindingConfig,
  JwtTokenBindingMode,
  JwtTrustIssuer,
  JwtTrustMode,
  JwtTrustPreflightResult,
  JwtTrustSelector,
} from '../../../api/jwtTrust'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  JWT_DPOP_ALG_OPTIONS,
  JWT_TOKEN_BINDING_MODE_META,
  JWT_TRUST_CHECK_NAME_LABELS,
  JWT_TRUST_CHECK_STATUS_META,
  JWT_TRUST_MODE_META,
  JWT_TRUST_STATE_META,
  isDPoPBindingMode,
  isMTLSBindingMode,
  mapJwtTrustFieldErrorPath,
} from '../../../utils/jwtTrust'
import {
  InlineNote,
  ModeCardGroup,
  PreflightResultCard,
  SectionHeader,
  type ModeCardOption,
} from './DetailTabPrimitives'
import './detailTab.css'

const METHOD_OPTIONS = [
  'GET',
  'POST',
  'PUT',
  'DELETE',
  'PATCH',
  'HEAD',
  'OPTIONS',
].map((m) => ({
  value: m,
  label: m,
}))

const ALGORITHM_OPTIONS = [
  { value: 'RS256', label: 'RS256' },
  { value: 'ES256', label: 'ES256' },
]

const MODE_CARD_OPTIONS: ModeCardOption<JwtTrustMode>[] = [
  {
    value: 'OFF',
    label: '关闭（不校验 Token）',
    description: '维持既有流量行为，不解析业务 Bearer 凭证',
    badge: '默认',
    tone: 'neutral',
  },
  {
    value: 'OBSERVE',
    label: '观察（校验并记录，不拦截）',
    description: '仅校验签名与声明并记录结果，推荐灰度阶段先启用',
    badge: '推荐先用',
    badgeColor: 'blue',
    tone: 'info',
  },
  {
    value: 'PROTECT',
    label: '强制验证（非法 Token 401 / 验证不可用 503）',
    description: '在 API 管线出口强制实断，白名单与 L7 allow 不绕过',
    badge: '严格阻断',
    badgeColor: 'green',
    tone: 'success',
  },
]

/** 表单值（选择器路径二选一折叠为 match_type+path；issuer 密钥来源拍平为三个字段） */
interface SelectorFormValue {
  methods: string[]
  match_type: 'exact' | 'prefix'
  path: string
  token_required: boolean
}

const TOKEN_BINDING_MODE_OPTIONS = (
  [
    'NONE',
    'DPOP_OPTIONAL',
    'DPOP_REQUIRED',
    'MTLS_REQUIRED',
    'DPOP_OR_MTLS',
  ] as const
).map((value) => ({
  value,
  label: JWT_TOKEN_BINDING_MODE_META[value].label,
}))

interface IssuerFormValue {
  issuer: string
  audiences: string[]
  algorithms: string[]
  key_source_type: 'STATIC_JWKS' | 'REMOTE_JWKS'
  jwks?: string
  url?: string
  clock_skew_seconds: number
  tenant_claim?: string
  role_claims?: string[]
  token_binding_mode?: JwtTokenBindingMode
  dpop_require_nonce?: boolean
  dpop_max_proof_age_seconds?: number
  dpop_nonce_ttl_seconds?: number
  dpop_allowed_algs?: string[]
}

interface PolicyFormValues {
  mode: JwtTrustMode
  selectors: SelectorFormValue[]
  issuers: IssuerFormValue[]
  reason: string
}

const DEFAULT_VALUES: PolicyFormValues = {
  mode: 'OFF',
  selectors: [],
  issuers: [],
  reason: '',
}

function toSelectors(values: SelectorFormValue[]): JwtTrustSelector[] {
  return (values ?? []).map((s) => ({
    methods: s.methods ?? [],
    path_exact: s.match_type === 'exact' ? (s.path ?? '') : undefined,
    path_prefix: s.match_type === 'prefix' ? (s.path ?? '') : undefined,
    token_required: s.token_required ?? false,
  }))
}

function toTokenBinding(
  is: IssuerFormValue,
): JwtTokenBindingConfig | undefined {
  const tbMode = is.token_binding_mode
  if (!tbMode || tbMode === 'NONE') {
    return undefined
  }
  if (!isDPoPBindingMode(tbMode)) {
    return { mode: tbMode }
  }
  const allowedAlgs = Array.from(
    new Set((is.dpop_allowed_algs ?? []).map((a) => a.trim()).filter(Boolean)),
  )
  return {
    mode: tbMode,
    require_nonce: Boolean(is.dpop_require_nonce),
    max_proof_age_seconds:
      is.dpop_max_proof_age_seconds ?? JWT_TRUST_LIMITS.defaultDPoPMaxProofAge,
    nonce_ttl_seconds:
      is.dpop_nonce_ttl_seconds ?? JWT_TRUST_LIMITS.defaultDPoPNonceTTL,
    ...(allowedAlgs.length > 0 ? { allowed_dpop_algs: allowedAlgs } : {}),
  }
}

function toIssuers(values: IssuerFormValue[]): JwtTrustIssuer[] {
  return (values ?? []).map((is) => {
    const tokenBinding = toTokenBinding(is)
    return {
      issuer: is.issuer ?? '',
      audiences: is.audiences ?? [],
      algorithms: is.algorithms ?? [],
      key_source: {
        type: is.key_source_type,
        jwks: is.key_source_type === 'STATIC_JWKS' ? (is.jwks ?? '') : undefined,
        url: is.key_source_type === 'REMOTE_JWKS' ? (is.url ?? '') : undefined,
      },
      clock_skew_seconds:
        is.clock_skew_seconds ?? JWT_TRUST_LIMITS.defaultClockSkew,
      tenant_claim: is.tenant_claim?.trim() ? is.tenant_claim.trim() : undefined,
      role_claims: Array.from(
        new Set(
          (is.role_claims ?? [])
            .map((c) => c.trim())
            .filter((c) => c.length > 0),
        ),
      ),
      ...(tokenBinding ? { token_binding: tokenBinding } : {}),
    }
  })
}

export default function JwtTrustTab({
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
  const canManage = hasPermission(permissions, 'jwt_trust.manage')
  const [form] = Form.useForm<PolicyFormValues>()
  const mode = Form.useWatch('mode', form) ?? 'OFF'
  const selectorsWatch = Form.useWatch('selectors', form) ?? []
  const issuersWatch = Form.useWatch('issuers', form) ?? []
  const [preflight, setPreflight] = useState<JwtTrustPreflightResult | null>(
    null,
  )
  const preflightRef = useRef<HTMLDivElement | null>(null)

  const policyQuery = useQuery({
    queryKey: ['jwt-trust-policy', appId],
    queryFn: () => jwtTrustApi.get(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  // GET 回填（含保存后重新拉取的新 version）
  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      selectors: (policy.selectors ?? []).map((s) => ({
        methods: s.methods ?? [],
        match_type: s.path_exact ? ('exact' as const) : ('prefix' as const),
        path: s.path_exact || s.path_prefix || '',
        token_required: s.token_required ?? false,
      })),
      issuers: (policy.issuers ?? []).map((is) => ({
        issuer: is.issuer,
        audiences: is.audiences ?? [],
        algorithms: is.algorithms ?? [],
        key_source_type: is.key_source?.type ?? 'STATIC_JWKS',
        jwks: is.key_source?.jwks ?? '',
        url: is.key_source?.url ?? '',
        clock_skew_seconds:
          is.clock_skew_seconds ?? JWT_TRUST_LIMITS.defaultClockSkew,
        tenant_claim: is.tenant_claim ?? '',
        role_claims: is.role_claims ?? [],
        token_binding_mode: is.token_binding?.mode ?? 'NONE',
        dpop_require_nonce: is.token_binding?.require_nonce ?? false,
        dpop_max_proof_age_seconds:
          is.token_binding?.max_proof_age_seconds ??
          JWT_TRUST_LIMITS.defaultDPoPMaxProofAge,
        dpop_nonce_ttl_seconds:
          is.token_binding?.nonce_ttl_seconds ??
          JWT_TRUST_LIMITS.defaultDPoPNonceTTL,
        dpop_allowed_algs:
          is.token_binding?.allowed_dpop_algs &&
          is.token_binding.allowed_dpop_algs.length > 0
            ? is.token_binding.allowed_dpop_algs
            : [...JWT_DPOP_ALGS],
      })),
      reason: '',
    })
  }, [policy, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ['jwt-trust-policy', appId],
    })

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      jwtTrustApi.update(appId, {
        mode: values.mode,
        expected_version: policy?.version ?? 0,
        selectors: toSelectors(values.selectors),
        issuers: toIssuers(values.issuers),
        reason: values.reason.trim(),
      }),
    onSuccess: () => {
      // 保存草稿≠线上生效：发布并获节点回执后才生效（任务书 §8）
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
          const name = mapJwtTrustFieldErrorPath(d.field)
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
      jwtTrustApi.preflight(appId, {
        mode: values.mode,
        selectors: toSelectors(values.selectors),
        issuers: toIssuers(values.issuers),
      }),
    onSuccess: (data) => {
      setPreflight(data)
      setTimeout(() => {
        if (typeof preflightRef.current?.scrollIntoView === 'function') {
          preflightRef.current.scrollIntoView({
            behavior: 'smooth',
            block: 'nearest',
          })
        }
      }, 60)
    },
    onError: (e) =>
      message.error(e instanceof ApiError ? e.message : '预检失败'),
  })

  const runPreflight = async () => {
    try {
      // 预检不需要变更理由，仅校验策略字段
      const values = await form.validateFields(['mode', 'selectors', 'issuers'])
      setPreflight(null)
      preflightMutation.mutate({ ...form.getFieldsValue(true), ...values })
    } catch {
      message.warning('请先修正表单中的校验错误再执行预检')
    }
  }

  /** 静态 JWKS 粘贴即时检查：检出私钥/对称材料立即拒绝并清空，不回显已粘贴内容（任务书 §8） */
  const onJwksChange = (fieldName: number, value: string) => {
    if (jwksHasPrivateMaterial(value)) {
      form.setFieldValue(['issuers', fieldName, 'jwks'], '')
      message.error(
        '检测到私钥或对称密钥材料（"d"/"p"/"q" 等私钥参数或 "kty":"oct"），已拒绝并清空输入；静态 JWKS 仅允许公钥',
      )
    }
  }

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
        message="加载 JWT 信任策略失败"
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
            <StatusTag value={summary.state} map={JWT_TRUST_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={JWT_TRUST_MODE_META} />
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
            description={`草稿 v${summary.draft_version} 与已生效版本 v${summary.published_version} 存在差异；保存草稿不等于线上生效，需经配置发布并获节点回执后才生效。发布失败时旧版本继续运行。`}
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
              title={`已生效：${JWT_TRUST_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="节点级密钥状态与同步结果以发布预检和节点回执为准；部分节点同步失败时发布会被拒绝并保留旧版本（部分节点未生效）。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 14 }}
            title="尚未配置 JWT 信任策略，当前不校验业务 Token"
            description="默认关闭，不改变既有流量；密钥不可用、部分节点未生效等运行态以预检与发布回执为准。"
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="策略配置"
        extra={
          <Space size={6}>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              RS256 / ES256
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>本地验签 · 零热路径 IO</Tag>
          </Space>
        }
      >
        <InlineNote tooltip="密钥轮换条件：上游须先在 JWKS 中公布新 kid 对应公钥，再开始使用新 kid 签发 Token；删除旧公钥后新请求立即不再信任旧 kid。验证通过仅证明发行方签发了 Token，不代表主体有权访问某业务对象。">
          仅校验 <code>Authorization</code> 头中的单个 Bearer JWT；支持 RS256 /
          ES256 显式白名单。
        </InlineNote>

        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          initialValues={DEFAULT_VALUES}
          disabled={!canManage}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <SectionHeader
            title="验证模式"
            description="选择当前应用对命中选择器请求的 JWT 校验与处置强度。"
          />
          <Form.Item
            name="mode"
            style={{ marginBottom: 8 }}
            extra={
              mode === 'PROTECT' ? (
                <Alert
                  type="warning"
                  showIcon
                  style={{ marginTop: 10 }}
                  title="强制验证要求应用 API 动态管线已启用且处于防护模式，且目标节点无已知同步失败，否则发布将被拒绝"
                />
              ) : undefined
            }
          >
            <ModeCardGroup options={MODE_CARD_OPTIONS} disabled={!canManage} />
          </Form.Item>

          <SectionHeader
            spaced
            title="校验范围（选择器）"
            badge={
              <Tag style={{ marginInlineEnd: 0 }}>
                {selectorsWatch.length} / {JWT_TRUST_LIMITS.maxSelectors}
              </Tag>
            }
            description={
              <>
                不同选择器之间为或（OR）关系，重叠时「必须携带 Token」取开启优先；路径前缀按完整路径段匹配（
                <code>/api</code> 匹配 <code>/api</code> 与{' '}
                <code>/api/orders</code>，不匹配 <code>/apix</code>
                ）；未命中选择器的请求维持原行为。
                {mode !== 'OFF' && '非关闭模式下至少需要一条选择器。'}
              </>
            }
          />

          <Form.List name="selectors">
            {(fields, { add, remove }) => (
              <div className="jz-detail-rule-box">
                {fields.length > 0 ? (
                  <>
                    <Row gutter={12} className="jz-detail-rule-header">
                      <Col xs={24} md={7}>
                        HTTP 方法
                      </Col>
                      <Col xs={24} md={4}>
                        匹配方式
                      </Col>
                      <Col xs={24} md={7}>
                        请求路径
                      </Col>
                      <Col xs={24} md={5}>
                        未携带处理
                      </Col>
                      <Col xs={24} md={1} style={{ textAlign: 'right' }} />
                    </Row>
                    {fields.map((field) => (
                      <Row
                        key={field.key}
                        gutter={[12, 8]}
                        align="middle"
                        className="jz-detail-rule-row"
                      >
                        <Col xs={24} md={7}>
                          <Form.Item
                            name={[field.name, 'methods']}
                            style={{ marginBottom: 0 }}
                            rules={[
                              {
                                required: mode !== 'OFF',
                                message: '请选择 HTTP 方法',
                              },
                            ]}
                          >
                            <Select
                              mode="multiple"
                              options={METHOD_OPTIONS}
                              placeholder="选择 HTTP 方法"
                              maxTagCount="responsive"
                              style={{ width: '100%' }}
                            />
                          </Form.Item>
                        </Col>
                        <Col xs={12} md={4}>
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
                        </Col>
                        <Col xs={24} md={7}>
                          <Form.Item
                            name={[field.name, 'path']}
                            style={{ marginBottom: 0 }}
                            rules={[
                              {
                                required: mode !== 'OFF',
                                message: '请输入路径',
                              },
                              {
                                validator: (_, v: string) => {
                                  if (!v) return Promise.resolve()
                                  if (!v.startsWith('/'))
                                    return Promise.reject(
                                      new Error('路径必须以 / 开头'),
                                    )
                                  if (v.includes('?') || v.includes('#')) {
                                    return Promise.reject(
                                      new Error('路径不得包含查询串或锚点'),
                                    )
                                  }
                                  return Promise.resolve()
                                },
                              },
                            ]}
                          >
                            <Input
                              placeholder="如 /api/orders"
                              autoComplete="off"
                            />
                          </Form.Item>
                        </Col>
                        <Col xs={20} md={5}>
                          <Form.Item
                            name={[field.name, 'token_required']}
                            style={{ marginBottom: 0 }}
                            valuePropName="checked"
                            initialValue={false}
                          >
                            <Switch
                              checkedChildren="必须携带 Token"
                              unCheckedChildren="可选"
                            />
                          </Form.Item>
                        </Col>
                        <Col xs={4} md={1} style={{ textAlign: 'right' }}>
                          <Tooltip title="删除此选择器">
                            <Button
                              type="text"
                              danger
                              icon={<MinusCircleOutlined />}
                              aria-label="删除此选择器"
                              onClick={() => remove(field.name)}
                            />
                          </Tooltip>
                        </Col>
                      </Row>
                    ))}
                  </>
                ) : (
                  <div className="jz-detail-rule-empty">
                    尚未添加校验范围选择器；点击下方按钮定义需要验证 Bearer JWT
                    的路径与方法
                  </div>
                )}
                <Button
                  block
                  type="dashed"
                  icon={<PlusOutlined />}
                  style={{ marginTop: fields.length > 0 ? 10 : 0 }}
                  disabled={fields.length >= JWT_TRUST_LIMITS.maxSelectors}
                  onClick={() =>
                    add({
                      methods: ['GET'],
                      match_type: 'prefix',
                      path: '',
                      token_required: false,
                    })
                  }
                >
                  添加选择器
                </Button>
              </div>
            )}
          </Form.List>

          <SectionHeader
            spaced
            title={`受信发行方（最多 ${JWT_TRUST_LIMITS.maxIssuers} 个）`}
            badge={
              <Tag style={{ marginInlineEnd: 0 }}>
                {issuersWatch.length} / {JWT_TRUST_LIMITS.maxIssuers}
              </Tag>
            }
            description={
              <>
                发行方（Issuer）为大小写敏感精确值且策略内唯一；Token
                的受众声明（aud）与配置的受众列表至少匹配一项；算法白名单仅
                RS256 / ES256，不由 Token 扩展。
                {mode !== 'OFF' && '非关闭模式下至少需要一个发行方。'}
              </>
            }
          />

          <Form.List name="issuers">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => {
                  const curIssuer = issuersWatch?.[field.name]
                  const keyType = curIssuer?.key_source_type ?? 'STATIC_JWKS'
                  const issuerPreview = curIssuer?.issuer?.trim()
                  const tbMode = curIssuer?.token_binding_mode ?? 'NONE'
                  return (
                    <div key={field.key} className="jz-detail-subcard">
                      <div className="jz-detail-subcard-head">
                        <div className="jz-detail-subcard-title">
                          <span className="jz-detail-subcard-index">
                            #{field.name + 1}
                          </span>
                          <Typography.Text strong style={{ fontSize: 13 }}>
                            {`发行方 #${field.name + 1}`}
                          </Typography.Text>
                          {issuerPreview && (
                            <Typography.Text
                              code
                              style={{ fontSize: 12 }}
                              ellipsis
                            >
                              {issuerPreview}
                            </Typography.Text>
                          )}
                          <Tag
                            icon={
                              keyType === 'REMOTE_JWKS' ? (
                                <LinkOutlined />
                              ) : (
                                <KeyOutlined />
                              )
                            }
                            color={
                              keyType === 'REMOTE_JWKS' ? 'geekblue' : 'cyan'
                            }
                            style={{ marginInlineEnd: 0 }}
                          >
                            {keyType === 'REMOTE_JWKS'
                              ? '远程 JWKS'
                              : '静态 JWKS'}
                          </Tag>
                          {tbMode !== 'NONE' && (
                            <Tag
                              color={
                                JWT_TOKEN_BINDING_MODE_META[tbMode]?.color ??
                                'purple'
                              }
                              style={{ marginInlineEnd: 0 }}
                            >
                              {JWT_TOKEN_BINDING_MODE_META[tbMode]?.label ??
                                tbMode}
                            </Tag>
                          )}
                        </div>
                        <Tooltip title="删除此发行方" placement="left">
                          <Button
                            type="text"
                            danger
                            size="small"
                            icon={<MinusCircleOutlined />}
                            aria-label={`删除发行方 #${field.name + 1}`}
                            onClick={() => remove(field.name)}
                          />
                        </Tooltip>
                      </div>

                      <div className="jz-detail-subcard-body">
                        <Row gutter={[16, 0]}>
                          <Col xs={24} md={10}>
                            <Form.Item
                              name={[field.name, 'issuer']}
                              label="发行方精确值（Issuer）"
                              rules={[
                                {
                                  required: mode !== 'OFF',
                                  message: '请输入发行方精确值',
                                },
                                {
                                  max: 512,
                                  message: '发行方长度不能超过 512',
                                },
                              ]}
                            >
                              <Input
                                placeholder="如 https://idp.example.com/"
                                autoComplete="off"
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={8}>
                            <Form.Item
                              name={[field.name, 'audiences']}
                              label="受众列表（Audience）"
                              rules={[
                                {
                                  required: mode !== 'OFF',
                                  message: '请至少填写一个受众',
                                },
                              ]}
                            >
                              <Select
                                mode="tags"
                                placeholder="输入后回车添加"
                                open={false}
                                tokenSeparators={[',']}
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={6}>
                            <Form.Item
                              name={[field.name, 'algorithms']}
                              label="算法白名单"
                              rules={[
                                {
                                  required: mode !== 'OFF',
                                  message: '请选择签名算法',
                                },
                              ]}
                            >
                              <Select
                                mode="multiple"
                                options={ALGORITHM_OPTIONS}
                                placeholder="RS256 / ES256"
                              />
                            </Form.Item>
                          </Col>
                        </Row>

                        <div className="jz-detail-subcard-group">
                          <div className="jz-detail-subcard-group-title">
                            验签密钥与时间校验
                          </div>
                          <Row gutter={[16, 0]}>
                            <Col xs={24} sm={14} md={12}>
                              <Form.Item
                                name={[field.name, 'key_source_type']}
                                label="密钥来源"
                                initialValue="STATIC_JWKS"
                              >
                                <Radio.Group
                                  options={[
                                    {
                                      value: 'STATIC_JWKS',
                                      label: '静态公钥 JWKS',
                                    },
                                    {
                                      value: 'REMOTE_JWKS',
                                      label: '远程 JWKS 地址',
                                    },
                                  ]}
                                  optionType="button"
                                  buttonStyle="solid"
                                  size="small"
                                />
                              </Form.Item>
                            </Col>
                            <Col xs={24} sm={10} md={6}>
                              <Form.Item
                                name={[field.name, 'clock_skew_seconds']}
                                label="时钟偏移宽限（秒）"
                                initialValue={JWT_TRUST_LIMITS.defaultClockSkew}
                                rules={[
                                  {
                                    required: mode !== 'OFF',
                                    message: '请输入时钟偏移宽限',
                                  },
                                ]}
                              >
                                <InputNumber
                                  min={0}
                                  max={JWT_TRUST_LIMITS.maxClockSkew}
                                  precision={0}
                                  style={{ width: '100%' }}
                                />
                              </Form.Item>
                            </Col>
                          </Row>

                          <Form.Item
                            noStyle
                            shouldUpdate={(
                              prev: PolicyFormValues,
                              cur: PolicyFormValues,
                            ) =>
                              prev.issuers?.[field.name]?.key_source_type !==
                              cur.issuers?.[field.name]?.key_source_type
                            }
                          >
                            {({ getFieldValue }) =>
                              getFieldValue([
                                'issuers',
                                field.name,
                                'key_source_type',
                              ]) === 'REMOTE_JWKS' ? (
                                <Form.Item
                                  name={[field.name, 'url']}
                                  label="远程 JWKS 地址"
                                  extra="仅 HTTPS；默认拒绝私网/回环/云元数据地址，企业内网 IdP 须由系统管理员在系统设置中的远程 JWKS 白名单显式登记"
                                  rules={[
                                    {
                                      required: mode !== 'OFF',
                                      message: '请输入远程 JWKS 地址',
                                    },
                                    {
                                      validator: (_, v: string) => {
                                        if (!v) return Promise.resolve()
                                        if (!/^https:\/\//i.test(v.trim())) {
                                          return Promise.reject(
                                            new Error('仅允许 HTTPS 地址'),
                                          )
                                        }
                                        return Promise.resolve()
                                      },
                                    },
                                  ]}
                                >
                                  <Input
                                    prefix={<LinkOutlined />}
                                    placeholder="https://idp.example.com/.well-known/jwks.json"
                                    autoComplete="off"
                                  />
                                </Form.Item>
                              ) : (
                                <Form.Item
                                  name={[field.name, 'jwks']}
                                  label="静态公钥 JWKS"
                                  extra={`仅公钥（≤${JWT_TRUST_LIMITS.maxJWKSBytes / 1024} KiB、≤${JWT_TRUST_LIMITS.maxJWKSKeys} 个公钥；RSA≥${JWT_TRUST_LIMITS.minRSAKeyBits} 位、EC 仅 P-256）；粘贴私钥将立即拒绝并清空`}
                                  rules={[
                                    {
                                      validator: (_, v: string) => {
                                        if (!v || !v.trim()) {
                                          return mode !== 'OFF'
                                            ? Promise.reject(
                                                new Error(
                                                  '请粘贴公钥 JWKS JSON',
                                                ),
                                              )
                                            : Promise.resolve()
                                        }
                                        const err = validateStaticJwks(v)
                                        return err
                                          ? Promise.reject(new Error(err))
                                          : Promise.resolve()
                                      },
                                    },
                                  ]}
                                >
                                  <Input.TextArea
                                    rows={4}
                                    className="jz-detail-code-textarea"
                                    placeholder='{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}'
                                    onChange={(e) =>
                                      onJwksChange(field.name, e.target.value)
                                    }
                                  />
                                </Form.Item>
                              )
                            }
                          </Form.Item>
                        </div>

                        <Row gutter={[16, 0]}>
                          <Col xs={24} md={10}>
                            <Form.Item
                              name={[field.name, 'tenant_claim']}
                              label="租户声明名（可选）"
                              extra="仅在验证通过后读取，不自动猜测"
                              rules={[
                                {
                                  max: JWT_TRUST_LIMITS.maxTenantClaimLen,
                                  message: `租户声明名长度不能超过 ${JWT_TRUST_LIMITS.maxTenantClaimLen}`,
                                },
                                {
                                  pattern: /^[A-Za-z_][A-Za-z0-9_-]*$/,
                                  message:
                                    '字母/数字/下划线/短横线，字母或下划线开头',
                                },
                              ]}
                            >
                              <Input
                                placeholder="如 tenant_id"
                                autoComplete="off"
                              />
                            </Form.Item>
                          </Col>
                          <Col xs={24} md={14}>
                            <Form.Item
                              name={[field.name, 'role_claims']}
                              label="角色声明名（可选）"
                              extra={`仅在验证通过后读取，不自动猜测；最多 ${JWT_TRUST_LIMITS.maxRoleClaims} 项`}
                              rules={[
                                {
                                  validator: (
                                    _,
                                    value: string[] | undefined,
                                  ) => {
                                    if (!value || value.length === 0)
                                      return Promise.resolve()
                                    const normalized: string[] = []
                                    const seen = new Set<string>()
                                    for (const raw of value) {
                                      const trimmed = raw.trim()
                                      if (!trimmed) continue
                                      if (
                                        trimmed.length >
                                          JWT_TRUST_LIMITS.maxRoleClaimLen ||
                                        !/^[A-Za-z_][A-Za-z0-9_-]{0,63}$/.test(
                                          trimmed,
                                        )
                                      ) {
                                        return Promise.reject(
                                          new Error(
                                            `角色声明名格式不合法（字母/数字/下划线/短横线，字母或下划线开头，最长 ${JWT_TRUST_LIMITS.maxRoleClaimLen} 字符）`,
                                          ),
                                        )
                                      }
                                      if (!seen.has(trimmed)) {
                                        seen.add(trimmed)
                                        normalized.push(trimmed)
                                      }
                                    }
                                    if (
                                      normalized.length >
                                      JWT_TRUST_LIMITS.maxRoleClaims
                                    ) {
                                      return Promise.reject(
                                        new Error(
                                          `角色声明名最多 ${JWT_TRUST_LIMITS.maxRoleClaims} 项`,
                                        ),
                                      )
                                    }
                                    return Promise.resolve()
                                  },
                                },
                              ]}
                            >
                              <Select
                                mode="tags"
                                placeholder="如 roles、groups，输入后回车添加"
                                open={false}
                                tokenSeparators={[',']}
                              />
                            </Form.Item>
                          </Col>
                        </Row>
                        <div className="jz-detail-subcard-group">
                          <div className="jz-detail-subcard-group-title">
                            令牌持有证明绑定（DPoP / mTLS）
                          </div>
                          <Row gutter={[16, 0]}>
                            <Col xs={24} md={12}>
                              <Form.Item
                                name={[field.name, 'token_binding_mode']}
                                label="绑定模式"
                                initialValue="NONE"
                                extra={
                                  JWT_TOKEN_BINDING_MODE_META[tbMode]
                                    ?.description
                                }
                              >
                                <Select options={TOKEN_BINDING_MODE_OPTIONS} />
                              </Form.Item>
                            </Col>
                          </Row>

                          <Form.Item
                            noStyle
                            shouldUpdate={(
                              prev: PolicyFormValues,
                              cur: PolicyFormValues,
                            ) =>
                              prev.issuers?.[field.name]?.token_binding_mode !==
                              cur.issuers?.[field.name]?.token_binding_mode
                            }
                          >
                            {({ getFieldValue }) => {
                              const currentBindingMode =
                                (getFieldValue([
                                  'issuers',
                                  field.name,
                                  'token_binding_mode',
                                ]) as JwtTokenBindingMode | undefined) ?? 'NONE'
                              const showDPoP =
                                isDPoPBindingMode(currentBindingMode)
                              const showMTLS =
                                isMTLSBindingMode(currentBindingMode)
                              if (!showDPoP && !showMTLS) return null
                              return (
                                <>
                                  {showDPoP && (
                                    <Row gutter={[16, 0]}>
                                      <Col xs={24} sm={12} md={6}>
                                        <Form.Item
                                          name={[
                                            field.name,
                                            'dpop_require_nonce',
                                          ]}
                                          label="要求 DPoP-Nonce 挑战"
                                          valuePropName="checked"
                                          initialValue={false}
                                        >
                                          <Switch
                                            checkedChildren="开启"
                                            unCheckedChildren="关闭"
                                          />
                                        </Form.Item>
                                      </Col>
                                      <Col xs={24} sm={12} md={6}>
                                        <Form.Item
                                          name={[
                                            field.name,
                                            'dpop_max_proof_age_seconds',
                                          ]}
                                          label="证明最大有效期（秒）"
                                          initialValue={
                                            JWT_TRUST_LIMITS.defaultDPoPMaxProofAge
                                          }
                                          rules={[
                                            {
                                              type: 'number',
                                              min: JWT_TRUST_LIMITS.minDPoPMaxProofAge,
                                              max: JWT_TRUST_LIMITS.maxDPoPMaxProofAge,
                                              message: `须在 ${JWT_TRUST_LIMITS.minDPoPMaxProofAge}–${JWT_TRUST_LIMITS.maxDPoPMaxProofAge} 秒之间`,
                                            },
                                          ]}
                                        >
                                          <InputNumber
                                            min={
                                              JWT_TRUST_LIMITS.minDPoPMaxProofAge
                                            }
                                            max={
                                              JWT_TRUST_LIMITS.maxDPoPMaxProofAge
                                            }
                                            precision={0}
                                            style={{ width: '100%' }}
                                          />
                                        </Form.Item>
                                      </Col>
                                      <Col xs={24} sm={12} md={6}>
                                        <Form.Item
                                          name={[
                                            field.name,
                                            'dpop_nonce_ttl_seconds',
                                          ]}
                                          label="Nonce 有效期（秒）"
                                          initialValue={
                                            JWT_TRUST_LIMITS.defaultDPoPNonceTTL
                                          }
                                          rules={[
                                            {
                                              type: 'number',
                                              min: JWT_TRUST_LIMITS.minDPoPNonceTTL,
                                              max: JWT_TRUST_LIMITS.maxDPoPNonceTTL,
                                              message: `须在 ${JWT_TRUST_LIMITS.minDPoPNonceTTL}–${JWT_TRUST_LIMITS.maxDPoPNonceTTL} 秒之间`,
                                            },
                                          ]}
                                        >
                                          <InputNumber
                                            min={
                                              JWT_TRUST_LIMITS.minDPoPNonceTTL
                                            }
                                            max={
                                              JWT_TRUST_LIMITS.maxDPoPNonceTTL
                                            }
                                            precision={0}
                                            style={{ width: '100%' }}
                                          />
                                        </Form.Item>
                                      </Col>
                                      <Col xs={24} sm={12} md={6}>
                                        <Form.Item
                                          name={[
                                            field.name,
                                            'dpop_allowed_algs',
                                          ]}
                                          label="允许的 DPoP 算法"
                                          initialValue={[...JWT_DPOP_ALGS]}
                                        >
                                          <Select
                                            mode="multiple"
                                            options={JWT_DPOP_ALG_OPTIONS}
                                            placeholder="ES256 / RS256 / EdDSA"
                                          />
                                        </Form.Item>
                                      </Col>
                                    </Row>
                                  )}
                                  {showMTLS && (
                                    <Typography.Paragraph
                                      type="secondary"
                                      style={{
                                        fontSize: 12,
                                        marginBottom: 10,
                                      }}
                                    >
                                      mTLS 证书绑定依据 RFC 8705 核验已通过 TLS
                                      信任链校验的客户端证书指纹（
                                      <code>cnf.x5t#S256</code>
                                      ），未验链证书将被忽略。
                                    </Typography.Paragraph>
                                  )}
                                </>
                              )
                            }}
                          </Form.Item>
                        </div>
                      </div>
                    </div>
                  )
                })}
                <Button
                  block
                  type="dashed"
                  icon={<PlusOutlined />}
                  disabled={fields.length >= JWT_TRUST_LIMITS.maxIssuers}
                  onClick={() =>
                    add({
                      issuer: '',
                      audiences: [],
                      algorithms: ['RS256'],
                      key_source_type: 'STATIC_JWKS',
                      jwks: '',
                      url: '',
                      clock_skew_seconds: JWT_TRUST_LIMITS.defaultClockSkew,
                      tenant_claim: '',
                      role_claims: [],
                      token_binding_mode: 'NONE',
                      dpop_require_nonce: false,
                      dpop_max_proof_age_seconds:
                        JWT_TRUST_LIMITS.defaultDPoPMaxProofAge,
                      dpop_nonce_ttl_seconds:
                        JWT_TRUST_LIMITS.defaultDPoPNonceTTL,
                      dpop_allowed_algs: [...JWT_DPOP_ALGS],
                    })
                  }
                >
                  添加发行方
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
                    max: JWT_TRUST_LIMITS.maxReasonLen,
                    message: `变更理由不能超过 ${JWT_TRUST_LIMITS.maxReasonLen} 字符`,
                  },
                ]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="说明本次变更原因，如：接入新的身份发行方"
                />
              </Form.Item>
              <div className="jz-detail-audit-submit-actions">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  <SafetyCertificateOutlined style={{ marginRight: 6 }} />
                  本页面不提供粘贴真实业务 Token
                  的在线调试；验证排障请通过安全事件详情中的 JWT
                  验证信息与发布预检完成。
                </Typography.Text>
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
              </div>
            </div>
          )}
        </Form>
      </Card>

      {preflight && (
        <div ref={preflightRef}>
          <PreflightResultCard
            publishable={preflight.publishable}
            summaryDescription="预检为管理端视角（含受限连通性检查），不代表各网关节点实际可达；节点实际密钥状态以发布回执为准。预检不保存、不发布。"
            checks={preflight.checks}
            checkNameLabels={JWT_TRUST_CHECK_NAME_LABELS}
            checkStatusMeta={JWT_TRUST_CHECK_STATUS_META}
            footerNote="说明：远程 JWKS 连通性为管理端探测结果；「节点状态与能力」为各目标节点的注册与同步回执状态，已知同步失败的节点将阻断强制验证策略发布（防静默降级，避免部分节点未生效）。"
          />
        </div>
      )}
    </div>
  )
}
