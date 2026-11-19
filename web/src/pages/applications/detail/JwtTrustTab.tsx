import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Form,
  Input,
  InputNumber,
  List,
  Radio,
  Select,
  Space,
  Spin,
  Switch,
  Tooltip,
  Typography,
} from 'antd'
import { MinusCircleOutlined, PlusOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  JWT_TRUST_LIMITS,
  jwtTrustApi,
  jwksHasPrivateMaterial,
  validateStaticJwks,
} from '../../../api/jwtTrust'
import type {
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
  JWT_TRUST_CHECK_NAME_LABELS,
  JWT_TRUST_CHECK_STATUS_META,
  JWT_TRUST_MODE_META,
  JWT_TRUST_STATE_META,
  mapJwtTrustFieldErrorPath,
} from '../../../utils/jwtTrust'

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

const MODE_OPTIONS = [
  { value: 'OFF', label: '关闭（不校验 Token）' },
  { value: 'OBSERVE', label: '观察（校验并记录，不拦截）' },
  { value: 'PROTECT', label: '强制验证（非法 Token 401 / 验证不可用 503）' },
]

/** 表单值（选择器路径二选一折叠为 match_type+path；issuer 密钥来源拍平为三个字段） */
interface SelectorFormValue {
  methods: string[]
  match_type: 'exact' | 'prefix'
  path: string
  token_required: boolean
}

interface IssuerFormValue {
  issuer: string
  audiences: string[]
  algorithms: string[]
  key_source_type: 'STATIC_JWKS' | 'REMOTE_JWKS'
  jwks?: string
  url?: string
  clock_skew_seconds: number
  tenant_claim?: string
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

function toIssuers(values: IssuerFormValue[]): JwtTrustIssuer[] {
  return (values ?? []).map((is) => ({
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
  }))
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
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'jwt_trust.manage')
  const [form] = Form.useForm<PolicyFormValues>()
  const mode = Form.useWatch('mode', form) ?? 'OFF'
  const [preflight, setPreflight] = useState<JwtTrustPreflightResult | null>(
    null,
  )

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
    onSuccess: (data) => setPreflight(data),
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
      <div style={{ display: 'flex', justifyContent: 'center', padding: 32 }}>
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
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card title="策略状态">
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用范围">{appCode}</Descriptions.Item>
          <Descriptions.Item label="配置状态">
            <StatusTag value={summary.state} map={JWT_TRUST_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={JWT_TRUST_MODE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="草稿版本">
            {summary.draft_version > 0 ? `v${summary.draft_version}` : '无草稿'}
          </Descriptions.Item>
          <Descriptions.Item label="已生效版本">
            {summary.published_version > 0
              ? `v${summary.published_version}`
              : '未随发布下发'}
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
            style={{ marginTop: 12 }}
            message="草稿已保存，尚未生效"
            description={`草稿 v${summary.draft_version} 与已生效版本 v${summary.published_version} 存在差异；保存草稿不等于线上生效，需经配置发布并获节点回执后才生效。发布失败时旧版本继续运行。`}
          />
        )}
        {summary.state === 'PUBLISHED' &&
          effectiveMode &&
          effectiveMode !== 'OFF' && (
            <Alert
              type="success"
              showIcon
              style={{ marginTop: 12 }}
              message={`已生效：${JWT_TRUST_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="节点级密钥状态与同步结果以发布预检和节点回执为准；部分节点同步失败时发布会被拒绝并保留旧版本（部分节点未生效）。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 12 }}
            message="尚未配置 JWT 信任策略，当前不校验业务 Token"
            description="默认关闭，不改变既有流量；密钥不可用、部分节点未生效等运行态以预检与发布回执为准。"
          />
        )}
      </Card>

      <Card
        title="策略配置"
        extra={
          canManage && (
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
          message="仅校验 Authorization 头中的单个 Bearer JWT；支持 RS256 / ES256 显式白名单。"
          description="密钥轮换条件：上游须先在 JWKS 中公布新 kid 对应公钥，再开始使用新 kid 签发 Token；删除旧公钥后新请求立即不再信任旧 kid。验证通过仅证明发行方签发了 Token，不代表主体有权访问某业务对象。"
        />
        <Form<PolicyFormValues>
          form={form}
          layout="vertical"
          initialValues={DEFAULT_VALUES}
          disabled={!canManage}
          onFinish={(values) => saveMutation.mutate(values)}
        >
          <Form.Item
            name="mode"
            label="验证模式"
            extra={
              mode === 'PROTECT' ? (
                <Typography.Text type="warning">
                  强制验证要求应用 API 动态管线已启用且处于防护模式，且目标节点无已知同步失败，否则发布将被拒绝
                </Typography.Text>
              ) : undefined
            }
          >
            <Radio.Group options={MODE_OPTIONS} />
          </Form.Item>

          <Typography.Title level={5} style={{ marginTop: 0 }}>
            校验范围（选择器）
          </Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            不同选择器之间为或（OR）关系，重叠时「必须携带 Token」取开启优先；路径前缀按完整路径段匹配（/api 匹配 /api 与
            /api/orders，不匹配 /apix）；未命中选择器的请求维持原行为。
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
                        placeholder="方法"
                        style={{ width: 220 }}
                      />
                    </Form.Item>
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
                        style={{ width: 240 }}
                        autoComplete="off"
                      />
                    </Form.Item>
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
              </>
            )}
          </Form.List>

          <Typography.Title level={5} style={{ marginTop: 24 }}>
            受信发行方（最多 {JWT_TRUST_LIMITS.maxIssuers} 个）
          </Typography.Title>
          <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
            发行方（Issuer）为大小写敏感精确值且策略内唯一；Token 的受众声明（aud）与配置的受众列表至少匹配一项；算法白名单仅 RS256 / ES256，不由 Token 扩展。
            {mode !== 'OFF' && '非关闭模式下至少需要一个发行方。'}
          </Typography.Paragraph>
          <Form.List name="issuers">
            {(fields, { add, remove }) => (
              <>
                {fields.map((field) => (
                  <Card
                    key={field.key}
                    size="small"
                    style={{ marginBottom: 12 }}
                    title={`发行方 #${field.name + 1}`}
                    extra={
                      <Tooltip title="删除此发行方">
                        <Button
                          type="text"
                          danger
                          icon={<MinusCircleOutlined />}
                          aria-label={`删除发行方 #${field.name + 1}`}
                          onClick={() => remove(field.name)}
                        />
                      </Tooltip>
                    }
                  >
                    <Space size="middle" wrap style={{ display: 'flex' }}>
                      <Form.Item
                        name={[field.name, 'issuer']}
                        label="发行方精确值（Issuer）"
                        style={{ width: 320 }}
                        rules={[
                          {
                            required: mode !== 'OFF',
                            message: '请输入发行方精确值',
                          },
                          { max: 512, message: '发行方长度不能超过 512' },
                        ]}
                      >
                        <Input
                          placeholder="如 https://idp.example.com/"
                          autoComplete="off"
                        />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'audiences']}
                        label="受众列表（Audience）"
                        style={{ minWidth: 260 }}
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
                      <Form.Item
                        name={[field.name, 'algorithms']}
                        label="算法白名单"
                        style={{ width: 200 }}
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
                    </Space>
                    <Space size="middle" wrap style={{ display: 'flex' }}>
                      <Form.Item
                        name={[field.name, 'key_source_type']}
                        label="密钥来源"
                        initialValue="STATIC_JWKS"
                      >
                        <Radio.Group
                          options={[
                            { value: 'STATIC_JWKS', label: '静态公钥 JWKS' },
                            { value: 'REMOTE_JWKS', label: '远程 JWKS 地址' },
                          ]}
                          optionType="button"
                          buttonStyle="solid"
                          size="small"
                        />
                      </Form.Item>
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
                          style={{ width: 140 }}
                        />
                      </Form.Item>
                      <Form.Item
                        name={[field.name, 'tenant_claim']}
                        label="租户声明名（可选）"
                        extra="仅在验证通过后读取，不自动猜测"
                        style={{ width: 220 }}
                        rules={[
                          {
                            pattern: /^[A-Za-z_][A-Za-z0-9_-]*$/,
                            message:
                              '字母/数字/下划线/短横线，字母或下划线开头',
                          },
                        ]}
                      >
                        <Input placeholder="如 tenant_id" autoComplete="off" />
                      </Form.Item>
                    </Space>
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
                                          new Error('请粘贴公钥 JWKS JSON'),
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
                              placeholder='{"keys":[{"kty":"RSA","kid":"...","n":"...","e":"AQAB"}]}'
                              style={{ fontFamily: 'monospace', fontSize: 12 }}
                              onChange={(e) =>
                                onJwksChange(field.name, e.target.value)
                              }
                            />
                          </Form.Item>
                        )
                      }
                    </Form.Item>
                  </Card>
                ))}
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
                    })
                  }
                >
                  添加发行方
                </Button>
              </>
            )}
          </Form.List>

          {canManage && (
            <Form.Item
              name="reason"
              label="变更理由"
              style={{ marginTop: 24, maxWidth: 720 }}
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
          )}
        </Form>
      </Card>

      {preflight && (
        <Card title="发布预检结果">
          <Alert
            type={preflight.publishable ? 'success' : 'error'}
            showIcon
            style={{ marginBottom: 16 }}
            message={
              preflight.publishable
                ? '预检通过，可经配置发布通道发布'
                : '存在未通过项，发布链路将以同口径拒绝'
            }
            description="预检为管理端视角（含受限连通性检查），不代表各网关节点实际可达；节点实际密钥状态以发布回执为准。预检不保存、不发布。"
          />
          <List
            size="small"
            dataSource={preflight.checks}
            renderItem={(c) => (
              <List.Item>
                <Space direction="vertical" size={2} style={{ width: '100%' }}>
                  <Space>
                    <StatusTag
                      value={c.status}
                      map={JWT_TRUST_CHECK_STATUS_META}
                    />
                    <Typography.Text strong>
                      {JWT_TRUST_CHECK_NAME_LABELS[c.name] ?? c.name}
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
          <Typography.Paragraph
            type="secondary"
            style={{ fontSize: 12, marginTop: 12 }}
          >
            说明：远程 JWKS
            连通性为管理端探测结果；「节点状态与能力」为各目标节点的注册与同步回执状态，已知同步失败的节点将阻断强制验证策略发布（防静默降级，避免部分节点未生效）。
          </Typography.Paragraph>
        </Card>
      )}

      {canManage && (
        <Typography.Paragraph type="secondary" style={{ fontSize: 12 }}>
          本页面不提供粘贴真实业务 Token
          的在线调试；验证排障请通过安全事件详情中的 JWT
          验证信息与发布预检完成。
        </Typography.Paragraph>
      )}
    </Space>
  )
}
