import { useEffect, useMemo } from 'react'
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
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from 'antd'
import {
  CodeOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import {
  CLIENT_SIDE_LIMITS,
  clientSideApi,
  type ClientSideCspMode,
  type ClientSideMode,
} from '../../../api/clientSide'
import QueryErrorAlert from '../../../components/QueryErrorAlert'
import StatusTag from '../../../components/StatusTag'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  buildCspPreview,
  CLIENT_SIDE_CSP_MODE_META,
  CLIENT_SIDE_MODE_META,
  CLIENT_SIDE_STATE_META,
  mapClientSideFieldErrorPath,
  validateCspOrigins,
  validateCustomCspDirectives,
  validateSensitivePaths,
} from '../../../utils/clientSide'
import {
  InlineNote,
  ModeCardGroup,
  SectionHeader,
  type ModeCardOption,
} from './DetailTabPrimitives'
import './detailTab.css'

const MODE_CARD_OPTIONS: ModeCardOption<ClientSideMode>[] = [
  {
    value: 'OFF',
    label: '关闭（不启用客户端防护）',
    description: '透传 HTML 响应，不注入 CSP 响应头与探针，不扫描脚本清单',
    badge: '默认',
    tone: 'neutral',
  },
  {
    value: 'OBSERVE',
    label: '观察（发现脚本与告警，不剥离）',
    description:
      '自动梳理页面脚本清单与 SRI 指纹、接收 CSP/探针告警，不改写或阻断页面脚本',
    badge: '推荐先用',
    badgeColor: 'blue',
    tone: 'info',
  },
  {
    value: 'PROTECT',
    label: '强制执行（防篡改与未授权剥离）',
    description:
      '在观察基础上支持强制 CSP 与敏感页探针，并可剥离未授权或 SRI 篡改的外链脚本',
    badge: '在线防护',
    badgeColor: 'green',
    tone: 'success',
  },
]

const CSP_MODE_OPTIONS: { value: ClientSideCspMode; label: string }[] = [
  { value: 'OFF', label: '关闭（不注入 CSP 头）' },
  {
    value: 'REPORT_ONLY',
    label: '学习上报（Content-Security-Policy-Report-Only）',
  },
  { value: 'ENFORCE', label: '强制执行（Content-Security-Policy）' },
]

interface PolicyFormValues {
  mode: ClientSideMode
  csp_mode: ClientSideCspMode
  sensitive_paths: string[]
  probe_enabled: boolean
  strip_unauthorized_scripts: boolean
  allowed_script_origins: string[]
  allowed_connect_origins: string[]
  allowed_form_origins: string[]
  custom_csp_directives: string
  reason: string
}

const DEFAULT_VALUES: PolicyFormValues = {
  mode: 'OFF',
  csp_mode: 'OFF',
  sensitive_paths: [],
  probe_enabled: false,
  strip_unauthorized_scripts: false,
  allowed_script_origins: ["'self'"],
  allowed_connect_origins: ["'self'"],
  allowed_form_origins: ["'self'"],
  custom_csp_directives: '',
  reason: '',
}

function cleanStringList(items: string[] | undefined): string[] {
  return Array.from(
    new Set((items ?? []).map((v) => v.trim()).filter(Boolean)),
  )
}

export default function ClientSideTab({
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
  const canManage = hasPermission(permissions, 'client_side.manage')
  const [form] = Form.useForm<PolicyFormValues>()

  const modeWatch = Form.useWatch('mode', form) ?? 'OFF'
  const cspModeWatch = Form.useWatch('csp_mode', form) ?? 'OFF'
  const probeEnabledWatch = Form.useWatch('probe_enabled', form) ?? false
  const stripScriptsWatch =
    Form.useWatch('strip_unauthorized_scripts', form) ?? false
  const scriptOriginsWatch = Form.useWatch('allowed_script_origins', form)
  const connectOriginsWatch = Form.useWatch('allowed_connect_origins', form)
  const formOriginsWatch = Form.useWatch('allowed_form_origins', form)
  const customCspWatch = Form.useWatch('custom_csp_directives', form) ?? ''

  const cspPreview = useMemo(
    () =>
      buildCspPreview({
        mode: modeWatch,
        csp_mode: cspModeWatch,
        probe_enabled: probeEnabledWatch,
        allowed_script_origins: scriptOriginsWatch ?? [],
        allowed_connect_origins: connectOriginsWatch ?? [],
        allowed_form_origins: formOriginsWatch ?? [],
        custom_csp_directives: customCspWatch,
      }),
    [
      modeWatch,
      cspModeWatch,
      probeEnabledWatch,
      scriptOriginsWatch,
      connectOriginsWatch,
      formOriginsWatch,
      customCspWatch,
    ],
  )

  const policyQuery = useQuery({
    queryKey: ['client-side-policy', appId],
    queryFn: () => clientSideApi.getPolicy(appId),
  })
  const policy = policyQuery.data?.policy
  const summary = policyQuery.data?.summary

  useEffect(() => {
    if (!policy) return
    form.setFieldsValue({
      mode: policy.mode ?? 'OFF',
      csp_mode: policy.csp_mode ?? 'OFF',
      sensitive_paths: policy.sensitive_paths ?? [],
      probe_enabled: Boolean(policy.probe_enabled),
      strip_unauthorized_scripts: Boolean(policy.strip_unauthorized_scripts),
      allowed_script_origins: policy.allowed_script_origins ?? [],
      allowed_connect_origins: policy.allowed_connect_origins ?? [],
      allowed_form_origins: policy.allowed_form_origins ?? [],
      custom_csp_directives: policy.custom_csp_directives ?? '',
      reason: '',
    })
  }, [policy, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({
      queryKey: ['client-side-policy', appId],
    })

  const saveMutation = useMutation({
    mutationFn: (values: PolicyFormValues) =>
      clientSideApi.updatePolicy(appId, {
        mode: values.mode,
        expected_version: policy?.version ?? 0,
        csp_mode: values.csp_mode,
        sensitive_paths: cleanStringList(values.sensitive_paths),
        probe_enabled: Boolean(values.probe_enabled),
        strip_unauthorized_scripts: Boolean(values.strip_unauthorized_scripts),
        allowed_script_origins: cleanStringList(values.allowed_script_origins),
        allowed_connect_origins: cleanStringList(
          values.allowed_connect_origins,
        ),
        allowed_form_origins: cleanStringList(values.allowed_form_origins),
        custom_csp_directives: (values.custom_csp_directives ?? '').trim(),
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
          const name = mapClientSideFieldErrorPath(d.field)
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
        message="加载客户端供应链安全策略失败"
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
              <Link to="/client-side-security">
                <Button type="link" size="small" style={{ paddingInline: 0 }}>
                  查看脚本清单与违规告警
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
            <StatusTag value={summary.state} map={CLIENT_SIDE_STATE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="当前模式">
            <StatusTag value={policy.mode} map={CLIENT_SIDE_MODE_META} />
          </Descriptions.Item>
          <Descriptions.Item label="CSP 模式">
            <StatusTag
              value={policy.csp_mode}
              map={CLIENT_SIDE_CSP_MODE_META}
            />
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
              title={`已生效：${CLIENT_SIDE_MODE_META[effectiveMode]?.label ?? effectiveMode}（版本 v${summary.published_version}）`}
              description="客户端供应链安全策略已随最近成功发布快照下发至网关节点运行。"
            />
          )}
        {summary.state === 'NOT_CONFIGURED' && (
          <Alert
            type="info"
            showIcon
            style={{ marginTop: 14 }}
            title="尚未配置客户端供应链安全策略，当前维持默认透传行为"
            description="支持 PCI DSS 4.0 6.4.3 脚本资产清点与授权台账、11.6.1 篡改与 CSP 违规监测及敏感表单页零依赖防窃取探针。"
          />
        )}
      </Card>

      <Card
        className="jz-detail-card"
        title="客户端供应链安全与 CSP 策略"
        extra={
          <Space size={6}>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              PCI DSS 4.0 6.4.3 / 11.6.1
            </Tag>
            <Tag style={{ marginInlineEnd: 0 }}>Magecart 防护 · 本地探针</Tag>
          </Space>
        }
      >
        <InlineNote tooltip="预留端点 /_wdsp/csp/v1/report 与 /_wdsp/cs/v1/probe.js 始终由网关本地处理，绝不反向代理至源站；HTML 脚本扫描仅覆盖 2xx 未压缩 text/html（<= 1 MiB），超大或压缩流式响应如实透传。">
          网关本地内置 CSP 上报接收端点（
          <Typography.Text code style={{ fontSize: 12 }}>
            {CLIENT_SIDE_LIMITS.cspReportEndpoint}
          </Typography.Text>
          ）与零依赖探针（
          <Typography.Text code style={{ fontSize: 12 }}>
            {CLIENT_SIDE_LIMITS.probeEndpoint}
          </Typography.Text>
          ），探针仅监测动态脚本注入与跨源外传目标，绝不读取密码、表单输入值或
          Cookie。
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
            description="控制当前应用对浏览器端脚本资产的发现、完整性比对与未授权脚本剥离强度。"
          />
          <Form.Item name="mode" style={{ marginBottom: 8 }}>
            <ModeCardGroup options={MODE_CARD_OPTIONS} disabled={!canManage} />
          </Form.Item>

          <SectionHeader
            spaced
            title="内容安全策略（CSP）与主动防护"
            description="配置网关注入的 CSP 模式、敏感表单页防窃取探针以及未授权外链脚本剥离开关。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="csp_mode"
                label="CSP 响应头模式"
                rules={[{ required: true, message: '请选择 CSP 模式' }]}
                extra="建议先使用「学习上报（Report-Only）」收集站点违规报告，确认无误报后再切换「强制执行（Enforce）」"
              >
                <Select options={CSP_MODE_OPTIONS} />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={[16, 12]} style={{ marginBottom: 12 }}>
            <Col xs={24} md={12}>
              <div
                className={`jz-detail-switch-tile${probeEnabledWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="probe_enabled"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>敏感表单页防窃取探针</span>
                      <span className="jz-detail-switch-desc">
                        在下方「敏感页面路径」命中的 HTML 中自动注入带 SRI
                        摘要的本地探针，监测动态 &lt;script&gt; 注入与跨源外传（绝不读取密码或表单值）
                      </span>
                    </>
                  }
                >
                  <Switch />
                </Form.Item>
              </div>
            </Col>
            <Col xs={24} md={12}>
              <div
                className={`jz-detail-switch-tile${stripScriptsWatch ? ' jz-detail-switch-tile--active' : ''}`}
              >
                <Form.Item
                  name="strip_unauthorized_scripts"
                  valuePropName="checked"
                  className="jz-detail-switch-form-item"
                  label={
                    <>
                      <span>剥离未授权外链脚本</span>
                      <span className="jz-detail-switch-desc">
                        仅在「强制执行（PROTECT）」模式下生效：响应下发前安全移除未授权或
                        SRI 完整性篡改的外链 &lt;script&gt; 标签
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
            title="敏感路径与允许来源白名单"
            description={`敏感路径与每项来源白名单上限均为 ${CLIENT_SIDE_LIMITS.maxOrigins} 条；自定义指令上限 ${CLIENT_SIDE_LIMITS.maxCustomDirectivesLen} 字符且严禁换行符。`}
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="sensitive_paths"
                label="敏感页面路径（用于探针注入与重点监测）"
                extra={`必须以 / 开头，支持精确或路径段前缀匹配（如 /login、/checkout、/pay），最多 ${CLIENT_SIDE_LIMITS.maxSensitivePaths} 条`}
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateSensitivePaths(val)
                      return err ? Promise.reject(new Error(err)) : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="输入以 / 开头的路径后回车，如 /login、/checkout"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="allowed_script_origins"
                label="允许脚本来源（script-src）"
                extra="输入 CSP 来源后回车，如 'self'、https://cdn.example.com"
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateCspOrigins(val, '允许脚本来源')
                      return err ? Promise.reject(new Error(err)) : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 'self'、https://cdn.example.com"
                />
              </Form.Item>
            </Col>
          </Row>

          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="allowed_connect_origins"
                label="允许数据外传目标（connect-src）"
                extra="限制浏览器 fetch / XHR / sendBeacon 目标源，如 'self'、https://api.example.com"
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateCspOrigins(val, '允许数据外传目标')
                      return err ? Promise.reject(new Error(err)) : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 'self'、https://api.example.com"
                />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="allowed_form_origins"
                label="允许表单提交目标（form-action）"
                extra="限制支付/登录表单提交目标源，防止表单劫持，如 'self'"
                rules={[
                  {
                    validator: (_, val?: string[]) => {
                      const err = validateCspOrigins(val, '允许表单提交目标')
                      return err ? Promise.reject(new Error(err)) : Promise.resolve()
                    },
                  },
                ]}
              >
                <Select
                  mode="tags"
                  open={false}
                  tokenSeparators={[',']}
                  placeholder="如 'self'、https://pay.example.com"
                />
              </Form.Item>
            </Col>
          </Row>

          <Form.Item
            name="custom_csp_directives"
            label="自定义附加 CSP 指令（可选）"
            extra={`以分号分隔的附加指令（如 object-src 'none'; base-uri 'self'; frame-ancestors 'none'），上限 ${CLIENT_SIDE_LIMITS.maxCustomDirectivesLen} 字符，禁止换行`}
            rules={[
              {
                validator: (_, val?: string) => {
                  const err = validateCustomCspDirectives(val)
                  return err ? Promise.reject(new Error(err)) : Promise.resolve()
                },
              },
            ]}
          >
            <Input.TextArea
              className="jz-detail-code-textarea"
              rows={2}
              placeholder="如 object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
            />
          </Form.Item>

          <SectionHeader
            spaced
            title="编译后 CSP 响应头实时预览"
            badge={
              cspPreview.active && cspPreview.headerName ? (
                <Tag
                  color={cspModeWatch === 'ENFORCE' ? 'green' : 'blue'}
                  style={{ marginInlineEnd: 0 }}
                >
                  {cspPreview.headerName}
                </Tag>
              ) : (
                <Tag style={{ marginInlineEnd: 0 }}>未下发</Tag>
              )
            }
            description="展示当前表单配置实际编译生成的 HTTP 响应头（只读预览），开启防窃取探针时会自动保障 script-src 与 connect-src 包含 'self'。"
          />
          <div
            data-testid="csp-header-preview"
            style={{
              background: '#f8fafd',
              border: '1px solid #dce3f0',
              borderRadius: 8,
              padding: '12px 14px',
              marginBottom: 8,
            }}
          >
            {cspPreview.active && cspPreview.headerName ? (
              <Space orientation="vertical" size={6} style={{ width: '100%' }}>
                <Typography.Text
                  strong
                  style={{
                    fontSize: 12,
                    color: '#334155',
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                  }}
                >
                  {cspPreview.headerName}:
                </Typography.Text>
                <pre
                  style={{
                    margin: 0,
                    padding: '8px 10px',
                    background: '#ffffff',
                    border: '1px solid #e6ebf5',
                    borderRadius: 6,
                    fontSize: 12,
                    lineHeight: 1.55,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    fontFamily:
                      'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace',
                    color: '#0f172a',
                  }}
                >
                  {cspPreview.headerValue}
                </pre>
              </Space>
            ) : (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {cspPreview.note}
              </Typography.Text>
            )}
          </div>

          {canManage && (
            <div className="jz-detail-audit-submit-box">
              <Form.Item
                name="reason"
                label="变更理由"
                style={{ marginBottom: 10, maxWidth: 760 }}
                extra="必填，进入操作审计与不可变版本记录"
                rules={[
                  {
                    required: true,
                    whitespace: true,
                    message: '请填写变更理由',
                  },
                  {
                    max: CLIENT_SIDE_LIMITS.maxReasonLen,
                    message: `变更理由不能超过 ${CLIENT_SIDE_LIMITS.maxReasonLen} 字符`,
                  },
                ]}
              >
                <Input.TextArea
                  rows={2}
                  placeholder="说明本次变更原因，如：为结账页开启 CSP 学习上报与防窃取探针"
                />
              </Form.Item>
              <div className="jz-detail-audit-submit-actions">
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  <CodeOutlined style={{ marginRight: 6 }} />
                  <SafetyCertificateOutlined style={{ marginRight: 4 }} />
                  草稿保存后须前往「配置发布」下发至网关节点方可生效；已授权与已封禁脚本清单会随发布自动同步至网关。
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
