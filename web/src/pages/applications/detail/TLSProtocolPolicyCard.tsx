import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Col,
  Form,
  Row,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Typography,
} from 'antd'
import { LockOutlined, SaveOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { tlsConfigApi } from '../../../api/applications'
import { useAuthStore } from '../../../stores/auth'
import { hasAnyPermission, hasPermission } from '../../../utils/permission'
import type {
  AllowedTLSVersion,
  AppHTTPVersion,
  AppTLSConfig,
  LegacySSLAnalysisVersion,
  TLSProtocolMode,
  UpstreamHTTPVersion,
  UpstreamTLSMinVersion,
} from '../../../types'
import { InlineNote, ModeCardGroup, SectionHeader, type ModeCardOption } from './DetailTabPrimitives'
import './detailTab.css'

const DEFAULT_TLS_CONFIG: AppTLSConfig = {
  tls_protocol_mode: 'AUTO_DETECT',
  allowed_tls_versions: ['TLS1.2', 'TLS1.3'],
  legacy_ssl_analysis_versions: ['SSLv2', 'SSLv2_v3', 'SSLv3'],
  http_versions: ['HTTP/1.0', 'HTTP/1.1', 'HTTP/2'],
  upstream_http_version: 'AUTO',
  upstream_tls_min_version: 'TLS1.2',
  session_analysis_enabled: true,
}

const PROTOCOL_MODE_OPTIONS: ModeCardOption<TLSProtocolMode>[] = [
  {
    value: 'AUTO_DETECT',
    label: '国密与通用自识别',
    badge: 'AUTO_DETECT',
    badgeColor: 'blue',
    tone: 'info',
    description: '同端口自动识别国际 TLS 与国密 TLCP 1.1 握手，按客户端能力协商对应证书。',
  },
  {
    value: 'INTERNATIONAL_ONLY',
    label: '仅通用协议',
    badge: 'INTERNATIONAL',
    badgeColor: 'default',
    tone: 'neutral',
    description: '仅接受国际标准 TLS 客户端连接，拒绝国密 TLCP 握手。',
  },
  {
    value: 'GM_ONLY',
    label: '仅国密协议',
    badge: 'GM_ONLY',
    badgeColor: 'volcano',
    tone: 'warning',
    description: '仅接受国密 TLCP 1.1 握手，需已绑定国密 SM2 双证书并启用 TLCP 1.1。',
  },
]

const ALLOWED_TLS_VERSION_OPTIONS: { value: AllowedTLSVersion; label: string }[] = [
  { value: 'TLCP1.1', label: 'TLCP 1.1（国密）' },
  { value: 'TLS1.0', label: 'TLS 1.0（弱协议）' },
  { value: 'TLS1.1', label: 'TLS 1.1（弱协议）' },
  { value: 'TLS1.2', label: 'TLS 1.2' },
  { value: 'TLS1.3', label: 'TLS 1.3' },
]

const LEGACY_SSL_OPTIONS: { value: LegacySSLAnalysisVersion; label: string }[] = [
  { value: 'SSLv2', label: 'SSLv2' },
  { value: 'SSLv2_v3', label: 'SSLv2/v3' },
  { value: 'SSLv3', label: 'SSLv3' },
]

const HTTP_VERSION_OPTIONS: { value: AppHTTPVersion; label: string }[] = [
  { value: 'HTTP/1.0', label: 'HTTP/1.0' },
  { value: 'HTTP/1.1', label: 'HTTP/1.1' },
  { value: 'HTTP/2', label: 'HTTP/2' },
]

const UPSTREAM_HTTP_OPTIONS: { value: UpstreamHTTPVersion; label: string }[] = [
  { value: 'AUTO', label: '自动协商（AUTO）' },
  { value: 'HTTP/2', label: 'HTTP/2' },
  { value: 'HTTP/1.1', label: 'HTTP/1.1（强制降级）' },
  { value: 'HTTP/1.0', label: 'HTTP/1.0（强制降级）' },
]

const UPSTREAM_TLS_MIN_OPTIONS: { value: UpstreamTLSMinVersion; label: string }[] = [
  { value: 'TLS1.3', label: 'TLS 1.3' },
  { value: 'TLS1.2', label: 'TLS 1.2（推荐）' },
  { value: 'TLS1.1', label: 'TLS 1.1（旧源站兼容）' },
  { value: 'TLS1.0', label: 'TLS 1.0（旧源站兼容）' },
]

export interface TLSProtocolPolicyCardProps {
  appId: string
  hasIntlCert?: boolean
  hasGMCert?: boolean
}

export default function TLSProtocolPolicyCard({
  appId,
  hasIntlCert,
  hasGMCert,
}: TLSProtocolPolicyCardProps) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'applications.read')
  const canUpdate = hasPermission(permissions, 'applications.update')
  const canPublish = hasAnyPermission(permissions, [
    'gateway_configs.preview',
    'gateway_configs.publish',
  ])

  const [form] = Form.useForm<AppTLSConfig>()
  const [configVersion, setConfigVersion] = useState(0)
  const versionRef = useRef(0)
  const [needsPublishHint, setNeedsPublishHint] = useState(false)

  const protocolMode = Form.useWatch('tls_protocol_mode', form) ?? DEFAULT_TLS_CONFIG.tls_protocol_mode
  const allowedTLSVersions = Form.useWatch('allowed_tls_versions', form) ?? DEFAULT_TLS_CONFIG.allowed_tls_versions
  const httpVersions = Form.useWatch('http_versions', form) ?? DEFAULT_TLS_CONFIG.http_versions
  const upstreamTLSMin = Form.useWatch('upstream_tls_min_version', form) ?? DEFAULT_TLS_CONFIG.upstream_tls_min_version
  const sessionAnalysisEnabled = Form.useWatch('session_analysis_enabled', form) ?? true

  const configQuery = useQuery({
    queryKey: ['tls-config', appId],
    queryFn: () => tlsConfigApi.get(appId),
    enabled: canRead,
  })

  useEffect(() => {
    const data = configQuery.data
    if (!data) return
    const nextVersion = data.version ?? 0
    versionRef.current = nextVersion
    setConfigVersion(nextVersion)
    form.setFieldsValue({
      ...DEFAULT_TLS_CONFIG,
      ...data.config,
      allowed_tls_versions: data.config?.allowed_tls_versions ?? DEFAULT_TLS_CONFIG.allowed_tls_versions,
      legacy_ssl_analysis_versions:
        data.config?.legacy_ssl_analysis_versions ?? DEFAULT_TLS_CONFIG.legacy_ssl_analysis_versions,
      http_versions: data.config?.http_versions ?? DEFAULT_TLS_CONFIG.http_versions,
    })
  }, [configQuery.data, form])

  const invalidate = () =>
    void queryClient.invalidateQueries({ queryKey: ['tls-config', appId] })

  const saveMutation = useMutation({
    mutationFn: (values: AppTLSConfig) =>
      tlsConfigApi.update(appId, {
        ...values,
        version: versionRef.current,
      }),
    onSuccess: (data) => {
      const nextVersion = data?.version ?? versionRef.current + 1
      versionRef.current = nextVersion
      setConfigVersion(nextVersion)
      setNeedsPublishHint(true)
      message.success('协议与加密策略已保存，请执行配置发布后生效')
      invalidate()
    },
    onError: (e: unknown) => {
      if (e instanceof ApiError && (e.status === 409 || e.code === 'RESOURCE_CONFLICT')) {
        message.warning('配置已被其他人修改，请刷新后重试')
        invalidate()
        return
      }
      message.error(e instanceof ApiError ? e.message : '保存协议与加密策略失败')
    },
  })

  if (!canRead) return null

  const hasWeakInboundTLS =
    allowedTLSVersions.includes('TLS1.0') || allowedTLSVersions.includes('TLS1.1')
  const hasWeakUpstreamTLS = upstreamTLSMin === 'TLS1.0' || upstreamTLSMin === 'TLS1.1'
  const http2Disabled = !httpVersions.includes('HTTP/2')
  const missingGMCertWarning = protocolMode === 'GM_ONLY' && hasGMCert === false
  const missingIntlCertWarning = protocolMode === 'INTERNATIONAL_ONLY' && hasIntlCert === false

  return (
    <Card
      className="jz-detail-card"
      title={
        <Space size={8} wrap>
          <LockOutlined style={{ color: '#2f54eb' }} />
          <span>协议与加密策略（TLS / HTTP 降级与自识别）</span>
        </Space>
      }
      extra={
        configQuery.data?.configured ? (
          <Tag color="blue" style={{ marginInlineEnd: 0 }}>
            版本 v{configVersion}
          </Tag>
        ) : (
          <Tag style={{ marginInlineEnd: 0 }}>默认基线</Tag>
        )
      }
    >
      {configQuery.isLoading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: 36 }}>
          <Spin />
        </div>
      ) : configQuery.isError ? (
        <Alert
          type="error"
          showIcon
          title="加载协议与加密策略失败"
          description={
            configQuery.error instanceof ApiError ? configQuery.error.message : undefined
          }
        />
      ) : (
        <Form<AppTLSConfig>
          form={form}
          layout="vertical"
          initialValues={DEFAULT_TLS_CONFIG}
          disabled={!canUpdate}
          onFinish={(values) => {
            saveMutation.mutate({
              tls_protocol_mode: values.tls_protocol_mode,
              allowed_tls_versions: values.allowed_tls_versions ?? [],
              legacy_ssl_analysis_versions: values.legacy_ssl_analysis_versions ?? [],
              http_versions: values.http_versions ?? [],
              upstream_http_version: values.upstream_http_version,
              upstream_tls_min_version: values.upstream_tls_min_version,
              session_analysis_enabled: Boolean(values.session_analysis_enabled),
            })
          }}
        >
          {needsPublishHint && (
            <Alert
              type="success"
              showIcon
              style={{ marginBottom: 16 }}
              title="协议与加密策略已保存，尚未发布至网关"
              description="需在「配置发布」执行发布后，网关监听器与回源传输层才会启用最新 TLS/TLCP 及 HTTP 协议策略。"
              action={
                canPublish ? (
                  <Link to="/config-publish">
                    <Button size="small" type="primary">
                      去配置发布
                    </Button>
                  </Link>
                ) : undefined
              }
            />
          )}

          <SectionHeader
            title="协议自识别模式"
            description="控制 HTTPS 入口端口是否同时识别国密 TLCP 1.1 与国际标准 TLS 握手。"
          />
          <Form.Item name="tls_protocol_mode" rules={[{ required: true }]}>
            <ModeCardGroup<TLSProtocolMode>
              options={PROTOCOL_MODE_OPTIONS}
              disabled={!canUpdate}
            />
          </Form.Item>

          {missingGMCertWarning && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title="当前站点尚未绑定国密 SM2 双证书"
              description="选择「仅国密协议 (GM_ONLY)」前，请先在上方国密槽位绑定有效的 SM2 签名+加密双证书，否则配置发布会被校验拒绝。"
            />
          )}
          {missingIntlCertWarning && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title="当前站点尚未绑定通用协议国际证书"
              description="选择「仅通用协议 (INTERNATIONAL_ONLY)」前，请先在上方国际槽位绑定证书或开启自动 SSL。"
            />
          )}

          <SectionHeader
            spaced
            title="允许协商的 TLS / TLCP 版本"
            description="决定网关在服务端握手阶段允许客户端协商的加密协议版本集合。"
          />
          <Form.Item
            name="allowed_tls_versions"
            dependencies={['tls_protocol_mode']}
            rules={[
              ({ getFieldValue }) => ({
                validator(_, value: AllowedTLSVersion[] | undefined) {
                  const list = value ?? []
                  if (list.length === 0) {
                    return Promise.reject(new Error('至少启用一个 TLS/TLCP 版本'))
                  }
                  const mode = getFieldValue('tls_protocol_mode') as TLSProtocolMode
                  if (mode === 'GM_ONLY' && !list.includes('TLCP1.1')) {
                    return Promise.reject(
                      new Error('仅国密模式（GM_ONLY）必须启用 TLCP 1.1'),
                    )
                  }
                  if (
                    mode === 'INTERNATIONAL_ONLY' &&
                    !list.some((v) => v !== 'TLCP1.1')
                  ) {
                    return Promise.reject(
                      new Error('仅通用模式（INTERNATIONAL_ONLY）必须至少启用一个国际 TLS 版本'),
                    )
                  }
                  return Promise.resolve()
                },
              }),
            ]}
          >
            <Checkbox.Group options={ALLOWED_TLS_VERSION_OPTIONS} />
          </Form.Item>
          {hasWeakInboundTLS && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title="已启用弱安全协议（TLS 1.0 / TLS 1.1）"
              description="TLS 1.0 与 TLS 1.1 存在已知降级与加密弱点风险，仅建议在兼容老旧终端的过渡期临时开启，过渡完成后请及时关闭。"
            />
          )}

          <SectionHeader
            spaced
            title="弱 SSL 加密会话分析与阻断"
            description="在 ClientHello 预读层识别过时 SSL 协议并立即阻断，同时写入加密会话分析审计日志。"
          />
          <Form.Item name="legacy_ssl_analysis_versions">
            <Checkbox.Group options={LEGACY_SSL_OPTIONS} />
          </Form.Item>

          <SectionHeader
            spaced
            title="接入 HTTP 协议与现网降级"
            description="取消勾选 HTTP/2 将在 ALPN 与网关监听器禁用 H2，强制客户端降级为 HTTP/1.1。"
          />
          <Form.Item
            name="http_versions"
            rules={[
              {
                validator(_, value: AppHTTPVersion[] | undefined) {
                  if (!value || value.length === 0) {
                    return Promise.reject(new Error('至少启用一个接入 HTTP 协议版本'))
                  }
                  return Promise.resolve()
                },
              },
            ]}
          >
            <Checkbox.Group options={HTTP_VERSION_OPTIONS} />
          </Form.Item>
          {http2Disabled && (
            <InlineNote compact>
              当前已取消 <strong>HTTP/2</strong>，发布后网关将强制对该站点执行现网 HTTP/1.1 协议降级（ALPN 不再宣告 h2）。
            </InlineNote>
          )}

          <SectionHeader
            spaced
            title="SSL 加载与回源协议降级"
            description="控制网关回源至上游服务器时的 HTTP 协议降级与 HTTPS 回源 TLS 最低版本。"
          />
          <Row gutter={[16, 0]}>
            <Col xs={24} md={12}>
              <Form.Item
                name="upstream_http_version"
                label="回源 HTTP 协议版本"
                rules={[{ required: true }]}
              >
                <Select options={UPSTREAM_HTTP_OPTIONS} />
              </Form.Item>
            </Col>
            <Col xs={24} md={12}>
              <Form.Item
                name="upstream_tls_min_version"
                label="回源 TLS 最低版本"
                rules={[{ required: true }]}
              >
                <Select options={UPSTREAM_TLS_MIN_OPTIONS} />
              </Form.Item>
            </Col>
          </Row>
          {hasWeakUpstreamTLS && (
            <Alert
              type="warning"
              showIcon
              style={{ marginBottom: 16 }}
              title="回源 TLS 最低版本已放宽至 TLS 1.0 / TLS 1.1"
              description="仅用于兼容尚未升级 TLS 1.2 的内网老旧源站；建议尽快升级源站 TLS 版本以消除安全隐患。"
            />
          )}

          <SectionHeader
            spaced
            title="加密会话分析采集"
            description="控制是否对该站点 TLS/TLCP 握手采集协议版本、算法套件、国密标识与 JA3 指纹。"
          />
          <div
            className={
              sessionAnalysisEnabled
                ? 'jz-detail-switch-tile jz-detail-switch-tile--active'
                : 'jz-detail-switch-tile'
            }
          >
            <Form.Item
              name="session_analysis_enabled"
              className="jz-detail-switch-form-item"
              label={
                <>
                  <span>启用 SSL/HTTPS 加密会话分析采集</span>
                  <span className="jz-detail-switch-desc">
                    开启后将握手元数据与弱协议阻断事件上报至「加密会话分析」页面（热路径异步落盘，不影响业务转发）
                  </span>
                </>
              }
              valuePropName="checked"
            >
              <Switch />
            </Form.Item>
          </div>

          {canUpdate && (
            <div className="jz-detail-action-bar">
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                保存后需前往「配置发布」执行发布，策略才会在网关数据面生效。
              </Typography.Text>
              <Button
                type="primary"
                icon={<SaveOutlined />}
                htmlType="submit"
                loading={saveMutation.isPending}
              >
                保存协议策略
              </Button>
            </div>
          )}
        </Form>
      )}
    </Card>
  )
}
