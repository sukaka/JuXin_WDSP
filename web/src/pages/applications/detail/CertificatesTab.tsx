import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  InputNumber,
  Row,
  Space,
  Spin,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import {
  ClockCircleOutlined,
  DeleteOutlined,
  EyeOutlined,
  SafetyCertificateOutlined,
  SwapOutlined,
  SyncOutlined,
} from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { acmeApi } from '../../../api/acme'
import { certificatesApi } from '../../../api/certificates'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import StatusTag from '../../../components/StatusTag'
import CertificateBindingModal from '../../certificates/CertificateBindingModal'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import {
  ACME_ORDER_STATUS_META,
  ACME_PROVIDER_META,
  CERT_STATUS_META,
  certRemainingColor,
  certRemainingDays,
  isActiveAcmeOrderStatus,
} from '../../../utils/stage3'
import type {
  ApplicationItem,
  CertificateItem,
  CertificateProtocolType,
} from '../../../types'
import { InlineNote } from './DetailTabPrimitives'
import TLSProtocolPolicyCard from './TLSProtocolPolicyCard'
import './detailTab.css'

const MAX_VISIBLE_SANS = 6

const CERT_DETAIL_FIELD_LABELS: Record<string, string> = {
  id: '证书 ID',
  name: '证书名称',
  protocol_type: '协议类型',
  certificate_type: '证书类型',
  common_name: '签名/通用名称 (CN)',
  subject: '签名/证书主题',
  issuer: '颁发者',
  serial_number: '序列号',
  not_before: '生效时间',
  not_after: '到期时间',
  effective_not_after: '综合到期时间',
  fingerprint_sha256: 'SHA256 指纹',
  public_key_algorithm: '公钥算法',
  public_key_bits: '公钥位数',
  signature_algorithm: '签名算法',
  san_domains: '备用域名 (SAN)',
  enc_common_name: '加密证书 CN',
  enc_subject: '加密证书主题',
  enc_issuer: '加密证书颁发者',
  enc_serial_number: '加密证书序列号',
  enc_not_before: '加密证书生效时间',
  enc_not_after: '加密证书到期时间',
  enc_fingerprint_sha256: '加密证书 SHA256 指纹',
  status: '状态',
  managed_by: '托管方式',
  usage_count: '使用应用数',
  created_at: '上传时间',
  updated_at: '更新时间',
}

const CERT_DETAIL_VALUE_LABELS: Record<string, Record<string, string>> = {
  protocol_type: {
    INTERNATIONAL: '通用国际（RSA/ECDSA/Ed25519）',
    SM_TLCP: '国密 SM2 双证书（TLCP 1.1）',
  },
  managed_by: {
    MANUAL: '手动上传',
    ACME: 'ACME 自动托管',
  },
}

function resolveCertHeroTone(
  cert: CertificateItem,
  remainingDays: number | null,
): 'default' | 'warning' | 'danger' {
  if (
    cert.status === 'EXPIRED' ||
    cert.status === 'INVALID' ||
    cert.status === 'KEY_MISMATCH' ||
    (remainingDays !== null && remainingDays < 0)
  ) {
    return 'danger'
  }
  if (
    cert.status === 'EXPIRING' ||
    (remainingDays !== null && remainingDays <= 30)
  ) {
    return 'warning'
  }
  return 'default'
}

interface BindingModalState {
  operation: 'bind' | 'unbind'
  slot: CertificateProtocolType
  certificate?: CertificateItem
}

export default function CertificatesTab({
  application,
}: {
  application: ApplicationItem
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [detailRecord, setDetailRecord] = useState<CertificateItem | null>(null)
  const [bindingModal, setBindingModal] = useState<BindingModalState | null>(
    null,
  )
  const [customRenewDays, setCustomRenewDays] = useState<number | null>(null)
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'certificates.read')
  const canBind = hasPermission(permissions, 'certificates.bind')
  const canCreate = hasPermission(permissions, 'certificates.create')
  const canReadApp = hasPermission(permissions, 'applications.read')

  const boundQuery = useQuery({
    queryKey: ['app-certificates', application.id],
    queryFn: () => certificatesApi.applicationCertificate(application.id),
    enabled: canRead,
  })
  const intlCertificate =
    boundQuery.data?.bindings?.international ??
    boundQuery.data?.certificate ??
    null
  const gmCertificate =
    boundQuery.data?.bindings?.gm ?? boundQuery.data?.gm_certificate ?? null

  const autoSslQuery = useQuery({
    queryKey: ['app-auto-ssl', application.id],
    queryFn: () => acmeApi.getAppAutoSsl(application.id),
    enabled: canRead,
    refetchInterval: (q) => {
      const data = q.state.data
      if (!data) return false
      return data.has_active_order ||
        isActiveAcmeOrderStatus(data.latest_order?.status)
        ? 3000
        : false
    },
  })
  const autoSsl = autoSslQuery.data

  // 同步服务端自定义续约天数到本地输入框
  const hasAutoSsl = Boolean(autoSsl)
  const serverRenewDays = autoSsl?.renew_before_days ?? null
  useEffect(() => {
    if (hasAutoSsl) {
      setCustomRenewDays(serverRenewDays)
    }
  }, [hasAutoSsl, serverRenewDays])

  // 当活跃签发任务完成时自动刷新已绑定证书
  const wasActiveRef = useRef(false)
  useEffect(() => {
    const active = Boolean(
      autoSsl?.has_active_order ||
        isActiveAcmeOrderStatus(autoSsl?.latest_order?.status),
    )
    if (wasActiveRef.current && !active) {
      void queryClient.invalidateQueries({
        queryKey: ['app-certificates', application.id],
      })
      void queryClient.invalidateQueries({ queryKey: ['certificates'] })
    }
    wasActiveRef.current = active
  }, [
    autoSsl?.has_active_order,
    autoSsl?.latest_order?.status,
    application.id,
    queryClient,
  ])

  const updateAutoSslMutation = useMutation({
    mutationFn: (body: { enabled: boolean; renew_before_days?: number | null }) =>
      acmeApi.updateAppAutoSsl(application.id, {
        enabled: body.enabled,
        challenge_type: 'HTTP01',
        renew_before_days: body.renew_before_days,
      }),
    onSuccess: (data) => {
      message.success(
        data.enabled
          ? '已开启自动 SSL：若站点尚无证书将自动申请，到期前自动续约'
          : '已关闭该站点自动 SSL',
      )
      void queryClient.invalidateQueries({
        queryKey: ['app-auto-ssl', application.id],
      })
      void queryClient.invalidateQueries({
        queryKey: ['application', application.id],
      })
    },
    onError: (e: unknown) => {
      message.error(
        e instanceof ApiError ? e.message : '更新自动 SSL 设置失败',
      )
    },
  })

  const issueMutation = useMutation({
    mutationFn: () => acmeApi.issueAppCert(application.id),
    onSuccess: () => {
      message.success('已发起 SSL 证书申请任务，正在自动完成域名验证与签发')
      void queryClient.invalidateQueries({
        queryKey: ['app-auto-ssl', application.id],
      })
      void queryClient.invalidateQueries({ queryKey: ['acme-orders'] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '发起证书申请失败')
    },
  })

  if (!canRead) {
    return (
      <Alert
        type="info"
        showIcon
        title="缺少「证书查看」权限，无法查看证书绑定信息"
      />
    )
  }

  const orderInProgress = Boolean(
    autoSsl?.has_active_order ||
      isActiveAcmeOrderStatus(autoSsl?.latest_order?.status),
  )

  const intlRemainingDays = intlCertificate
    ? certRemainingDays(
        intlCertificate.effective_not_after ?? intlCertificate.not_after,
      )
    : null
  const intlHeroTone = intlCertificate
    ? resolveCertHeroTone(intlCertificate, intlRemainingDays)
    : 'default'
  const intlStatusMeta = intlCertificate
    ? CERT_STATUS_META[intlCertificate.status]
    : undefined
  const intlSanDomains = intlCertificate?.san_domains ?? []
  const intlVisibleSans = intlSanDomains.slice(0, MAX_VISIBLE_SANS)
  const intlHiddenSans = intlSanDomains.slice(MAX_VISIBLE_SANS)

  const gmRemainingDays = gmCertificate
    ? certRemainingDays(
        gmCertificate.effective_not_after ?? gmCertificate.not_after,
      )
    : null
  const gmHeroTone = gmCertificate
    ? resolveCertHeroTone(gmCertificate, gmRemainingDays)
    : 'default'
  const gmStatusMeta = gmCertificate
    ? CERT_STATUS_META[gmCertificate.status]
    : undefined
  const gmSanDomains = gmCertificate?.san_domains ?? []
  const gmVisibleSans = gmSanDomains.slice(0, MAX_VISIBLE_SANS)
  const gmHiddenSans = gmSanDomains.slice(MAX_VISIBLE_SANS)

  const criticalWarnings = (autoSsl?.warnings ?? []).filter(
    (w) => w.level === 'error' || w.level === 'warning',
  )
  const infoWarnings = (autoSsl?.warnings ?? []).filter(
    (w) => w.level !== 'error' && w.level !== 'warning',
  )

  return (
    <div className="jz-detail-tab">
      {/* 区块 1：槽位 1 — 通用协议证书（RSA / ECDSA / Ed25519） */}
      <Card
        className="jz-detail-card"
        title={
          <Space size={8} wrap>
            <span>通用协议证书（RSA / ECDSA / Ed25519）</span>
            <Tag color="blue" style={{ marginInlineEnd: 0 }}>
              国际槽位
            </Tag>
          </Space>
        }
        extra={
          intlCertificate && (
            <Space size={8} wrap>
              <Button
                size="small"
                icon={<EyeOutlined aria-hidden="true" />}
                onClick={() => setDetailRecord(intlCertificate)}
              >
                查看详情
              </Button>
              {canBind && (
                <>
                  <Button
                    type="primary"
                    size="small"
                    icon={<SwapOutlined aria-hidden="true" />}
                    onClick={() =>
                      setBindingModal({
                        operation: 'bind',
                        slot: 'INTERNATIONAL',
                      })
                    }
                  >
                    替换证书
                  </Button>
                  <Button
                    danger
                    size="small"
                    icon={<DeleteOutlined aria-hidden="true" />}
                    onClick={() =>
                      setBindingModal({
                        operation: 'unbind',
                        slot: 'INTERNATIONAL',
                        certificate: intlCertificate,
                      })
                    }
                  >
                    解绑证书
                  </Button>
                </>
              )}
            </Space>
          )
        }
      >
        {boundQuery.isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 36 }}>
            <Spin />
          </div>
        ) : boundQuery.isError ? (
          <Alert
            type="error"
            showIcon
            title="加载绑定证书失败"
            description={
              boundQuery.error instanceof ApiError
                ? boundQuery.error.message
                : undefined
            }
          />
        ) : intlCertificate ? (
          <div
            className={`jz-detail-cert-hero${intlHeroTone !== 'default' ? ` jz-detail-cert-hero--${intlHeroTone}` : ''}`}
          >
            <div className="jz-detail-cert-hero-top">
              <div className="jz-detail-cert-hero-identity">
                <div className="jz-detail-cert-hero-icon" aria-hidden="true">
                  <SafetyCertificateOutlined />
                </div>
                <div style={{ minWidth: 0 }}>
                  <Space size={8} wrap align="center">
                    <Typography.Text strong style={{ fontSize: 16 }}>
                      {intlCertificate.name}
                    </Typography.Text>
                    {intlStatusMeta ? (
                      <Tag color={intlStatusMeta.color}>
                        {intlStatusMeta.label}
                      </Tag>
                    ) : (
                      <Tag>{intlCertificate.status}</Tag>
                    )}
                    {intlCertificate.managed_by === 'ACME' ? (
                      <Tag color="cyan" icon={<SafetyCertificateOutlined />}>
                        ACME 自动
                      </Tag>
                    ) : (
                      <Tag>手动上传</Tag>
                    )}
                  </Space>
                  <div style={{ marginTop: 4 }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      CN：
                    </Typography.Text>
                    <Typography.Text code style={{ fontSize: 12 }}>
                      {intlCertificate.common_name || '-'}
                    </Typography.Text>
                  </div>
                </div>
              </div>

              {intlRemainingDays !== null && (
                <Tag
                  icon={<ClockCircleOutlined />}
                  color={certRemainingColor(intlRemainingDays)}
                  style={{
                    fontSize: 13,
                    padding: '4px 10px',
                    marginInlineEnd: 0,
                  }}
                >
                  {intlRemainingDays < 0
                    ? `已过期 ${-intlRemainingDays} 天`
                    : `剩余 ${intlRemainingDays} 天`}
                </Tag>
              )}
            </div>

            <Row gutter={[16, 14]} className="jz-detail-cert-hero-grid">
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">通用名称 (CN)</div>
                <div className="jz-detail-cert-meta-value">
                  <Typography.Text code>
                    {intlCertificate.common_name || '-'}
                  </Typography.Text>
                </div>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">到期时间</div>
                <div className="jz-detail-cert-meta-value">
                  {formatDateTime(
                    intlCertificate.effective_not_after ??
                      intlCertificate.not_after ??
                      null,
                  )}
                </div>
              </Col>
              <Col xs={24} sm={24} md={8}>
                <div className="jz-detail-cert-meta-label">颁发者 / 密钥</div>
                <div className="jz-detail-cert-meta-value">
                  {intlCertificate.issuer || '-'}
                  {intlCertificate.public_key_algorithm
                    ? ` · ${intlCertificate.public_key_algorithm}${intlCertificate.public_key_bits ? ` ${intlCertificate.public_key_bits}` : ''}`
                    : ''}
                </div>
              </Col>
              <Col span={24}>
                <div className="jz-detail-cert-meta-label">
                  备用域名 (SAN
                  {intlSanDomains.length > 0
                    ? ` · ${intlSanDomains.length} 个`
                    : ''}
                  )
                </div>
                {intlSanDomains.length > 0 ? (
                  <Space size={6} wrap>
                    {intlVisibleSans.map((domain) => (
                      <Tag
                        key={domain}
                        style={{
                          fontFamily:
                            'ui-monospace, SFMono-Regular, Menlo, monospace',
                          marginInlineEnd: 0,
                        }}
                      >
                        {domain}
                      </Tag>
                    ))}
                    {intlHiddenSans.length > 0 && (
                      <Tooltip title={intlSanDomains.join('\n')}>
                        <Tag color="blue" style={{ cursor: 'pointer' }}>
                          +{intlHiddenSans.length} 个域名
                        </Tag>
                      </Tooltip>
                    )}
                  </Space>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                )}
              </Col>
            </Row>
          </div>
        ) : (
          <div className="jz-detail-cert-empty">
            <div className="jz-detail-cert-empty-icon" aria-hidden="true">
              <SafetyCertificateOutlined />
            </div>
            <Typography.Text strong style={{ fontSize: 14 }}>
              {autoSsl?.enabled
                ? '当前应用尚未签发证书，已开启自动 SSL 将自动申请并绑定'
                : '当前应用未绑定证书'}
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              可从证书库选择已有通用国际证书直接绑定，或在下方开启 ACME 自动申请免费 SSL 证书。
            </Typography.Text>
            {canBind && (
              <Button
                type="primary"
                style={{ marginTop: 4 }}
                onClick={() =>
                  setBindingModal({
                    operation: 'bind',
                    slot: 'INTERNATIONAL',
                  })
                }
              >
                绑定证书
              </Button>
            )}
          </div>
        )}

        <div style={{ marginTop: 14 }}>
          <InlineNote compact>
            <strong>证书绑定、替换和解绑均需经过配置发布后生效</strong>
            ：后端会校验证书有效期及 CN/SAN 对应用全部 HTTPS 域名的覆盖；同一应用可与下方国密 SM2 双证书并存。
          </InlineNote>
        </div>
      </Card>

      {/* 区块 2：槽位 2 — 国密协议双证书（SM2 / TLCP 1.1） */}
      <Card
        className="jz-detail-card"
        title={
          <Space size={8} wrap>
            <span>国密协议双证书（SM2 / TLCP 1.1）</span>
            <Tag color="volcano" style={{ marginInlineEnd: 0 }}>
              国密槽位
            </Tag>
          </Space>
        }
        extra={
          gmCertificate && (
            <Space size={8} wrap>
              <Button
                size="small"
                icon={<EyeOutlined aria-hidden="true" />}
                onClick={() => setDetailRecord(gmCertificate)}
              >
                查看国密详情
              </Button>
              {canBind && (
                <>
                  <Button
                    type="primary"
                    size="small"
                    icon={<SwapOutlined aria-hidden="true" />}
                    onClick={() =>
                      setBindingModal({
                        operation: 'bind',
                        slot: 'SM_TLCP',
                      })
                    }
                  >
                    替换国密双证书
                  </Button>
                  <Button
                    danger
                    size="small"
                    icon={<DeleteOutlined aria-hidden="true" />}
                    onClick={() =>
                      setBindingModal({
                        operation: 'unbind',
                        slot: 'SM_TLCP',
                        certificate: gmCertificate,
                      })
                    }
                  >
                    解绑国密双证书
                  </Button>
                </>
              )}
            </Space>
          )
        }
      >
        {boundQuery.isLoading ? (
          <div style={{ display: 'flex', justifyContent: 'center', padding: 28 }}>
            <Spin />
          </div>
        ) : boundQuery.isError ? (
          <Alert
            type="error"
            showIcon
            title="加载国密证书绑定失败"
            description={
              boundQuery.error instanceof ApiError
                ? boundQuery.error.message
                : undefined
            }
          />
        ) : gmCertificate ? (
          <div
            className={`jz-detail-cert-hero${gmHeroTone !== 'default' ? ` jz-detail-cert-hero--${gmHeroTone}` : ''}`}
          >
            <div className="jz-detail-cert-hero-top">
              <div className="jz-detail-cert-hero-identity">
                <div className="jz-detail-cert-hero-icon" aria-hidden="true">
                  <SafetyCertificateOutlined />
                </div>
                <div style={{ minWidth: 0 }}>
                  <Space size={8} wrap align="center">
                    <Typography.Text strong style={{ fontSize: 16 }}>
                      {gmCertificate.name}
                    </Typography.Text>
                    {gmStatusMeta ? (
                      <Tag color={gmStatusMeta.color}>{gmStatusMeta.label}</Tag>
                    ) : (
                      <Tag>{gmCertificate.status}</Tag>
                    )}
                    <Tag color="volcano">国密 SM2/TLCP</Tag>
                  </Space>
                  <div style={{ marginTop: 4 }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      签名 CN：
                    </Typography.Text>
                    <Typography.Text code style={{ fontSize: 12 }}>
                      {gmCertificate.common_name || '-'}
                    </Typography.Text>
                    {gmCertificate.enc_common_name && (
                      <>
                        <Typography.Text
                          type="secondary"
                          style={{ fontSize: 12, marginLeft: 12 }}
                        >
                          加密 CN：
                        </Typography.Text>
                        <Typography.Text code style={{ fontSize: 12 }}>
                          {gmCertificate.enc_common_name}
                        </Typography.Text>
                      </>
                    )}
                  </div>
                </div>
              </div>

              {gmRemainingDays !== null && (
                <Tag
                  icon={<ClockCircleOutlined />}
                  color={certRemainingColor(gmRemainingDays)}
                  style={{
                    fontSize: 13,
                    padding: '4px 10px',
                    marginInlineEnd: 0,
                  }}
                >
                  {gmRemainingDays < 0
                    ? `已过期 ${-gmRemainingDays} 天`
                    : `剩余 ${gmRemainingDays} 天`}
                </Tag>
              )}
            </div>

            <Row gutter={[16, 14]} className="jz-detail-cert-hero-grid">
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">签名证书到期时间</div>
                <div className="jz-detail-cert-meta-value">
                  {formatDateTime(gmCertificate.not_after ?? null)}
                </div>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">加密证书到期时间</div>
                <div className="jz-detail-cert-meta-value">
                  {formatDateTime(gmCertificate.enc_not_after ?? null)}
                </div>
              </Col>
              <Col xs={24} sm={24} md={8}>
                <div className="jz-detail-cert-meta-label">签名 / 加密序列号</div>
                <div className="jz-detail-cert-meta-value" style={{ fontSize: 12 }}>
                  {gmCertificate.serial_number || '-'}
                  {gmCertificate.enc_serial_number
                    ? ` / ${gmCertificate.enc_serial_number}`
                    : ''}
                </div>
              </Col>
              <Col span={24}>
                <div className="jz-detail-cert-meta-label">
                  备用域名 (SAN
                  {gmSanDomains.length > 0 ? ` · ${gmSanDomains.length} 个` : ''}
                  )
                </div>
                {gmSanDomains.length > 0 ? (
                  <Space size={6} wrap>
                    {gmVisibleSans.map((domain) => (
                      <Tag
                        key={domain}
                        style={{
                          fontFamily:
                            'ui-monospace, SFMono-Regular, Menlo, monospace',
                          marginInlineEnd: 0,
                        }}
                      >
                        {domain}
                      </Tag>
                    ))}
                    {gmHiddenSans.length > 0 && (
                      <Tooltip title={gmSanDomains.join('\n')}>
                        <Tag color="volcano" style={{ cursor: 'pointer' }}>
                          +{gmHiddenSans.length} 个域名
                        </Tag>
                      </Tooltip>
                    )}
                  </Space>
                ) : (
                  <Typography.Text type="secondary">-</Typography.Text>
                )}
              </Col>
            </Row>
          </div>
        ) : (
          <div className="jz-detail-cert-empty">
            <div className="jz-detail-cert-empty-icon" aria-hidden="true">
              <SafetyCertificateOutlined />
            </div>
            <Typography.Text strong style={{ fontSize: 14 }}>
              当前应用未绑定国密双证书
            </Typography.Text>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              支持与通用国际证书同端口共存；绑定 SM2 签名+加密双证书后，网关可在同一 HTTPS 端口自动识别国密 TLCP 1.1 与标准 TLS 客户端。
            </Typography.Text>
            {canBind && (
              <Button
                type="primary"
                style={{ marginTop: 4 }}
                onClick={() =>
                  setBindingModal({
                    operation: 'bind',
                    slot: 'SM_TLCP',
                  })
                }
              >
                绑定国密双证书
              </Button>
            )}
          </div>
        )}
      </Card>

      {/* 区块 3：ACME 自动申请与到期续约 SSL 证书 */}
      <Card
        className="jz-detail-card"
        title={
          <Space size={8} wrap>
            <SafetyCertificateOutlined style={{ color: '#2f54eb' }} />
            <span>自动申请与到期续约 SSL 证书（ACME HTTP-01）</span>
            {autoSsl?.enabled ? (
              <Tag color="green" style={{ marginInlineEnd: 0 }}>
                已开启
              </Tag>
            ) : (
              <Tag style={{ marginInlineEnd: 0 }}>未开启</Tag>
            )}
            {orderInProgress && (
              <Tag
                color="processing"
                icon={<SyncOutlined spin />}
                style={{ marginInlineEnd: 0 }}
              >
                正在申请/续约中
              </Tag>
            )}
          </Space>
        }
        extra={
          <Space size={10} wrap>
            {canBind && (
              <Switch
                checked={Boolean(autoSsl?.enabled)}
                loading={updateAutoSslMutation.isPending}
                disabled={autoSslQuery.isLoading}
                checkedChildren="自动 SSL 开"
                unCheckedChildren="自动 SSL 关"
                onChange={(checked) =>
                  updateAutoSslMutation.mutate({
                    enabled: checked,
                    renew_before_days: customRenewDays,
                  })
                }
              />
            )}
            {canCreate && (
              <Tooltip
                title={
                  !autoSsl?.ready
                    ? '请先解决下方就绪检查提示项后再申请'
                    : orderInProgress
                      ? '当前已有进行中的申请任务'
                      : undefined
                }
              >
                <Button
                  type="primary"
                  size="small"
                  icon={<SafetyCertificateOutlined />}
                  loading={issueMutation.isPending || orderInProgress}
                  disabled={!autoSsl?.ready || orderInProgress}
                  onClick={() => issueMutation.mutate()}
                >
                  {intlCertificate ? '立即申请/续约' : '立即申请证书'}
                </Button>
              </Tooltip>
            )}
          </Space>
        }
      >
        <InlineNote compact>
          <strong>作用域说明</strong>：ACME 自动申请与续约仅管理「通用协议证书（国际槽位）」，不会覆盖或解绑已绑定的国密 SM2 双证书。
        </InlineNote>
        {autoSslQuery.isError ? (
          <Alert
            type="error"
            showIcon
            title="加载自动 SSL 状态失败"
            description={
              autoSslQuery.error instanceof ApiError
                ? autoSslQuery.error.message
                : undefined
            }
          />
        ) : autoSsl ? (
          <Space orientation="vertical" size={14} style={{ display: 'flex' }}>
            {criticalWarnings.map((w) => (
              <Alert
                key={w.code}
                type={w.level}
                showIcon
                title={w.message}
                action={
                  w.code === 'GLOBAL_ACME_DISABLED' ||
                  w.code === 'GLOBAL_ACME_INCOMPLETE' ? (
                    <Link to="/certificates">
                      <Button size="small" type="link">
                        前往配置 ACME
                      </Button>
                    </Link>
                  ) : undefined
                }
              />
            ))}

            <Row gutter={[16, 16]}>
              <Col xs={24} lg={13}>
                <div className="jz-detail-acme-panel">
                  <div className="jz-detail-acme-panel-title">ACME 运行概览</div>
                  <Row gutter={[16, 12]}>
                    <Col xs={24} sm={12}>
                      <div className="jz-detail-cert-meta-label">CA 提供商</div>
                      <StatusTag
                        value={autoSsl.global_provider}
                        map={ACME_PROVIDER_META}
                      />
                    </Col>
                    <Col xs={24} sm={12}>
                      <div className="jz-detail-cert-meta-label">签发后策略</div>
                      {autoSsl.auto_publish ? (
                        <Tag color="green">自动发布网关生效</Tag>
                      ) : (
                        <Tag>仅入库绑定（待手工发布）</Tag>
                      )}
                    </Col>
                    <Col span={24}>
                      <div className="jz-detail-cert-meta-label">
                        覆盖 HTTPS 域名
                      </div>
                      {autoSsl.https_domains.length > 0 ? (
                        <Space wrap size={6}>
                          {autoSsl.https_domains.map((d) => (
                            <Tag
                              key={d}
                              style={{
                                fontFamily:
                                  'ui-monospace, SFMono-Regular, Menlo, monospace',
                                marginInlineEnd: 0,
                              }}
                            >
                              {d}
                            </Tag>
                          ))}
                        </Space>
                      ) : (
                        <Typography.Text type="secondary">-</Typography.Text>
                      )}
                    </Col>
                  </Row>
                </div>
              </Col>

              <Col xs={24} lg={11}>
                <div className="jz-detail-acme-panel">
                  <div className="jz-detail-acme-panel-title">
                    续约策略与最近任务
                  </div>
                  <div style={{ marginBottom: autoSsl.latest_order ? 14 : 0 }}>
                    <div className="jz-detail-cert-meta-label">
                      提前续约窗口（到期前天数）
                    </div>
                    <Space size={8} wrap>
                      <InputNumber
                        size="small"
                        min={7}
                        max={60}
                        placeholder={`默认 ${autoSsl.effective_renew_before_days} 天`}
                        value={customRenewDays}
                        disabled={!canBind}
                        onChange={(v) =>
                          setCustomRenewDays(typeof v === 'number' ? v : null)
                        }
                        style={{ width: 130 }}
                      />
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        天
                      </Typography.Text>
                      {canBind && (
                        <Button
                          size="small"
                          onClick={() =>
                            updateAutoSslMutation.mutate({
                              enabled: autoSsl.enabled,
                              renew_before_days: customRenewDays,
                            })
                          }
                          loading={updateAutoSslMutation.isPending}
                        >
                          保存天数
                        </Button>
                      )}
                    </Space>
                  </div>

                  {autoSsl.latest_order ? (
                    <Row
                      gutter={[12, 10]}
                      style={{
                        paddingTop: 12,
                        borderTop: '1px dashed #dce3f0',
                      }}
                    >
                      <Col xs={24} sm={12}>
                        <div className="jz-detail-cert-meta-label">
                          最近任务状态
                        </div>
                        <StatusTag
                          value={autoSsl.latest_order.status}
                          map={ACME_ORDER_STATUS_META}
                        />
                      </Col>
                      <Col xs={24} sm={12}>
                        <div className="jz-detail-cert-meta-label">
                          最近尝试时间
                        </div>
                        <div
                          className="jz-detail-cert-meta-value"
                          style={{ fontSize: 12 }}
                        >
                          {formatDateTime(
                            autoSsl.last_attempt_at ||
                              autoSsl.latest_order.created_at,
                          )}
                        </div>
                      </Col>
                      <Col span={24}>
                        <div className="jz-detail-cert-meta-label">
                          下次自动重试
                        </div>
                        <div
                          className="jz-detail-cert-meta-value"
                          style={{ fontSize: 12 }}
                        >
                          {autoSsl.next_retry_at
                            ? formatDateTime(autoSsl.next_retry_at)
                            : '-'}
                        </div>
                      </Col>
                    </Row>
                  ) : (
                    <Typography.Text
                      type="secondary"
                      style={{
                        display: 'block',
                        marginTop: 12,
                        paddingTop: 10,
                        borderTop: '1px dashed #dce3f0',
                        fontSize: 12,
                      }}
                    >
                      暂无 ACME 申请或续约任务记录
                    </Typography.Text>
                  )}
                </div>
              </Col>
            </Row>

            {infoWarnings.map((w) => (
              <InlineNote key={w.code} compact>
                {w.message}
              </InlineNote>
            ))}

            {autoSsl.last_error && (
              <Alert
                type="error"
                showIcon
                title={`最近一次自动申请/续约失败（已连续失败 ${autoSsl.fail_count} 次）`}
                description={
                  <Typography.Text type="danger">
                    {autoSsl.last_error}
                  </Typography.Text>
                }
              />
            )}
          </Space>
        ) : null}
      </Card>

      {/* 区块 4：站点级协议与加密策略（TLS / HTTP 降级与自识别，按 applications.read/update 门控） */}
      {canReadApp && (
        <TLSProtocolPolicyCard
          appId={application.id}
          hasIntlCert={Boolean(intlCertificate)}
          hasGMCert={Boolean(gmCertificate)}
        />
      )}

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="证书详情"
        record={detailRecord as Record<string, unknown> | null}
        fieldLabels={CERT_DETAIL_FIELD_LABELS}
        valueLabels={CERT_DETAIL_VALUE_LABELS}
        onClose={() => setDetailRecord(null)}
      />
      {bindingModal && (
        <CertificateBindingModal
          open
          operation={bindingModal.operation}
          application={application}
          protocolSlot={bindingModal.slot}
          certificate={
            bindingModal.operation === 'unbind'
              ? bindingModal.certificate
              : undefined
          }
          onClose={() => setBindingModal(null)}
        />
      )}
    </div>
  )
}
