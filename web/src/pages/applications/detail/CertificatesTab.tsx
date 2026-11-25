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
import type { ApplicationItem, CertificateItem } from '../../../types'
import { InlineNote } from './DetailTabPrimitives'
import './detailTab.css'

const MAX_VISIBLE_SANS = 6

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

export default function CertificatesTab({
  application,
}: {
  application: ApplicationItem
}) {
  const { message } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const [detailRecord, setDetailRecord] = useState<CertificateItem | null>(null)
  const [operation, setOperation] = useState<'bind' | 'unbind' | null>(null)
  const [customRenewDays, setCustomRenewDays] = useState<number | null>(null)
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'certificates.read')
  const canBind = hasPermission(permissions, 'certificates.bind')
  const canCreate = hasPermission(permissions, 'certificates.create')

  const boundQuery = useQuery({
    queryKey: ['app-certificates', application.id],
    queryFn: () => certificatesApi.applicationCertificate(application.id),
    enabled: canRead,
  })
  const boundCertificate = boundQuery.data?.certificate ?? null

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

  const remainingDays = boundCertificate
    ? certRemainingDays(boundCertificate.not_after)
    : null
  const heroTone = boundCertificate
    ? resolveCertHeroTone(boundCertificate, remainingDays)
    : 'default'
  const certStatusMeta = boundCertificate
    ? CERT_STATUS_META[boundCertificate.status]
    : undefined
  const sanDomains = boundCertificate?.san_domains ?? []
  const visibleSans = sanDomains.slice(0, MAX_VISIBLE_SANS)
  const hiddenSans = sanDomains.slice(MAX_VISIBLE_SANS)

  const criticalWarnings = (autoSsl?.warnings ?? []).filter(
    (w) => w.level === 'error' || w.level === 'warning',
  )
  const infoWarnings = (autoSsl?.warnings ?? []).filter(
    (w) => w.level !== 'error' && w.level !== 'warning',
  )

  return (
    <div className="jz-detail-tab">
      {/* 区块 1：当前绑定证书（主角凭证卡片，替代单行超宽表格） */}
      <Card
        className="jz-detail-card"
        title="当前绑定证书"
        extra={
          boundCertificate && (
            <Space size={8} wrap>
              <Button
                size="small"
                icon={<EyeOutlined aria-hidden="true" />}
                onClick={() => setDetailRecord(boundCertificate)}
              >
                查看详情
              </Button>
              {canBind && (
                <>
                  <Button
                    type="primary"
                    size="small"
                    icon={<SwapOutlined aria-hidden="true" />}
                    onClick={() => setOperation('bind')}
                  >
                    替换证书
                  </Button>
                  <Button
                    danger
                    size="small"
                    icon={<DeleteOutlined aria-hidden="true" />}
                    onClick={() => setOperation('unbind')}
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
        ) : boundCertificate ? (
          <div
            className={`jz-detail-cert-hero${heroTone !== 'default' ? ` jz-detail-cert-hero--${heroTone}` : ''}`}
          >
            <div className="jz-detail-cert-hero-top">
              <div className="jz-detail-cert-hero-identity">
                <div className="jz-detail-cert-hero-icon" aria-hidden="true">
                  <SafetyCertificateOutlined />
                </div>
                <div style={{ minWidth: 0 }}>
                  <Space size={8} wrap align="center">
                    <Typography.Text strong style={{ fontSize: 16 }}>
                      {boundCertificate.name}
                    </Typography.Text>
                    {certStatusMeta ? (
                      <Tag color={certStatusMeta.color}>
                        {certStatusMeta.label}
                      </Tag>
                    ) : (
                      <Tag>{boundCertificate.status}</Tag>
                    )}
                    {boundCertificate.managed_by === 'ACME' ? (
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
                      {boundCertificate.common_name || '-'}
                    </Typography.Text>
                  </div>
                </div>
              </div>

              {remainingDays !== null && (
                <Tag
                  icon={<ClockCircleOutlined />}
                  color={certRemainingColor(remainingDays)}
                  style={{
                    fontSize: 13,
                    padding: '4px 10px',
                    marginInlineEnd: 0,
                  }}
                >
                  {remainingDays < 0
                    ? `已过期 ${-remainingDays} 天`
                    : `剩余 ${remainingDays} 天`}
                </Tag>
              )}
            </div>

            <Row gutter={[16, 14]} className="jz-detail-cert-hero-grid">
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">通用名称 (CN)</div>
                <div className="jz-detail-cert-meta-value">
                  <Typography.Text code>
                    {boundCertificate.common_name || '-'}
                  </Typography.Text>
                </div>
              </Col>
              <Col xs={24} sm={12} md={8}>
                <div className="jz-detail-cert-meta-label">到期时间</div>
                <div className="jz-detail-cert-meta-value">
                  {formatDateTime(boundCertificate.not_after ?? null)}
                </div>
              </Col>
              <Col xs={24} sm={24} md={8}>
                <div className="jz-detail-cert-meta-label">颁发者 / 密钥</div>
                <div className="jz-detail-cert-meta-value">
                  {boundCertificate.issuer || '-'}
                  {boundCertificate.public_key_algorithm
                    ? ` · ${boundCertificate.public_key_algorithm}${boundCertificate.public_key_bits ? ` ${boundCertificate.public_key_bits}` : ''}`
                    : ''}
                </div>
              </Col>
              <Col span={24}>
                <div className="jz-detail-cert-meta-label">
                  备用域名 (SAN{sanDomains.length > 0 ? ` · ${sanDomains.length} 个` : ''})
                </div>
                {sanDomains.length > 0 ? (
                  <Space size={6} wrap>
                    {visibleSans.map((domain) => (
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
                    {hiddenSans.length > 0 && (
                      <Tooltip title={sanDomains.join('\n')}>
                        <Tag color="blue" style={{ cursor: 'pointer' }}>
                          +{hiddenSans.length} 个域名
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
              可从证书库选择已有证书直接绑定，或在下方开启 ACME 自动申请免费
              SSL 证书。
            </Typography.Text>
            {canBind && (
              <Button
                type="primary"
                style={{ marginTop: 4 }}
                onClick={() => setOperation('bind')}
              >
                绑定证书
              </Button>
            )}
          </div>
        )}

        <div style={{ marginTop: 14 }}>
          <InlineNote compact>
            <strong>证书绑定、替换和解绑均需经过配置发布后生效</strong>
            ：后端会校验证书有效期及 CN/SAN 对应用全部 HTTPS
            域名的覆盖；开启自动 SSL 且开启自动发布时，签发与续约成功后会自动触发配置发布。
          </InlineNote>
        </div>
      </Card>

      {/* 区块 2：ACME 自动申请与到期续约 SSL 证书 */}
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
                  {boundCertificate ? '立即申请/续约' : '立即申请证书'}
                </Button>
              </Tooltip>
            )}
          </Space>
        }
      >
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

      <RecordDetailDrawer
        open={detailRecord !== null}
        title="证书详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
      {operation && (
        <CertificateBindingModal
          open
          operation={operation}
          application={application}
          certificate={
            operation === 'unbind' ? (boundCertificate ?? undefined) : undefined
          }
          onClose={() => setOperation(null)}
        />
      )}
    </div>
  )
}
