import { useEffect, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  InputNumber,
  Space,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { SafetyCertificateOutlined, SyncOutlined } from '@ant-design/icons'
import { ApiError } from '../../../api/client'
import { acmeApi } from '../../../api/acme'
import { certificatesApi } from '../../../api/certificates'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import SmartTable from '../../../components/SmartTable'
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

export default function CertificatesTab({ application }: { application: ApplicationItem }) {
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
      return data.has_active_order || isActiveAcmeOrderStatus(data.latest_order?.status)
        ? 3000
        : false
    },
  })
  const autoSsl = autoSslQuery.data

  // 同步服务端自定义续约天数到本地输入框
  useEffect(() => {
    if (autoSsl) {
      setCustomRenewDays(autoSsl.renew_before_days ?? null)
    }
  }, [autoSsl?.renew_before_days])

  // 当活跃签发任务完成时自动刷新已绑定证书表格
  const wasActiveRef = useRef(false)
  useEffect(() => {
    const active = Boolean(
      autoSsl?.has_active_order || isActiveAcmeOrderStatus(autoSsl?.latest_order?.status),
    )
    if (wasActiveRef.current && !active) {
      void queryClient.invalidateQueries({ queryKey: ['app-certificates', application.id] })
      void queryClient.invalidateQueries({ queryKey: ['certificates'] })
    }
    wasActiveRef.current = active
  }, [autoSsl?.has_active_order, autoSsl?.latest_order?.status, application.id, queryClient])

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
      void queryClient.invalidateQueries({ queryKey: ['app-auto-ssl', application.id] })
      void queryClient.invalidateQueries({ queryKey: ['application', application.id] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '更新自动 SSL 设置失败')
    },
  })

  const issueMutation = useMutation({
    mutationFn: () => acmeApi.issueAppCert(application.id),
    onSuccess: () => {
      message.success('已发起 SSL 证书申请任务，正在自动完成域名验证与签发')
      void queryClient.invalidateQueries({ queryKey: ['app-auto-ssl', application.id] })
      void queryClient.invalidateQueries({ queryKey: ['acme-orders'] })
    },
    onError: (e: unknown) => {
      message.error(e instanceof ApiError ? e.message : '发起证书申请失败')
    },
  })

  const columns: ColumnsType<CertificateItem> = [
    { title: '证书名称', dataIndex: 'name', width: 180 },
    {
      title: '托管方式',
      key: 'managed_by',
      width: 120,
      render: (_, record) =>
        record.managed_by === 'ACME' ? (
          <Tag color="cyan" icon={<SafetyCertificateOutlined />}>
            ACME 自动
          </Tag>
        ) : (
          <Tag>手动上传</Tag>
        ),
    },
    { title: '通用名称(CN)', dataIndex: 'common_name', width: 180 },
    {
      title: '备用域名',
      dataIndex: 'san_domains',
      render: (sans: string[]) =>
        sans && sans.length > 0 ? (
          <Tooltip title={sans.join('\n')}>
            <Tag>{sans.length} 个</Tag>
          </Tooltip>
        ) : (
          '-'
        ),
    },
    {
      title: '到期时间',
      dataIndex: 'not_after',
      width: 180,
      render: (v: string | null) => formatDateTime(v),
    },
    {
      title: '剩余天数',
      key: 'remaining',
      width: 110,
      render: (_, record) => {
        const days = certRemainingDays(record.not_after)
        if (days === null) return '-'
        return (
          <Tag color={certRemainingColor(days)}>
            {days < 0 ? `已过期 ${-days} 天` : `${days} 天`}
          </Tag>
        )
      },
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: string) => {
        const meta = CERT_STATUS_META[v]
        return meta ? <Tag color={meta.color}>{meta.label}</Tag> : <Tag>{v}</Tag>
      },
    },
  ]

  if (!canRead) {
    return (
      <Alert
        type="info"
        showIcon
        message="缺少「证书查看」权限，无法查看证书绑定信息"
      />
    )
  }

  const orderInProgress = Boolean(
    autoSsl?.has_active_order || isActiveAcmeOrderStatus(autoSsl?.latest_order?.status),
  )

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        size="small"
        title={
          <Space>
            <SafetyCertificateOutlined />
            <span>自动申请与到期续约 SSL 证书（ACME HTTP-01）</span>
            {autoSsl?.enabled ? (
              <Tag color="green">已开启</Tag>
            ) : (
              <Tag>未开启</Tag>
            )}
            {orderInProgress && (
              <Tag color="processing" icon={<SyncOutlined spin />}>
                正在申请/续约中
              </Tag>
            )}
          </Space>
        }
        extra={
          <Space>
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
            message="加载自动 SSL 状态失败"
            description={
              autoSslQuery.error instanceof ApiError ? autoSslQuery.error.message : undefined
            }
          />
        ) : (
          autoSsl && (
            <Space direction="vertical" size={12} style={{ display: 'flex' }}>
              {autoSsl.warnings.map((w) => (
                <Alert
                  key={w.code}
                  type={w.level}
                  showIcon
                  message={w.message}
                  action={
                    w.code === 'GLOBAL_ACME_DISABLED' || w.code === 'GLOBAL_ACME_INCOMPLETE' ? (
                      <Link to="/certificates">
                        <Button size="small" type="link">
                          前往配置 ACME
                        </Button>
                      </Link>
                    ) : undefined
                  }
                />
              ))}

              <Descriptions size="small" column={{ xs: 1, sm: 2, md: 3 }}>
                <Descriptions.Item label="CA 提供商">
                  <StatusTag value={autoSsl.global_provider} map={ACME_PROVIDER_META} />
                </Descriptions.Item>
                <Descriptions.Item label="签发后策略">
                  {autoSsl.auto_publish ? (
                    <Tag color="green">自动发布网关生效</Tag>
                  ) : (
                    <Tag>仅入库绑定（待手工发布）</Tag>
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="提前续约窗口">
                  <Space size={6}>
                    <InputNumber
                      size="small"
                      min={7}
                      max={60}
                      placeholder={`默认 ${autoSsl.effective_renew_before_days} 天`}
                      value={customRenewDays}
                      disabled={!canBind}
                      onChange={(v) => setCustomRenewDays(typeof v === 'number' ? v : null)}
                      style={{ width: 110 }}
                    />
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
                </Descriptions.Item>
                <Descriptions.Item label="覆盖 HTTPS 域名" span={3}>
                  {autoSsl.https_domains.length > 0 ? (
                    <Space wrap size={4}>
                      {autoSsl.https_domains.map((d) => (
                        <Tag key={d} style={{ fontFamily: 'monospace' }}>
                          {d}
                        </Tag>
                      ))}
                    </Space>
                  ) : (
                    '-'
                  )}
                </Descriptions.Item>
                {autoSsl.latest_order && (
                  <>
                    <Descriptions.Item label="最近任务状态">
                      <StatusTag value={autoSsl.latest_order.status} map={ACME_ORDER_STATUS_META} />
                    </Descriptions.Item>
                    <Descriptions.Item label="最近尝试时间">
                      {formatDateTime(autoSsl.last_attempt_at || autoSsl.latest_order.created_at)}
                    </Descriptions.Item>
                    <Descriptions.Item label="下次自动重试">
                      {autoSsl.next_retry_at ? formatDateTime(autoSsl.next_retry_at) : '-'}
                    </Descriptions.Item>
                  </>
                )}
              </Descriptions>

              {autoSsl.last_error && (
                <Alert
                  type="error"
                  showIcon
                  message={`最近一次自动申请/续约失败（已连续失败 ${autoSsl.fail_count} 次）`}
                  description={
                    <Typography.Text type="danger">{autoSsl.last_error}</Typography.Text>
                  }
                />
              )}
            </Space>
          )
        )}
      </Card>

      <Alert
        type="info"
        showIcon
        message="证书绑定、替换和解绑均需经过配置发布后生效"
        description="后端会校验证书有效期及 CN/SAN 对应用全部 HTTPS 域名的覆盖；开启自动 SSL 且开启自动发布时，签发与续约成功后会自动触发配置发布。"
      />

      {canBind && (
        <Space>
          <Button type="primary" onClick={() => setOperation('bind')}>
            {boundCertificate ? '手动替换证书' : '手动绑定证书'}
          </Button>
          {boundCertificate && (
            <Button danger onClick={() => setOperation('unbind')}>
              解绑证书
            </Button>
          )}
        </Space>
      )}

      {boundQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载绑定证书失败"
          description={boundQuery.error instanceof ApiError ? boundQuery.error.message : undefined}
        />
      ) : (
        <SmartTable<CertificateItem>
          storageKey="applications-certificates"
          rowKey="id"
          loading={boundQuery.isLoading}
          columns={columns}
          dataSource={boundCertificate ? [boundCertificate] : []}
          pagination={false}
          locale={{
            emptyText: autoSsl?.enabled
              ? '当前应用尚未签发证书，已开启自动 SSL 将自动申请并绑定'
              : '当前应用未绑定证书',
          }}
          onRow={(record) => ({
            onDoubleClick: () => setDetailRecord(record),
            style: { cursor: 'pointer' },
          })}
        />
      )}

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
          certificate={operation === 'unbind' ? boundCertificate ?? undefined : undefined}
          onClose={() => setOperation(null)}
        />
      )}
    </Space>
  )
}
