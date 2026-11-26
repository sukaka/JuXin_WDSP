import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Checkbox,
  Descriptions,
  Divider,
  Drawer,
  Input,
  Select,
  Space,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { PlusOutlined, SafetyCertificateOutlined, SettingOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { acmeApi } from '../../api/acme'
import { applicationsApi } from '../../api/applications'
import { certificatesApi } from '../../api/certificates'
import SmartTable from '../../components/SmartTable'
import AcmeOrdersTable from './AcmeOrdersTable'
import AcmeSettingsModal from './AcmeSettingsModal'
import CertificateBindingModal from './CertificateBindingModal'
import CertificateUploadModal from './CertificateUploadModal'
import StatusTag from '../../components/StatusTag'
import useBatchDelete from '../../hooks/useBatchDelete'
import { useAuthStore } from '../../stores/auth'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  ACME_PROVIDER_META,
  CERT_PROTOCOL_META,
  CERT_STATUS_META,
  certRemainingColor,
  certRemainingDays,
  isGMProtocol,
} from '../../utils/stage3'
import type { CertificateItem, CertificateProtocolType } from '../../types'

interface Filters {
  name?: string
  status?: string
  protocol_type?: CertificateProtocolType
  include_replaced?: boolean
}

/** 证书详情里的绑定应用列表（按 ID 反查应用名称） */
function BoundApplications({ certId }: { certId: string }) {
  const appsQuery = useQuery({
    queryKey: ['cert-applications', certId],
    queryFn: () => certificatesApi.applications(certId),
  })
  const appListQuery = useQuery({
    queryKey: ['applications', 'all-for-cert'],
    queryFn: () => applicationsApi.list({ page: 1, page_size: 100 }),
    enabled: (appsQuery.data?.count ?? 0) > 0,
  })

  if (appsQuery.isLoading) return <Typography.Text type="secondary">加载中…</Typography.Text>
  if (appsQuery.isError) {
    return (
      <Typography.Text type="danger">
        {appsQuery.error instanceof ApiError ? appsQuery.error.message : '加载失败'}
      </Typography.Text>
    )
  }
  const ids = appsQuery.data?.application_ids ?? []
  if (ids.length === 0) return <Typography.Text type="secondary">未绑定任何应用</Typography.Text>
  const nameOf = (id: string) => {
    const app = (appListQuery.data?.items ?? []).find((a) => a.id === id)
    return app ? `${app.name}（${app.code}）` : id
  }
  return (
    <Space wrap>
      {ids.map((id) => (
        <Tag key={id} color="blue">
          {nameOf(id)}
        </Tag>
      ))}
    </Space>
  )
}

export default function CertificatesPage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  const [filters, setFilters] = useState<Filters>({})
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [uploadOpen, setUploadOpen] = useState(false)
  const [acmeSettingsOpen, setAcmeSettingsOpen] = useState(false)
  const [activeTab, setActiveTab] = useState<'list' | 'orders'>('list')
  const [detailId, setDetailId] = useState<string | null>(null)
  const [binding, setBinding] = useState<{ operation: 'bind' | 'unbind'; certificate: CertificateItem } | null>(null)

  const listQuery = useQuery({
    queryKey: ['certificates', filters, page, pageSize],
    queryFn: () => certificatesApi.list({ ...filters, page, page_size: pageSize }),
  })

  const detailQuery = useQuery({
    queryKey: ['certificate', detailId],
    queryFn: () => certificatesApi.get(detailId as string),
    enabled: detailId !== null,
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['certificates'] })

  const onError = (e: unknown) => {
    if (e instanceof ApiError && e.code === 'RESOURCE_CONFLICT') {
      message.error(e.message || '证书正在使用中，无法执行该操作')
      void invalidate()
      return
    }
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const removeMutation = useMutation({
    mutationFn: (id: string) => certificatesApi.remove(id),
    onSuccess: () => {
      message.success('删除成功')
      void invalidate()
    },
    onError,
  })

  const renewMutation = useMutation({
    mutationFn: (id: string) => acmeApi.renewCertificate(id),
    onSuccess: () => {
      message.success('已触发证书续约任务，可在「申请与续约记录」查看实时进度')
      setActiveTab('orders')
      void queryClient.invalidateQueries({ queryKey: ['acme-orders'] })
      void invalidate()
    },
    onError,
  })

  const { rowSelection, batchDeleteButton } = useBatchDelete<CertificateItem>({
    remove: (id) => certificatesApi.remove(id),
    invalidateKeys: [['certificates']],
    entityName: '证书',
    canDelete: hasPermission(permissions, 'certificates.delete'),
  })

  const columns: ColumnsType<CertificateItem> = [
    {
      title: '名称',
      dataIndex: 'name',
      width: 180,
      render: (v: string, record) => (
        <Button
          type="link"
          size="small"
          style={{ padding: 0, height: 'auto' }}
          onClick={() => setDetailId(record.id)}
        >
          {v}
        </Button>
      ),
    },
    {
      title: '协议类型',
      dataIndex: 'protocol_type',
      width: 130,
      render: (v?: CertificateProtocolType) => (
        <StatusTag value={v ?? 'INTERNATIONAL'} map={CERT_PROTOCOL_META} />
      ),
    },
    { title: '通用名称(CN)', dataIndex: 'common_name', width: 180 },
    {
      title: '颁发者',
      dataIndex: 'issuer',
      width: 220,
      ellipsis: true,
      render: (v: string) => (
        <Tooltip title={v}>
          <span>{v}</span>
        </Tooltip>
      ),
    },
    {
      title: '备用域名',
      dataIndex: 'san_domains',
      width: 100,
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
      key: 'effective_not_after',
      width: 170,
      render: (_, record) => {
        const effective = record.effective_not_after ?? record.not_after ?? null
        if (isGMProtocol(record.protocol_type) && record.enc_not_after) {
          return (
            <Tooltip
              title={`签名证书到期：${formatDateTime(record.not_after)}\n加密证书到期：${formatDateTime(record.enc_not_after)}`}
            >
              <span>{formatDateTime(effective)}</span>
            </Tooltip>
          )
        }
        return formatDateTime(effective)
      },
    },
    {
      title: '剩余天数',
      key: 'remaining',
      width: 120,
      render: (_, record) => {
        const days = certRemainingDays(record.effective_not_after ?? record.not_after)
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
      render: (v: string) => <StatusTag value={v} map={CERT_STATUS_META} />,
    },
    {
      title: '托管方式',
      key: 'managed_by',
      width: 130,
      render: (_, record) =>
        record.managed_by === 'ACME' ? (
          <Tooltip
            title={`自动续约：${record.auto_renew ? `到期前 ${record.renew_before_days ?? 30} 天` : '已关闭'}`}
          >
            <Tag color="cyan" icon={<SafetyCertificateOutlined />}>
              ACME 自动
            </Tag>
          </Tooltip>
        ) : (
          <Tag>手动上传</Tag>
        ),
    },
    {
      title: '使用应用数',
      dataIndex: 'usage_count',
      width: 100,
    },
    {
      title: '操作',
      key: 'actions',
      width: 300,
      fixed: 'right',
      render: (_, record) => (
        <Space>
          <Button type="link" size="small" onClick={() => setDetailId(record.id)}>
            详情
          </Button>
          {record.managed_by === 'ACME' &&
            record.status !== 'REPLACED' &&
            record.usage_count > 0 &&
            hasPermission(permissions, 'certificates.create') && (
              <Button
                type="link"
                size="small"
                loading={renewMutation.isPending}
                onClick={() =>
                  modal.confirm({
                    title: '立即续约确认',
                    content: `确定立即通过 ACME 为证书「${record.name}」发起续约吗？续约成功后将自动替换应用绑定。`,
                    onOk: () => renewMutation.mutate(record.id),
                  })
                }
              >
                立即续约
              </Button>
            )}
          {hasPermission(permissions, 'certificates.bind') && record.status !== 'REPLACED' && (
            <>
              <Button
                type="link"
                size="small"
                onClick={() => setBinding({ operation: 'bind', certificate: record })}
              >
                绑定/替换
              </Button>
              {record.usage_count > 0 && (
                <Button
                  type="link"
                  size="small"
                  danger
                  onClick={() => setBinding({ operation: 'unbind', certificate: record })}
                >
                  解绑
                </Button>
              )}
            </>
          )}
          {hasPermission(permissions, 'certificates.delete') && (
            <Button
              type="link"
              size="small"
              danger
              disabled={record.usage_count > 0}
              onClick={() =>
                modal.confirm({
                  title: '删除确认',
                  content: `确定删除证书「${record.name}」吗？删除后不可恢复。`,
                  okButtonProps: { danger: true },
                  onOk: () => removeMutation.mutate(record.id),
                })
              }
            >
              删除
            </Button>
          )}
        </Space>
      ),
    },
  ]

  const detail = detailQuery.data
  const detailIsGM = isGMProtocol(detail?.protocol_type)

  return (
    <Card
      title="HTTPS 证书"
      extra={
        <Space>
          {hasPermission(permissions, 'certificates.read') && (
            <Button icon={<SettingOutlined />} onClick={() => setAcmeSettingsOpen(true)}>
              自动证书（ACME）设置
            </Button>
          )}
          {hasPermission(permissions, 'certificates.create') && (
            <Button
              type="primary"
              icon={<PlusOutlined />}
              onClick={() => setUploadOpen(true)}
            >
              上传证书
            </Button>
          )}
        </Space>
      }
    >
      <Tabs
        activeKey={activeTab}
        onChange={(k) => setActiveTab(k as 'list' | 'orders')}
        items={[
          {
            key: 'list',
            label: '证书台账',
            children: (
              <>
                <Space style={{ marginBottom: 16 }} wrap>
                  <Input.Search
                    placeholder="搜索名称或 CN"
                    allowClear
                    style={{ width: 240 }}
                    onSearch={(v) => {
                      setFilters((f) => ({ ...f, name: v || undefined }))
                      setPage(1)
                    }}
                  />
                  <Select
                    aria-label="协议类型"
                    placeholder="全部协议"
                    allowClear
                    style={{ width: 170 }}
                    value={filters.protocol_type}
                    options={[
                      { value: 'INTERNATIONAL', label: '通用国际证书' },
                      { value: 'SM_TLCP', label: '国密双证书(SM2)' },
                    ]}
                    onChange={(v: CertificateProtocolType | undefined) => {
                      setFilters((f) => ({ ...f, protocol_type: v }))
                      setPage(1)
                    }}
                  />
                  <Select
                    placeholder="状态"
                    allowClear
                    style={{ width: 150 }}
                    options={Object.entries(CERT_STATUS_META).map(([value, meta]) => ({
                      value,
                      label: meta.label,
                    }))}
                    onChange={(v) => {
                      setFilters((f) => ({ ...f, status: v }))
                      setPage(1)
                    }}
                  />
                  <Checkbox
                    checked={Boolean(filters.include_replaced)}
                    onChange={(e) => {
                      setFilters((f) => ({ ...f, include_replaced: e.target.checked || undefined }))
                      setPage(1)
                    }}
                  >
                    显示已续签替换证书
                  </Checkbox>
                  {batchDeleteButton}
                </Space>

                {listQuery.isError ? (
                  <Alert
                    type="error"
                    showIcon
                    message="加载证书列表失败"
                    description={listQuery.error instanceof ApiError ? listQuery.error.message : undefined}
                  />
                ) : (
                  <SmartTable<CertificateItem>
                    storageKey="certificates"
                    rowKey="id"
                    rowSelection={rowSelection}
                    loading={listQuery.isLoading}
                    columns={columns}
                    dataSource={listQuery.data?.items}
                    onRow={(record) => ({
                      onDoubleClick: () => setDetailId(record.id),
                      style: { cursor: 'pointer' },
                    })}
                    scroll={{ x: 1520 }}
                    pagination={{
                      current: page,
                      pageSize,
                      total: listQuery.data?.total ?? 0,
                      showSizeChanger: true,
                      showTotal: (t) => `共 ${t} 条`,
                      onChange: (p, ps) => {
                        setPage(p)
                        setPageSize(ps)
                      },
                    }}
                  />
                )}
              </>
            ),
          },
          {
            key: 'orders',
            label: '自动申请与续约记录',
            children: <AcmeOrdersTable />,
          },
        ]}
      />

      <CertificateUploadModal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onSuccess={() => {
          setUploadOpen(false)
          void invalidate()
        }}
        onConflict={() => {
          void invalidate()
        }}
      />

      <Drawer
        title={detail ? `证书详情：${detail.name}` : '证书详情'}
        open={detailId !== null}
        onClose={() => setDetailId(null)}
        width={660}
      >
        {detailQuery.isLoading && <Typography.Text type="secondary">加载中…</Typography.Text>}
        {detailQuery.isError && (
          <Alert
            type="error"
            showIcon
            message="加载证书详情失败"
            description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          />
        )}
        {detail && (
          <>
            <Descriptions column={1} size="small" bordered>
              <Descriptions.Item label="名称">{detail.name}</Descriptions.Item>
              <Descriptions.Item label="协议类型">
                <StatusTag value={detail.protocol_type ?? 'INTERNATIONAL'} map={CERT_PROTOCOL_META} />
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                <StatusTag value={detail.status} map={CERT_STATUS_META} />
              </Descriptions.Item>
              <Descriptions.Item label="托管方式">
                {detail.managed_by === 'ACME' ? (
                  <Space>
                    <Tag color="cyan">ACME 自动续约</Tag>
                    {detail.acme_provider && <StatusTag value={detail.acme_provider} map={ACME_PROVIDER_META} />}
                  </Space>
                ) : (
                  <Tag>手动上传</Tag>
                )}
              </Descriptions.Item>
              {detail.managed_by === 'ACME' && (
                <>
                  <Descriptions.Item label="提前续约天数">
                    到期前 {detail.renew_before_days ?? 30} 天
                  </Descriptions.Item>
                  <Descriptions.Item label="最近续约时间">
                    {formatDateTime(detail.last_renewed_at)}
                  </Descriptions.Item>
                </>
              )}
              <Descriptions.Item label={detailIsGM ? '签名证书 CN' : '通用名称(CN)'}>
                {detail.common_name}
              </Descriptions.Item>
              <Descriptions.Item label={detailIsGM ? '签名证书主题' : '主题'}>
                {detail.subject}
              </Descriptions.Item>
              <Descriptions.Item label={detailIsGM ? '签名证书颁发者' : '颁发者'}>
                {detail.issuer}
              </Descriptions.Item>
              <Descriptions.Item label={detailIsGM ? '签名证书序列号' : '序列号'}>
                {detail.serial_number}
              </Descriptions.Item>
              <Descriptions.Item label="备用域名">
                {detail.san_domains && detail.san_domains.length > 0 ? (
                  <Space wrap>
                    {detail.san_domains.map((d) => (
                      <Tag key={d}>{d}</Tag>
                    ))}
                  </Space>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label={detailIsGM ? '签名证书有效期' : '有效期'}>
                {formatDateTime(detail.not_before)} ~ {formatDateTime(detail.not_after)}
                {(() => {
                  const days = certRemainingDays(detail.not_after)
                  if (days === null) return null
                  return (
                    <Tag color={certRemainingColor(days)} style={{ marginLeft: 8 }}>
                      {days < 0 ? `已过期 ${-days} 天` : `剩余 ${days} 天`}
                    </Tag>
                  )
                })()}
              </Descriptions.Item>
              <Descriptions.Item label={detailIsGM ? '签名证书 SHA256 指纹' : 'SHA256 指纹'}>
                <Typography.Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {detail.fingerprint_sha256}
                </Typography.Text>
              </Descriptions.Item>
              <Descriptions.Item label="公钥算法">
                {detail.public_key_algorithm} {detail.public_key_bits > 0 ? `${detail.public_key_bits} 位` : ''}
              </Descriptions.Item>
              <Descriptions.Item label="签名算法">{detail.signature_algorithm}</Descriptions.Item>
              <Descriptions.Item label="绑定应用">
                <BoundApplications certId={detail.id} />
              </Descriptions.Item>
              <Descriptions.Item label="上传时间">{formatDateTime(detail.created_at)}</Descriptions.Item>
            </Descriptions>

            {detailIsGM && (
              <>
                <Divider titlePlacement="start" plain style={{ fontSize: 13, margin: '16px 0 12px' }}>
                  加密证书信息（SM2 加密）
                </Divider>
                <Descriptions column={1} size="small" bordered>
                  <Descriptions.Item label="加密证书 CN">
                    {detail.enc_common_name || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="加密证书主题">
                    {detail.enc_subject || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="加密证书颁发者">
                    {detail.enc_issuer || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="加密证书序列号">
                    {detail.enc_serial_number || '-'}
                  </Descriptions.Item>
                  <Descriptions.Item label="加密证书有效期">
                    {detail.enc_not_before || detail.enc_not_after ? (
                      <>
                        {formatDateTime(detail.enc_not_before)} ~ {formatDateTime(detail.enc_not_after)}
                        {(() => {
                          const days = certRemainingDays(detail.enc_not_after)
                          if (days === null) return null
                          return (
                            <Tag color={certRemainingColor(days)} style={{ marginLeft: 8 }}>
                              {days < 0 ? `已过期 ${-days} 天` : `剩余 ${days} 天`}
                            </Tag>
                          )
                        })()}
                      </>
                    ) : (
                      '-'
                    )}
                  </Descriptions.Item>
                  <Descriptions.Item label="加密证书 SHA256 指纹">
                    {detail.enc_fingerprint_sha256 ? (
                      <Typography.Text copyable style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {detail.enc_fingerprint_sha256}
                      </Typography.Text>
                    ) : (
                      '-'
                    )}
                  </Descriptions.Item>
                </Descriptions>
              </>
            )}
          </>
        )}
      </Drawer>
      <AcmeSettingsModal open={acmeSettingsOpen} onClose={() => setAcmeSettingsOpen(false)} />
      {binding && (
        <CertificateBindingModal
          open
          operation={binding.operation}
          certificate={binding.certificate}
          onClose={() => setBinding(null)}
        />
      )}
    </Card>
  )
}
