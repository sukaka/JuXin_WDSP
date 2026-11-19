import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Alert, Button, Space, Tag, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../../api/client'
import { certificatesApi } from '../../../api/certificates'
import RecordDetailDrawer from '../../../components/RecordDetailDrawer'
import SmartTable from '../../../components/SmartTable'
import CertificateBindingModal from '../../certificates/CertificateBindingModal'
import { useAuthStore } from '../../../stores/auth'
import { formatDateTime } from '../../../utils/format'
import { hasPermission } from '../../../utils/permission'
import { CERT_STATUS_META, certRemainingColor, certRemainingDays } from '../../../utils/stage3'
import type { ApplicationItem, CertificateItem } from '../../../types'

export default function CertificatesTab({ application }: { application: ApplicationItem }) {
  const [detailRecord, setDetailRecord] = useState<CertificateItem | null>(null)
  const [operation, setOperation] = useState<'bind' | 'unbind' | null>(null)
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canRead = hasPermission(permissions, 'certificates.read')
  const canBind = hasPermission(permissions, 'certificates.bind')

  const boundQuery = useQuery({
    queryKey: ['app-certificates', application.id],
    queryFn: () => certificatesApi.applicationCertificate(application.id),
    enabled: canRead,
  })
  const boundCertificate = boundQuery.data?.certificate ?? null

  const columns: ColumnsType<CertificateItem> = [
    { title: '证书名称', dataIndex: 'name', width: 180 },
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
        return <Tag color={certRemainingColor(days)}>{days < 0 ? `已过期 ${-days} 天` : `${days} 天`}</Tag>
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
        message="缺少 certificates.read 权限，无法查看证书绑定信息"
      />
    )
  }

  return (
    <div>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="证书绑定、替换和解绑均需经过配置发布后生效"
        description="后端会校验证书有效期及 CN/SAN 对应用全部 HTTPS 域名的覆盖。保存关系后可在操作结果中直接进入配置发布页。"
      />
      {canBind && (
        <Space style={{ marginBottom: 16 }}>
          <Button type="primary" onClick={() => setOperation('bind')}>
            {boundCertificate ? '替换证书' : '绑定证书'}
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
          locale={{ emptyText: '当前应用未绑定证书' }}
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
    </div>
  )
}
