import { useQuery } from '@tanstack/react-query'
import { Alert, Table, Tag, Tooltip } from 'antd'
import type { ColumnsType } from 'antd/es/table'
import { ApiError } from '../../../api/client'
import { certificatesApi } from '../../../api/certificates'
import { formatDateTime } from '../../../utils/format'
import { CERT_STATUS_META, certRemainingColor, certRemainingDays } from '../../../utils/stage3'
import type { CertificateItem } from '../../../types'

/**
 * 应用维度的证书绑定查询：
 * 后端暂无“按应用查询绑定证书”的接口，这里通过证书列表 + 各证书的绑定应用列表反查（前 100 个证书）。
 */
async function fetchBoundCertificates(appId: string): Promise<CertificateItem[]> {
  const page = await certificatesApi.list({ page: 1, page_size: 100 })
  const certs = page.items ?? []
  if (certs.length === 0) return []
  const flags = await Promise.all(
    certs.map((cert) =>
      certificatesApi
        .applications(cert.id)
        .then((r) => (r.application_ids ?? []).includes(appId))
        .catch(() => false),
    ),
  )
  return certs.filter((_, i) => flags[i])
}

export default function CertificatesTab({ appId }: { appId: string }) {
  const boundQuery = useQuery({
    queryKey: ['app-certificates', appId],
    queryFn: () => fetchBoundCertificates(appId),
  })

  const columns: ColumnsType<CertificateItem> = [
    { title: '证书名称', dataIndex: 'name', width: 180 },
    { title: '通用名称(CN)', dataIndex: 'common_name', width: 180 },
    {
      title: 'SAN 域名',
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

  return (
    <div>
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="证书绑定关系由后端发布流程管理"
        description="当前后端未提供证书绑定/解绑的 HTTP 接口（certificates.bind 权限已预留），本页展示已绑定到本应用的证书。绑定与替换请在后续版本通过发布流程完成。"
      />
      {boundQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载绑定证书失败"
          description={boundQuery.error instanceof ApiError ? boundQuery.error.message : undefined}
        />
      ) : (
        <Table<CertificateItem>
          rowKey="id"
          loading={boundQuery.isLoading}
          columns={columns}
          dataSource={boundQuery.data}
          pagination={false}
          locale={{ emptyText: '当前应用未绑定证书' }}
        />
      )}
    </div>
  )
}
