import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Col,
  Descriptions,
  Progress,
  Row,
  Space,
  Spin,
  Statistic,
  Tag,
  Typography,
  Upload,
} from 'antd'
import { InboxOutlined, ReloadOutlined } from '@ant-design/icons'
import type { ColumnsType } from 'antd/es/table'
import RecordDetailDrawer from '../../components/RecordDetailDrawer'
import SmartTable from '../../components/SmartTable'
import { ApiError } from '../../api/client'
import { licenseApi } from '../../api/license'
import { useAuthStore } from '../../stores/auth'
import { useLicenseStore } from '../../stores/license'
import { useProductStore } from '../../stores/product'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import type {
  LicenseArtifactIntegrity,
  LicenseCommercialAuthorization,
  LicenseConfidentialComputing,
  LicenseGatewayProtection,
  LicenseHistoryItem,
  LicenseProtectionForm,
  LicenseRecordStatus,
  LicenseRecovery,
} from '../../types'

/** 产品形态中文名（'' = 未授权） */
const PRODUCT_NAMES: Record<string, string> = {
  waf: '九章WEB应用智能防护系统',
  wdsp: '九章Web动态防护系统',
  api: '九章API安全系统',
}

const LICENSE_TYPE_LABELS: Record<string, string> = {
  FORMAL: '正式授权',
  TRIAL: '试用授权',
}

const RECORD_STATUS_TAGS: Record<LicenseRecordStatus, { color: string; label: string }> = {
  ACTIVE: { color: 'green', label: '生效中' },
  EXPIRED: { color: 'red', label: '已到期' },
  FINGERPRINT_MISMATCH: { color: 'orange', label: '指纹不匹配' },
  SUPERSEDED: { color: 'default', label: '已被取代' },
  INVALID: { color: 'red', label: '无效' },
}

type ProtectionTag = { color: string; label: string }

const PROTECTION_FORM_TAGS: Record<LicenseProtectionForm, ProtectionTag> = {
  STANDARD_OFFLINE: { color: 'blue', label: '标准离线交付' },
  CONFIDENTIAL_COMPUTING: { color: 'purple', label: '机密计算交付' },
  UNKNOWN: { color: 'default', label: '未知交付形态' },
}

const COMMERCIAL_AUTHORIZATION_TAGS: Record<LicenseCommercialAuthorization, ProtectionTag> = {
  AUTHORIZED: { color: 'green', label: '商业授权有效' },
  NOT_IMPORTED: { color: 'orange', label: '未导入授权' },
  EXPIRED: { color: 'red', label: '授权已到期' },
  DEVICE_MISMATCH: { color: 'red', label: '设备不匹配' },
  INVALID: { color: 'red', label: '授权无效' },
  UNKNOWN: { color: 'default', label: '授权状态未知' },
}

const ARTIFACT_INTEGRITY_TAGS: Record<LicenseArtifactIntegrity, ProtectionTag> = {
  VERIFIED: { color: 'green', label: '完整性已验证' },
  PENDING_MIGRATION: { color: 'orange', label: '等待迁移验证' },
  UNVERIFIABLE: { color: 'orange', label: '暂无法验证完整性' },
  FAILED: { color: 'red', label: '完整性验证失败' },
  UNKNOWN: { color: 'default', label: '完整性状态未知' },
}

const GATEWAY_PROTECTION_TAGS: Record<LicenseGatewayProtection, ProtectionTag> = {
  PROTECTED: { color: 'green', label: '网关防护可用' },
  BYPASS: { color: 'orange', label: '网关处于旁路' },
  UNAVAILABLE: { color: 'red', label: '网关防护不可用' },
  PRESERVE_EXISTING: { color: 'blue', label: '保持既有防护配置' },
  UNKNOWN: { color: 'default', label: '实际防护状态未知' },
}

const CONFIDENTIAL_COMPUTING_TAGS: Record<LicenseConfidentialComputing, ProtectionTag> = {
  DISABLED: { color: 'default', label: '机密计算未启用' },
  VERIFIED: { color: 'green', label: '机密计算证明有效' },
  FAILED: { color: 'red', label: '机密计算证明失败' },
  UNSUPPORTED: { color: 'orange', label: '当前平台不支持' },
  UNAVAILABLE: { color: 'orange', label: '机密计算暂不可用' },
  UNKNOWN: { color: 'default', label: '机密计算状态未知' },
}

const RECOVERY_TAGS: Record<LicenseRecovery, ProtectionTag> = {
  NONE: { color: 'green', label: '无需恢复' },
  IMPORT_LICENSE: { color: 'blue', label: '重新导入签名授权' },
  REVALIDATE_PACKAGE: { color: 'blue', label: '重新验证交付包' },
  KEEP_LAST_CONFIG: { color: 'orange', label: '保持上次有效配置' },
  SUPPORT_REQUIRED: { color: 'orange', label: '需要支持介入' },
  UNKNOWN: { color: 'default', label: '恢复路径未知' },
}

function protectionTag<T extends string>(
  value: T | undefined,
  tags: Record<T, ProtectionTag>,
): ProtectionTag {
  return (value && tags[value]) || { color: 'default', label: '状态未知' }
}

function ProtectionStatusTag({ status }: { status: ProtectionTag }) {
  return <Tag color={status.color}>{status.label}</Tag>
}

/** 临期阈值：剩余 ≤ 7 天红色倒计时（与后端临期告警口径一致） */
const EXPIRING_SOON_DAYS = 7

/** 剩余天数（到期日含当天；后端按 UTC 日界判定，前端按本地时间近似倒计时） */
function remainDays(expiresAt: string): number {
  return Math.ceil((Date.parse(expiresAt) - Date.now()) / 86_400_000)
}

/** 到期时间：null = 永久；≤ 7 天红色倒计时 */
function ExpiryText({ expiresAt }: { expiresAt: string | null }) {
  if (!expiresAt) return <>永久</>
  const days = remainDays(expiresAt)
  if (days <= EXPIRING_SOON_DAYS) {
    return (
      <Typography.Text type="danger">
        {formatDateTime(expiresAt)}（剩余 {Math.max(days, 0)} 天）
      </Typography.Text>
    )
  }
  return <>{formatDateTime(expiresAt)}</>
}

/** 配额项：0 = 不限；usage 缺失时只显示上限 */
function QuotaItem({
  title,
  quota,
  used,
  suffix,
}: {
  title: string
  quota: number
  used?: number
  suffix?: string
}) {
  if (quota <= 0) {
    return <Statistic title={title} value="不限" />
  }
  const percent = used !== undefined ? Math.min(100, Math.round((used / quota) * 100)) : undefined
  return (
    <div>
      <Statistic
        title={title}
        value={used !== undefined ? `${used} / ${quota}` : quota}
        suffix={suffix}
      />
      {percent !== undefined && (
        <Progress percent={percent} size="small" status={percent >= 100 ? 'exception' : 'active'} />
      )}
    </div>
  )
}

export default function LicensePage() {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canManage = hasPermission(permissions, 'license.manage')
  const canReadHistory = hasPermission(permissions, 'license.read')
  const status = useLicenseStore((s) => s.status)
  const initialized = useLicenseStore((s) => s.initialized)
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(20)
  const [detailRecord, setDetailRecord] = useState<LicenseHistoryItem | null>(null)

  // 兜底拉取（正常流程授权守卫已保证状态加载完成）
  useEffect(() => {
    if (!useLicenseStore.getState().initialized) {
      void useLicenseStore.getState().load()
    }
  }, [])

  const historyQuery = useQuery({
    queryKey: ['license-history', page, pageSize],
    queryFn: () => licenseApi.history(page, pageSize),
    enabled: canReadHistory,
  })

  const importMutation = useMutation({
    mutationFn: (file: File) => licenseApi.import(file),
    onSuccess: (state) => {
      message.success('授权导入成功')
      useLicenseStore.getState().setStatus(state)
      // 生效产品形态可能随授权变化，重新加载产品能力
      void useProductStore.getState().load()
      void queryClient.invalidateQueries({ queryKey: ['license-history'] })
    },
    onError: (e) => {
      // 导入失败：响应信封 message（中文）原样展示
      message.error(e instanceof ApiError ? e.message : '授权导入失败')
    },
  })

  const columns: ColumnsType<LicenseHistoryItem> = [
    {
      title: '授权编号',
      dataIndex: 'license_id',
      width: 200,
      render: (v: string) => <Typography.Text code>{v}</Typography.Text>,
    },
    {
      title: '类型',
      dataIndex: 'license_type',
      width: 90,
      render: (v: string) => LICENSE_TYPE_LABELS[v] ?? v,
    },
    {
      title: '产品',
      dataIndex: 'product',
      width: 90,
      render: (v: string) => <Tag>{v.toUpperCase()}</Tag>,
    },
    { title: '客户', dataIndex: 'customer', render: (v: string) => v || '-' },
    {
      title: '导入时间',
      dataIndex: 'imported_at',
      width: 170,
      render: (v: string) => formatDateTime(v),
    },
    {
      title: '到期',
      key: 'expires',
      width: 170,
      render: (_, item) => (item.perpetual || !item.expires_at ? '永久' : formatDateTime(item.expires_at)),
    },
    {
      title: '状态',
      dataIndex: 'status',
      width: 110,
      render: (v: LicenseRecordStatus) => {
        const t = RECORD_STATUS_TAGS[v]
        return t ? <Tag color={t.color}>{t.label}</Tag> : <Tag>{v}</Tag>
      },
    },
    {
      title: '导入人',
      dataIndex: 'imported_by',
      width: 120,
      render: (v: string | null) =>
        v ? (
          <Typography.Text code style={{ fontSize: 12 }}>
            {v.slice(0, 8)}…
          </Typography.Text>
        ) : (
          '系统'
        ),
    },
  ]

  if (!initialized) {
    return (
      <Card>
        <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
          <Spin size="large" tip="加载授权状态..." />
        </div>
      </Card>
    )
  }

  if (!status) {
    return (
      <Card title="授权管理">
        <Alert
          type="error"
          showIcon
          message="加载授权状态失败"
          description="请检查网络连接后重试；授权无效期间系统处于锁定状态。"
          action={
            <Button icon={<ReloadOutlined />} onClick={() => void useLicenseStore.getState().load()}>
              重试
            </Button>
          }
        />
      </Card>
    )
  }

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card
        title="授权状态"
        extra={
          <Button icon={<ReloadOutlined />} onClick={() => void useLicenseStore.getState().load()}>
            刷新状态
          </Button>
        }
      >
        <Space direction="vertical" size="middle" style={{ width: '100%' }}>
          <div>
            {status.valid ? (
              <Tag color="green" style={{ fontSize: 18, padding: '4px 16px' }}>
                授权有效
              </Tag>
            ) : (
              <Tag color="red" style={{ fontSize: 18, padding: '4px 16px' }}>
                授权无效
              </Tag>
            )}
          </div>
          <Descriptions bordered size="small" column={2}>
            <Descriptions.Item label="产品形态">
              {PRODUCT_NAMES[status.product] ?? '未授权'}
            </Descriptions.Item>
            <Descriptions.Item label="授权类型">
              {LICENSE_TYPE_LABELS[status.license_type] ?? '-'}
            </Descriptions.Item>
            <Descriptions.Item label="客户">{status.customer || '-'}</Descriptions.Item>
            <Descriptions.Item label="授权编号">{status.license_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="到期时间" span={status.valid ? 1 : 2}>
              {status.valid ? <ExpiryText expiresAt={status.expires_at} /> : '-'}
            </Descriptions.Item>
            {!status.valid && (
              <Descriptions.Item label="无效原因" span={2}>
                <Typography.Text type="danger">{status.reason || '-'}</Typography.Text>
              </Descriptions.Item>
            )}
          </Descriptions>
        </Space>
      </Card>

      <Card title="授权与防护状态">
        {status.protection_state ? (
          <>
            <Descriptions bordered size="small" column={2}>
              <Descriptions.Item label="交付形态">
                <ProtectionStatusTag
                  status={protectionTag(
                    status.protection_state.protection_form,
                    PROTECTION_FORM_TAGS,
                  )}
                />
              </Descriptions.Item>
              <Descriptions.Item label="商业授权">
                <ProtectionStatusTag
                  status={protectionTag(
                    status.protection_state.commercial_authorization,
                    COMMERCIAL_AUTHORIZATION_TAGS,
                  )}
                />
              </Descriptions.Item>
              <Descriptions.Item label="产物/授权完整性">
                <ProtectionStatusTag
                  status={protectionTag(
                    status.protection_state.artifact_integrity,
                    ARTIFACT_INTEGRITY_TAGS,
                  )}
                />
              </Descriptions.Item>
              <Descriptions.Item label="网关实际防护">
                <ProtectionStatusTag
                  status={protectionTag(
                    status.protection_state.gateway_protection,
                    GATEWAY_PROTECTION_TAGS,
                  )}
                />
              </Descriptions.Item>
              <Descriptions.Item label="机密计算">
                <ProtectionStatusTag
                  status={protectionTag(
                    status.protection_state.confidential_computing,
                    CONFIDENTIAL_COMPUTING_TAGS,
                  )}
                />
              </Descriptions.Item>
              <Descriptions.Item label="恢复路径">
                <ProtectionStatusTag
                  status={protectionTag(status.protection_state.recovery, RECOVERY_TAGS)}
                />
              </Descriptions.Item>
              {status.protection_state.reason && (
                <Descriptions.Item label="状态说明" span={2}>
                  {status.protection_state.reason}
                </Descriptions.Item>
              )}
            </Descriptions>
            <Typography.Text type="secondary" style={{ display: 'block', marginTop: 8, fontSize: 12 }}>
              版本：{status.protection_state.schema_version || '未提供'}。这些状态分别来自后端证据，不由“授权有效”单独推断。
            </Typography.Text>
          </>
        ) : (
          <Alert
            type="warning"
            showIcon
            message="当前接口未返回多维授权与防护状态"
            description="页面不会据此推断产物完整性、网关实际防护或机密计算已启用；请升级管理端接口或查看发布证据。"
          />
        )}
      </Card>

      <Card title="本机指纹">
        {status.host_fingerprint ? (
          <Space direction="vertical" size={8} style={{ width: '100%' }}>
            <Typography.Text
              code
              copyable={{ text: status.host_fingerprint, tooltips: ['复制指纹', '已复制'] }}
            >
              {status.host_fingerprint}
            </Typography.Text>
            <Typography.Text type="secondary">
              请将本机指纹发给厂家，用于签发绑定本机的授权文件。
            </Typography.Text>
          </Space>
        ) : (
          <Alert
            type="info"
            showIcon
            message="未采集到本机指纹"
            description="安装期指纹采集未执行或指纹文件缺失，绑定机器指纹的授权将无法导入，详见部署文档。"
          />
        )}
      </Card>

      {status.valid && (
        <Card title="授权配额">
          <Row gutter={24}>
            <Col span={8}>
              <QuotaItem
                title="应用数量"
                quota={status.quotas.max_applications}
                used={status.usage?.applications}
              />
            </Col>
            <Col span={8}>
              <QuotaItem
                title="API 数量"
                quota={status.quotas.max_api_endpoints}
                used={status.usage?.api_endpoints}
              />
            </Col>
            <Col span={8}>
              <QuotaItem title="全局 QPS" quota={status.quotas.max_qps} suffix="次/秒" />
            </Col>
          </Row>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            配额为 0 表示不限制。
          </Typography.Text>
        </Card>
      )}

      <Card title="导入授权">
        {canManage ? (
          <Upload.Dragger
            accept=".lic"
            maxCount={1}
            showUploadList={false}
            disabled={importMutation.isPending}
            beforeUpload={(file) => {
              // 高危操作二次确认：导入后立即生效并取代当前授权，误选无效文件会致全系统 423 锁定
              modal.confirm({
                title: '导入授权',
                content: `确定导入授权文件「${file.name}」吗？导入后立即生效并取代当前授权；若新授权无效（过期、指纹不匹配等），系统将进入锁定状态。`,
                okText: '确认导入',
                okType: 'danger',
                onOk: () => importMutation.mutate(file),
              })
              // 阻止 antd 默认上传，由导入 mutation 负责提交
              return false
            }}
          >
            <p className="ant-upload-drag-icon">
              <InboxOutlined />
            </p>
            <p className="ant-upload-text">点击或拖拽 .lic 授权文件到此区域导入</p>
            <p className="ant-upload-hint">
              离线授权文件（.lic，不超过 64KB），导入后立即生效并取代当前授权。
            </p>
          </Upload.Dragger>
        ) : (
          <Alert
            type="info"
            showIcon
            message="当前账号无授权导入权限（license.manage），如需导入授权请联系系统管理员。"
          />
        )}
      </Card>

      <Card title="导入历史">
        {!canReadHistory ? (
          <Alert type="info" showIcon message="当前账号无授权历史查看权限（license.read）。" />
        ) : historyQuery.isError ? (
          <Alert
            type="error"
            showIcon
            message="加载导入历史失败"
            description={
              historyQuery.error instanceof ApiError ? historyQuery.error.message : undefined
            }
          />
        ) : (
          <SmartTable<LicenseHistoryItem>
            storageKey="license-history"
            rowKey="id"
            loading={historyQuery.isLoading}
            columns={columns}
            dataSource={historyQuery.data?.items}
            onRow={(record) => ({
              onDoubleClick: () => setDetailRecord(record),
              style: { cursor: 'pointer' },
            })}
            pagination={{
              current: page,
              pageSize,
              total: historyQuery.data?.total ?? 0,
              showSizeChanger: true,
              showTotal: (t) => `共 ${t} 条`,
              onChange: (p, ps) => {
                setPage(p)
                setPageSize(ps)
              },
            }}
          />
        )}
      </Card>
      <RecordDetailDrawer
        open={detailRecord !== null}
        title="授权记录详情"
        record={detailRecord as Record<string, unknown> | null}
        onClose={() => setDetailRecord(null)}
      />
    </Space>
  )
}
