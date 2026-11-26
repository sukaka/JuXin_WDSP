import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Alert,
  App as AntdApp,
  Button,
  Card,
  Descriptions,
  Space,
  Spin,
  Tabs,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import ProtectionModeTag from '../../components/ProtectionModeTag'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { useProductStore } from '../../stores/product'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import {
  APP_HEALTH_META,
  APP_STATUS_META,
  DEPLOYMENT_MODE_META,
  DEPLOYMENT_STATUS_META,
} from '../../utils/stage3'
import ApplicationAssetValueCard from './ApplicationAssetValueCard'
import DomainsTab from './detail/DomainsTab'
import UpstreamsTab from './detail/UpstreamsTab'
import CertificatesTab from './detail/CertificatesTab'
import TLSProtocolPolicyCard from './detail/TLSProtocolPolicyCard'
import HeaderProxyTab from './detail/HeaderProxyTab'
import JwtTrustTab from './detail/JwtTrustTab'
import BotPolicyTab from './detail/BotPolicyTab'
import AiCrawlTab from './detail/AiCrawlTab'
import ClientSideTab from './detail/ClientSideTab'

export default function ApplicationDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const webWafEnabled = useProductStore((s) => s.webWafEnabled)

  const detailQuery = useQuery({
    queryKey: ['application', id],
    queryFn: () => applicationsApi.get(id),
    enabled: id !== '',
  })

  const toggleMutation = useMutation({
    mutationFn: (action: 'enable' | 'disable') =>
      action === 'enable'
        ? applicationsApi.enable(id)
        : applicationsApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void queryClient.invalidateQueries({ queryKey: ['application', id] })
      void queryClient.invalidateQueries({ queryKey: ['applications'] })
    },
    onError: (e) =>
      message.error(e instanceof ApiError ? e.message : '操作失败'),
  })

  // 面包屑注入当前应用名（卸载时自动清理）
  useBreadcrumbObjectName(detailQuery.data?.name)

  if (detailQuery.isLoading) {
    return (
      <div style={{ display: 'flex', justifyContent: 'center', padding: 64 }}>
        <Spin size="large" />
      </div>
    )
  }

  if (detailQuery.isError || !detailQuery.data) {
    return (
      <Card>
        <Alert
          type="error"
          showIcon
          message="加载应用详情失败"
          description={
            detailQuery.error instanceof ApiError
              ? detailQuery.error.message
              : undefined
          }
          action={
            <Button onClick={() => navigate('/applications')}>返回列表</Button>
          }
        />
      </Card>
    )
  }

  const app = detailQuery.data
  const hasHttps = app.domains.some((d) => d.https_enabled)
  const isMirror = app.deployment_mode === 'MIRROR'
  const isTransparent = app.deployment_mode === 'TRANSPARENT'

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      <Card
        title={
          <Space>
            <Tooltip title="返回应用列表">
              <Button
                type="text"
                icon={<ArrowLeftOutlined />}
                aria-label="返回应用列表"
                onClick={() => navigate('/applications')}
              />
            </Tooltip>
            <span>{app.name}</span>
            <ProtectionModeTag mode={app.protection_mode} />
            <StatusTag
              value={app.deployment_mode || 'REVERSE_PROXY'}
              map={DEPLOYMENT_MODE_META}
            />
            <StatusTag value={app.status} map={APP_STATUS_META} />
            <StatusTag
              value={app.deployment_status}
              map={DEPLOYMENT_STATUS_META}
            />
          </Space>
        }
        extra={
          hasPermission(permissions, 'applications.disable') &&
          (app.status === 'ACTIVE' ? (
            <Button
              danger
              onClick={() =>
                modal.confirm({
                  title: '停用确认',
                  content: `确定停用应用「${app.name}」吗？停用后防护与转发将失效。`,
                  okButtonProps: { danger: true },
                  onOk: () => toggleMutation.mutate('disable'),
                })
              }
            >
              停用应用
            </Button>
          ) : (
            <Button
              type="primary"
              onClick={() => toggleMutation.mutate('enable')}
            >
              启用应用
            </Button>
          ))
        }
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用标识">
            <Typography.Text code copyable>
              {app.code}
            </Typography.Text>
          </Descriptions.Item>
          <Descriptions.Item label="业务负责人">
            {app.business_owner || '-'}
          </Descriptions.Item>
          <Descriptions.Item label="技术负责人">
            {app.technical_owner || '-'}
          </Descriptions.Item>
          <Descriptions.Item label="描述">
            {app.description || '-'}
          </Descriptions.Item>
          {webWafEnabled && (
            <Descriptions.Item label="默认防护策略">
              {app.protection_policy ? (
                <Space size={4} wrap>
                  <Tag color="blue">{app.protection_policy.name}</Tag>
                  <ProtectionModeTag mode={app.protection_policy.protection_mode} />
                  <Tag color="geekblue">{`PL${app.protection_policy.paranoia_level}`}</Tag>
                </Space>
              ) : (
                <Typography.Text type="secondary">
                  未绑定（按应用防护模式）
                </Typography.Text>
              )}
            </Descriptions.Item>
          )}
          <Descriptions.Item label="健康状态">
            <StatusTag
              value={
                app.health_status && APP_HEALTH_META[app.health_status]
                  ? app.health_status
                  : 'UNKNOWN'
              }
              map={APP_HEALTH_META}
            />
          </Descriptions.Item>
          <Descriptions.Item label="最后发布时间">
            {formatDateTime(app.last_publish_at)}
          </Descriptions.Item>
          <Descriptions.Item label="创建时间">
            {formatDateTime(app.created_at)}
          </Descriptions.Item>
          <Descriptions.Item label="更新时间">
            {formatDateTime(app.updated_at)}
          </Descriptions.Item>
        </Descriptions>
      </Card>

      {isMirror && (
        <Alert
          type="info"
          showIcon
          message="当前应用为镜像旁路模式（仅检测、不阻断、不转发）"
          description="流量副本经镜像口送达 mirrorcap，仅分析配置域名对应的明文 HTTP/1.x 端口（HTTPS 流量无需证书，仅通过 TLS SNI 参与站点资产发现）。源站管理、代理与头合规、Bot 挑战、证书绑定等在线反代能力不适用于镜像旁路模式。"
        />
      )}

      {isTransparent && (
        <Alert
          type="info"
          showIcon
          message="当前应用为透明串接模式（二层桥接在线检测与阻断）"
          description="透明串接属在线阻断桥接模式，生效前需确认：（1）已在「网络配置」完成网桥配置；（2）在「域名管理」配置访问域名与真实目标端口（启用 HTTPS 时须在「证书绑定」上传对应证书）；（3）在「源站管理」配置至少 1 个已启用的源站服务器。同 IP 下未纳管的 HTTPS 站点按 fail-closed 策略处理，不会自动透传，需显式加入透明 TLS 透传白名单。"
        />
      )}

      <Card>
        <Tabs
          items={[
            {
              key: 'domains',
              label: `域名管理 (${app.domains.length})`,
              children: (
                <DomainsTab
                  appId={app.id}
                  deploymentMode={app.deployment_mode}
                  appProtectionMode={app.protection_mode}
                  appProtectionPolicy={app.protection_policy}
                />
              ),
            },
            {
              key: 'upstreams',
              label: `源站管理 (${app.upstreams.length})`,
              children: <UpstreamsTab appId={app.id} deploymentMode={app.deployment_mode} />,
            },
            {
              key: 'header-proxy',
              label: '代理与头合规',
              children: <HeaderProxyTab appId={app.id} />,
            },
            // JWT 信任策略（WDSP P0-03）：无 jwt_trust.read 权限不露入口
            ...(hasPermission(permissions, 'jwt_trust.read')
              ? [
                  {
                    key: 'jwt-trust',
                    label: 'JWT 信任策略',
                    children: <JwtTrustTab appId={app.id} appCode={app.code} />,
                  },
                ]
              : []),
            // Bot 挑战策略（WDSP P1-02 B4）：无 bot_policy.read 权限不露入口
            ...(hasPermission(permissions, 'bot_policy.read')
              ? [
                  {
                    key: 'bot-policy',
                    label: 'Bot 挑战策略',
                    children: (
                      <BotPolicyTab appId={app.id} appCode={app.code} />
                    ),
                  },
                ]
              : []),
            // AI 爬虫治理与迷宫策略（WDSP Phase 9A-2）：无 ai_crawl.read 权限不露入口
            ...(hasPermission(permissions, 'ai_crawl.read')
              ? [
                  {
                    key: 'ai-crawl',
                    label: 'AI 爬虫治理',
                    children: (
                      <AiCrawlTab appId={app.id} appCode={app.code} />
                    ),
                  },
                ]
              : []),
            // 客户端供应链安全（WDSP Phase 9B / PCI DSS 4.0 6.4.3 & 11.6.1）：无 client_side.read 权限不露入口
            ...(hasPermission(permissions, 'client_side.read')
              ? [
                  {
                    key: 'client-side',
                    label: '客户端供应链安全',
                    children: (
                      <ClientSideTab appId={app.id} appCode={app.code} />
                    ),
                  },
                ]
              : []),
            // 证书绑定：无 certificates.read 权限不露入口，避免跨模块请求触发 403
            ...(hasPermission(permissions, 'certificates.read')
              ? [
                  {
                    key: 'certificates',
                    label: '证书绑定',
                    children: isMirror ? (
                      <Alert
                        type="info"
                        showIcon
                        message="镜像旁路模式不终结 TLS，无需绑定 HTTPS 证书（HTTPS 仅经 TLS SNI 被动发现站点，无法解密检测）"
                      />
                    ) : hasHttps ? (
                      <CertificatesTab application={app} />
                    ) : (
                      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
                        <Alert
                          type="info"
                          showIcon
                          message="当前应用未启用 HTTPS 域名，无需绑定证书"
                        />
                        {hasPermission(permissions, 'applications.read') && (
                          <TLSProtocolPolicyCard appId={app.id} />
                        )}
                      </Space>
                    ),
                  },
                ]
              : []),
            // API 资产价值（按接口评分聚合）：无 api_asset.read 权限不露入口，避免跨模块请求触发 403
            ...(hasPermission(permissions, 'api_asset.read')
              ? [
                  {
                    key: 'asset-value',
                    label: 'API 资产价值',
                    children: (
                      <ApplicationAssetValueCard
                        applicationId={app.id}
                        embedded
                      />
                    ),
                  },
                ]
              : []),
          ]}
        />
      </Card>
    </Space>
  )
}
