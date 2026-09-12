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
} from 'antd'
import { ArrowLeftOutlined } from '@ant-design/icons'
import { ApiError } from '../../api/client'
import { applicationsApi } from '../../api/applications'
import ProtectionModeTag from '../../components/ProtectionModeTag'
import StatusTag from '../../components/StatusTag'
import { useAuthStore } from '../../stores/auth'
import { useBreadcrumbObjectName } from '../../stores/breadcrumb'
import { formatDateTime } from '../../utils/format'
import { hasPermission } from '../../utils/permission'
import { APP_STATUS_META, DEPLOYMENT_MODE_META, DEPLOYMENT_STATUS_META } from '../../utils/stage3'
import DomainsTab from './detail/DomainsTab'
import UpstreamsTab from './detail/UpstreamsTab'
import CertificatesTab from './detail/CertificatesTab'
import HeaderProxyTab from './detail/HeaderProxyTab'
import JwtTrustTab from './detail/JwtTrustTab'
import BotPolicyTab from './detail/BotPolicyTab'

export default function ApplicationDetailPage() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)

  const detailQuery = useQuery({
    queryKey: ['application', id],
    queryFn: () => applicationsApi.get(id),
    enabled: id !== '',
  })

  const toggleMutation = useMutation({
    mutationFn: (action: 'enable' | 'disable') =>
      action === 'enable' ? applicationsApi.enable(id) : applicationsApi.disable(id),
    onSuccess: () => {
      message.success('操作成功')
      void queryClient.invalidateQueries({ queryKey: ['application', id] })
      void queryClient.invalidateQueries({ queryKey: ['applications'] })
    },
    onError: (e) => message.error(e instanceof ApiError ? e.message : '操作失败'),
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
          description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
          action={
            <Button onClick={() => navigate('/applications')}>返回列表</Button>
          }
        />
      </Card>
    )
  }

  const app = detailQuery.data
  const hasHttps = app.domains.some((d) => d.https_enabled)

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
            <StatusTag value={app.deployment_mode || 'REVERSE_PROXY'} map={DEPLOYMENT_MODE_META} />
            <StatusTag value={app.status} map={APP_STATUS_META} />
            <StatusTag value={app.deployment_status} map={DEPLOYMENT_STATUS_META} />
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
            <Button type="primary" onClick={() => toggleMutation.mutate('enable')}>
              启用应用
            </Button>
          ))
        }
      >
        <Descriptions column={{ xs: 1, sm: 2, md: 3 }} size="small">
          <Descriptions.Item label="应用编码">{app.code}</Descriptions.Item>
          <Descriptions.Item label="业务负责人">{app.business_owner || '-'}</Descriptions.Item>
          <Descriptions.Item label="技术负责人">{app.technical_owner || '-'}</Descriptions.Item>
          <Descriptions.Item label="描述">{app.description || '-'}</Descriptions.Item>
          <Descriptions.Item label="健康状态">
            {app.health_status === 'HEALTHY' ? (
              <Tag color="green">健康</Tag>
            ) : app.health_status === 'UNHEALTHY' ? (
              <Tag color="red">异常</Tag>
            ) : (
              <Tag>未知</Tag>
            )}
          </Descriptions.Item>
          <Descriptions.Item label="最后发布时间">{formatDateTime(app.last_publish_at)}</Descriptions.Item>
          <Descriptions.Item label="创建时间">{formatDateTime(app.created_at)}</Descriptions.Item>
          <Descriptions.Item label="更新时间">{formatDateTime(app.updated_at)}</Descriptions.Item>
        </Descriptions>
      </Card>

      <Card>
        <Tabs
          items={[
            {
              key: 'domains',
              label: `域名管理 (${app.domains.length})`,
              children: <DomainsTab appId={app.id} />,
            },
            {
              key: 'upstreams',
              label: `源站管理 (${app.upstreams.length})`,
              children: <UpstreamsTab appId={app.id} />,
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
                    children: <BotPolicyTab appId={app.id} appCode={app.code} />,
                  },
                ]
              : []),
            {
              key: 'certificates',
              label: '证书绑定',
              children: hasHttps ? (
                <CertificatesTab appId={app.id} />
              ) : (
                <Alert
                  type="info"
                  showIcon
                  message="当前应用未启用 HTTPS 域名，无需绑定证书"
                />
              ),
            },
          ]}
        />
      </Card>
    </Space>
  )
}
