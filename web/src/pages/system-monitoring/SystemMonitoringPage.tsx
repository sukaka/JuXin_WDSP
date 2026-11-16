import { useQuery } from '@tanstack/react-query'
import { Badge, Card, Col, Row, Space, Statistic, Typography } from 'antd'
import { dashboardsApi } from '../../api/dashboards'
import { systemHealthApi } from '../../api/systemHealth'
import QueryErrorAlert from '../../components/QueryErrorAlert'
import StatusTag from '../../components/StatusTag'
import { formatDateTime } from '../../utils/format'
import {
  COMPONENT_NAME_META,
  COMPONENT_STATUS_META,
  formatUptime,
} from '../../utils/stage6'
import type { RuntimeComponent } from '../../types'
import GatewayTrafficCard from './GatewayTrafficCard'

/** 组件状态卡片 */
function ComponentCard({ component }: { component: RuntimeComponent }) {
  const metrics = Object.entries(component.metrics ?? {}).slice(0, 4)
  return (
    <Card
      size="small"
      title={
        <Space>
          <Badge
            status={
              component.status === 'UP'
                ? 'success'
                : component.status === 'DEGRADED'
                  ? 'warning'
                  : component.status === 'DOWN'
                    ? 'error'
                    : 'default'
            }
          />
          {COMPONENT_NAME_META[component.component] ?? component.component}
        </Space>
      }
      extra={<StatusTag value={component.status} map={COMPONENT_STATUS_META} />}
    >
      <Space direction="vertical" size={4} style={{ display: 'flex' }}>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          延迟：
          {component.latency_ms != null ? `${component.latency_ms} ms` : '-'}
        </Typography.Text>
        {metrics.map(([k, v]) => (
          <Typography.Text
            key={k}
            type="secondary"
            style={{ fontSize: 12 }}
            ellipsis
          >
            {k}：{String(v)}
          </Typography.Text>
        ))}
        {component.message && (
          <Typography.Text
            type="secondary"
            style={{ fontSize: 12 }}
            ellipsis={{ tooltip: component.message }}
          >
            {component.message}
          </Typography.Text>
        )}
      </Space>
    </Card>
  )
}

/** 运行监控：组件健康状态卡片墙，30 秒自动刷新 */
export default function SystemMonitoringPage() {
  const healthQuery = useQuery({
    queryKey: ['system-health'],
    queryFn: () => systemHealthApi.overview(),
    refetchInterval: 30000,
  })

  const componentsQuery = useQuery({
    queryKey: ['system-health', 'components'],
    queryFn: () => systemHealthApi.components(),
    refetchInterval: 30000,
  })

  // 运行总览（网关运行时间/发布与报告统计），权限不足时静默降级不展示
  const runtimeQuery = useQuery({
    queryKey: ['dashboard', 'runtime-overview'],
    queryFn: () => dashboardsApi.runtimeOverview(),
    refetchInterval: 30000,
    retry: false,
  })

  const components =
    componentsQuery.data?.components ?? healthQuery.data?.components ?? []
  const checkedAt =
    componentsQuery.data?.checked_at ?? healthQuery.data?.checked_at
  const missing = healthQuery.data?.missing_components ?? []
  const runtime = runtimeQuery.isError ? undefined : runtimeQuery.data

  return (
    <Space direction="vertical" size={16} style={{ display: 'flex' }}>
      {components.map(
        (component) =>
          component.component === 'GATEWAY' && (
            <GatewayTrafficCard key={component.component} gateway={component} />
          ),
      )}
      <Card
        title="运行监控"
        extra={
          <Space>
            {healthQuery.data?.status && (
              <StatusTag
                value={healthQuery.data.status}
                map={COMPONENT_STATUS_META}
              />
            )}
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              {checkedAt ? `更新于 ${formatDateTime(checkedAt)}` : ''}（30
              秒自动刷新）
            </Typography.Text>
          </Space>
        }
      >
        {runtime && (
          <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title="网关状态"
                  value={runtime.gateway?.status ?? 'UNKNOWN'}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title="网关持续运行"
                  value={formatUptime(runtime.gateway?.uptime_seconds)}
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title={`近${runtime.publish?.window_days ?? 30}天发布成功率`}
                  value={Math.round((runtime.publish?.success_rate ?? 0) * 100)}
                  suffix="%"
                />
              </Card>
            </Col>
            <Col xs={12} md={6}>
              <Card size="small">
                <Statistic
                  title={`近${runtime.reports?.window_days ?? 30}天报告成功/失败`}
                  value={`${runtime.reports?.success ?? 0} / ${runtime.reports?.failed ?? 0}`}
                />
              </Card>
            </Col>
          </Row>
        )}

        {componentsQuery.isError && healthQuery.isError ? (
          <QueryErrorAlert
            error={componentsQuery.error}
            message="加载组件状态失败"
          />
        ) : (
          <Row gutter={[16, 16]}>
            {components.length === 0 && !componentsQuery.isLoading ? (
              <Col span={24}>
                <Typography.Text type="secondary">
                  暂无组件状态数据
                </Typography.Text>
              </Col>
            ) : (
              components.map((c) => (
                <Col key={c.component} xs={24} sm={12} md={8} lg={6}>
                  <ComponentCard component={c} />
                </Col>
              ))
            )}
            {missing.map((name) => (
              <Col key={`missing-${name}`} xs={24} sm={12} md={8} lg={6}>
                <ComponentCard
                  component={{
                    component: name,
                    status: 'UNKNOWN',
                    message: '尚未采集到健康快照',
                  }}
                />
              </Col>
            ))}
          </Row>
        )}
      </Card>
    </Space>
  )
}
