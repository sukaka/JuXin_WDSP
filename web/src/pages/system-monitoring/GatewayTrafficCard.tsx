import { Alert, Card, Col, Row, Space, Statistic, Tag, Typography } from 'antd'
import type { RuntimeComponent } from '../../types'

function numberMetric(
  component: RuntimeComponent,
  key: string,
): number | undefined {
  const value = component.metrics?.[key]
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function booleanMetric(component: RuntimeComponent, key: string): boolean {
  return component.metrics?.[key] === true
}

function stringMetric(
  component: RuntimeComponent,
  key: string,
): string | undefined {
  const value = component.metrics?.[key]
  return typeof value === 'string' && value !== '' ? value : undefined
}

function decimal(value: number | undefined, digits = 1): string {
  return value === undefined ? '-' : value.toFixed(digits)
}

const BYPASS_REASONS: Record<string, string> = {
  CPU_THRESHOLD: 'CPU 超过阈值',
  MEMORY_THRESHOLD: '内存超过阈值',
  CPU_AND_MEMORY_THRESHOLD: 'CPU 与内存超过阈值',
  MIN_HOLD_OR_SAMPLE_UNAVAILABLE: '最短保持期内或采样暂不可用',
}

export default function GatewayTrafficCard({
  gateway,
}: {
  gateway: RuntimeComponent
}) {
  const hasRuntimeMetrics =
    gateway.metrics?.software_bypass_enabled !== undefined ||
    numberMetric(gateway, 'tcp_connections_active') !== undefined
  if (!hasRuntimeMetrics) return null

  const enabled = booleanMetric(gateway, 'software_bypass_enabled')
  const active = booleanMetric(gateway, 'software_bypass_active')
  const reason = stringMetric(gateway, 'software_bypass_reason')
  const cpuThreshold = numberMetric(
    gateway,
    'software_bypass_cpu_threshold_percent',
  )
  const memoryThreshold = numberMetric(
    gateway,
    'software_bypass_memory_threshold_percent',
  )
  const sampleError = stringMetric(gateway, 'resource_sample_error')
  const sessionOverflow =
    numberMetric(gateway, 'http_sessions_overflow_total') ?? 0

  return (
    <Card
      title="网关流量与软件旁路"
      extra={
        <Tag color={active ? 'red' : enabled ? 'blue' : 'default'}>
          {active
            ? '旁路中（未检测）'
            : enabled
              ? '自动旁路已启用'
              : '自动旁路未启用'}
        </Tag>
      }
    >
      <Space direction="vertical" size={16} style={{ display: 'flex' }}>
        {active && (
          <Alert
            type="warning"
            showIcon
            message={`当前为纯透传${reason ? `：${BYPASS_REASONS[reason] ?? reason}` : ''}`}
            description="访问控制、CC、Bot、API 动态防护与 WAF 均已跳过；请求 ID、安全响应头和源站反向代理仍保留。"
          />
        )}
        {sampleError && (
          <Alert
            type="error"
            showIcon
            message="部分系统资源采样不可用"
            description={sampleError}
          />
        )}
        {sessionOverflow > 0 && (
          <Alert
            type="warning"
            showIcon
            message="会话跟踪已达到 10000 条容量上限"
            description={`溢出次数：${sessionOverflow}；连接与请求计数不受影响。`}
          />
        )}
        <Row gutter={[16, 16]}>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="CPU 使用率"
              value={decimal(numberMetric(gateway, 'cpu_usage_percent'))}
              suffix="%"
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="内存使用率"
              value={decimal(numberMetric(gateway, 'memory_usage_percent'))}
              suffix="%"
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="当前 TCP 连接"
              value={numberMetric(gateway, 'tcp_connections_active') ?? '-'}
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="新建连接/秒"
              value={decimal(
                numberMetric(gateway, 'tcp_connections_accepted_per_second'),
                2,
              )}
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="累计新建连接"
              value={
                numberMetric(gateway, 'tcp_connections_accepted_total') ?? '-'
              }
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="活跃 HTTP 会话"
              value={numberMetric(gateway, 'http_sessions_active') ?? '-'}
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="累计新建会话"
              value={numberMetric(gateway, 'http_sessions_new_total') ?? '-'}
            />
          </Col>
          <Col xs={12} md={6} lg={3}>
            <Statistic
              title="在途 HTTP 请求"
              value={numberMetric(gateway, 'http_requests_in_flight') ?? '-'}
            />
          </Col>
        </Row>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          触发条件：CPU &gt; {cpuThreshold ?? '-'}% 或内存 &gt;{' '}
          {memoryThreshold ?? '-'}%；恢复阈值为触发值减 5
          个百分点。会话按应用与配置的 Cookie 去重，5
          分钟空闲后不计为活跃；无会话 Cookie 的请求不计入会话数。
        </Typography.Text>
      </Space>
    </Card>
  )
}
