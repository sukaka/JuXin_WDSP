import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import GatewayTrafficCard from '../GatewayTrafficCard'
import type { RuntimeComponent } from '../../../types'

function gateway(metrics: Record<string, unknown>): RuntimeComponent {
  return { component: 'GATEWAY', status: 'UP', metrics }
}

describe('GatewayTrafficCard', () => {
  it('展示真实连接、会话、资源指标和旁路风险提示', () => {
    render(
      gatewayCard({
        cpu_usage_percent: 81.52,
        memory_usage_percent: 82.1,
        tcp_connections_active: 12,
        tcp_connections_accepted_total: 1200,
        tcp_connections_accepted_per_second: 34.5,
        http_sessions_active: 8,
        http_sessions_new_total: 100,
        http_requests_in_flight: 3,
        software_bypass_enabled: true,
        software_bypass_active: true,
        software_bypass_reason: 'CPU_THRESHOLD',
        software_bypass_cpu_threshold_percent: 80,
        software_bypass_memory_threshold_percent: 80,
      }),
    )
    expect(screen.getByText('旁路中（未检测）')).toBeInTheDocument()
    expect(screen.getByText(/CPU 超过阈值/)).toBeInTheDocument()
    const values = Array.from(
      document.querySelectorAll('.ant-statistic-content-value'),
    ).map((node) => node.textContent)
    expect(values).toEqual(
      expect.arrayContaining(['81.5', '12', '34.50', '1,200']),
    )
    expect(
      screen.getByText(/访问控制、CC、Bot、API 动态防护与 WAF 均已跳过/),
    ).toBeInTheDocument()
  })

  it('未启用时保持正常状态，零值按零展示', () => {
    render(
      gatewayCard({
        tcp_connections_active: 0,
        tcp_connections_accepted_total: 0,
        http_sessions_active: 0,
        software_bypass_enabled: false,
        software_bypass_active: false,
      }),
    )
    expect(screen.getByText('自动旁路未启用')).toBeInTheDocument()
    expect(screen.queryByText(/当前为纯透传/)).not.toBeInTheDocument()
    expect(screen.getAllByText('0').length).toBeGreaterThanOrEqual(3)
  })

  it('旧版网关无运行指标时不渲染卡片', () => {
    const { container } = render(gatewayCard({ config_hash: 'abc' }))
    expect(container).toBeEmptyDOMElement()
  })
})

function gatewayCard(metrics: Record<string, unknown>) {
  return <GatewayTrafficCard gateway={gateway(metrics)} />
}
