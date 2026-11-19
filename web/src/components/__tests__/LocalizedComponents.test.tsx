import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import ProtectionModeTag from '../ProtectionModeTag'
import AnalyzeResultView from '../ai/AnalyzeResultView'
import EvidenceList from '../ai/EvidenceList'
import ApmTraceWaterfall from '../ApmTraceWaterfall'
import AutomationSuspectedTag from '../AutomationSuspectedTag'
import RiskLevelTag from '../RiskLevelTag'
import UserStatusTag from '../UserStatusTag'

describe('共享组件中文化回归测试', () => {
  it('ProtectionModeTag 仅显示中文标签，不拼接英文模式码', () => {
    render(
      <div>
        <ProtectionModeTag mode="OFF" />
        <ProtectionModeTag mode="OBSERVE" />
        <ProtectionModeTag mode="PROTECT" />
        <ProtectionModeTag mode="BYPASS" />
      </div>,
    )
    expect(screen.getByText('关闭')).toBeInTheDocument()
    expect(screen.getByText('观察')).toBeInTheDocument()
    expect(screen.getByText('防护')).toBeInTheDocument()
    expect(screen.getByText('透传')).toBeInTheDocument()
    expect(screen.queryByText(/OBSERVE/)).not.toBeInTheDocument()
    expect(screen.queryByText(/PROTECT/)).not.toBeInTheDocument()
  })

  it('AnalyzeResultView 展示「参与智能体」并映射智能体中文名', () => {
    render(
      <AnalyzeResultView
        result={{
          task_id: '12345678-abcd-efgh',
          answer: '分析完成',
          plan: {
            task_type: 'EVENT_ANALYSIS',
            risk_level: 'HIGH',
            summary: '排查攻击链路',
            agents: ['security_event', 'log_analysis', 'custom_agent'],
          },
          steps: [],
          evidence: [],
        }}
      />,
    )
    expect(screen.getByText('参与智能体')).toBeInTheDocument()
    expect(screen.queryByText('参与 Agent')).not.toBeInTheDocument()
    expect(screen.getByText('安全事件智能体')).toBeInTheDocument()
    expect(screen.getByText('日志分析智能体')).toBeInTheDocument()
    expect(screen.getByText('custom_agent')).toBeInTheDocument()
  })

  it('EvidenceList 映射 AI 工具来源中文名', () => {
    render(
      <EvidenceList
        items={[
          { id: 'E1', source: 'security_event.search', summary: '命中 3 条高危事件' },
          { id: 'E2', source: 'unknown.tool', summary: '保留未知来源' },
        ]}
      />,
    )
    expect(screen.getByText('安全事件查询：')).toBeInTheDocument()
    expect(screen.getByText('unknown.tool：')).toBeInTheDocument()
  })

  it('ApmTraceWaterfall 中文化错误标签、Span 类型与状态码', () => {
    render(
      <ApmTraceWaterfall
        spans={[
          {
            span_id: 'sp-root',
            parent_span_id: '',
            service_name: 'order-svc',
            operation_name: 'GET /orders',
            start_time: '2026-10-01T00:00:00.000Z',
            duration_ms: 120,
            span_kind: 'Server',
            status_code: 'Error',
            attributes: {},
          },
          {
            span_id: 'sp-child',
            parent_span_id: 'sp-root',
            service_name: 'order-db',
            operation_name: 'SELECT',
            start_time: '2026-10-01T00:00:00.020Z',
            duration_ms: 30,
            span_kind: 'CLIENT',
            status_code: 'Ok',
            attributes: {},
          },
        ]}
      />,
    )
    expect(screen.getByText('错误')).toBeInTheDocument()
    expect(screen.queryByText('ERROR')).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'span GET /orders' }))
    expect(screen.getByText(/Span ID：/)).toBeInTheDocument()
    expect(screen.getByText('服务端')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'span SELECT' }))
    expect(screen.getByText(/父 Span：/)).toBeInTheDocument()
    expect(screen.getByText('客户端')).toBeInTheDocument()
    expect(screen.getByText('正常')).toBeInTheDocument()
  })

  it('AutomationSuspectedTag 将 basis 判定依据中文化展示在 tooltip', async () => {
    render(
      <AutomationSuspectedTag
        suspected
        basis="stages=RECON,DISCOVERY,EXPLOIT;indicator=HEADLESS"
      />,
    )
    fireEvent.mouseEnter(screen.getByText('疑似自动化攻击'))
    expect(
      await screen.findByText('判定依据：命中阶段：侦察、API发现、漏洞利用；指示信号：无头访问'),
    ).toBeInTheDocument()
  })

  it('RiskLevelTag 支持大小写归一以及 INFO / NONE', () => {
    render(
      <div>
        <RiskLevelTag level="high" />
        <RiskLevelTag level="info" />
        <RiskLevelTag level="NONE" />
      </div>,
    )
    expect(screen.getByText('高')).toBeInTheDocument()
    expect(screen.getByText('信息')).toBeInTheDocument()
    expect(screen.getByText('无')).toBeInTheDocument()
  })

  it('UserStatusTag 支持大小写归一', () => {
    render(
      <div>
        <UserStatusTag status="active" />
        <UserStatusTag status="disabled" />
        <UserStatusTag status="locked" />
      </div>,
    )
    expect(screen.getByText('正常')).toBeInTheDocument()
    expect(screen.getByText('已停用')).toBeInTheDocument()
    expect(screen.getByText('已锁定')).toBeInTheDocument()
  })
})
