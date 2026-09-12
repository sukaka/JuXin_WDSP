import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter } from 'react-router-dom'
import ApmAvailabilityAlert, { ApmIngestWatermark } from '../ApmAvailabilityAlert'
import ApmCorrelationNotice from '../ApmCorrelationNotice'
import type { ApmAvailability, ApmCorrelation } from '../../types'

function availability(partial: Partial<ApmAvailability>): ApmAvailability {
  return {
    query_state: 'READY',
    reason_codes: [],
    observed_sources: ['GATEWAY', 'OTEL'],
    last_collected_at: null,
    last_ingested_at: null,
    estimated_lag_ms: null,
    partial: false,
    ...partial,
  }
}

function renderWithRouter(node: ReactElement) {
  return render(<MemoryRouter>{node}</MemoryRouter>)
}

describe('ApmAvailabilityAlert', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('字段缺失（旧后端）显示「状态信息不足」，不编造原因', () => {
    renderWithRouter(<ApmAvailabilityAlert availability={undefined} />)
    expect(screen.getByText('状态信息不足')).toBeInTheDocument()
    expect(screen.getByText(/不推断缺失原因/)).toBeInTheDocument()
  })

  it('UNAVAILABLE 显示「调用链存储暂不可用」与原因码，提供重试按钮', () => {
    const onRetry = vi.fn()
    renderWithRouter(
      <ApmAvailabilityAlert
        availability={availability({
          query_state: 'UNAVAILABLE',
          reason_codes: ['STORAGE_UNAVAILABLE'],
          observed_sources: [],
        })}
        onRetry={onRetry}
      />,
    )
    expect(screen.getByText('调用链存储暂不可用')).toBeInTheDocument()
    expect(screen.getByText(/调用链存储当前不可用/)).toBeInTheDocument()
    // 不展示零值健康结论
    expect(screen.getByText(/不代表业务真实状况/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /重\s*试/ }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('observed_sources 仅 GATEWAY 时解释「目前仅有网关观测数据」并给接入指引', () => {
    renderWithRouter(
      <ApmAvailabilityAlert availability={availability({ observed_sources: ['GATEWAY'] })} />,
    )
    expect(screen.getByText('目前仅有网关观测数据')).toBeInTheDocument()
    // 明确安装流量镜像 Agent 不会生成代码级 Trace
    expect(screen.getByText(/不会生成代码级 Trace/)).toBeInTheDocument()
    const link = screen.getByRole('button', { name: '前往「Agent 管理」创建注册令牌' }).closest('a')
    expect(link?.getAttribute('href')).toBe('/apm-agents')
  })

  it('PARTIAL 显示结果不完整与原因码', () => {
    renderWithRouter(
      <ApmAvailabilityAlert
        availability={availability({ query_state: 'PARTIAL', partial: true, reason_codes: ['OUTSIDE_RETENTION'] })}
      />,
    )
    expect(screen.getByText('结果可能不完整')).toBeInTheDocument()
    expect(screen.getByText(/查询时间超出数据保留期/)).toBeInTheDocument()
  })

  it('READY 且无异常信号时不渲染', () => {
    const { container } = renderWithRouter(<ApmAvailabilityAlert availability={availability({})} />)
    expect(container).toBeEmptyDOMElement()
  })
})

describe('ApmIngestWatermark', () => {
  it('展示采集/入库时间与滞后估计；未知显示「未知」', () => {
    renderWithRouter(
      <ApmIngestWatermark
        availability={availability({
          last_collected_at: '2026-08-30T00:30:00Z',
          last_ingested_at: '2026-08-30T00:30:02Z',
          estimated_lag_ms: 12_000,
        })}
      />,
    )
    expect(screen.getByText(/最近采集时间/)).toBeInTheDocument()
    expect(screen.getByText(/约 12 秒/)).toBeInTheDocument()

    renderWithRouter(<ApmIngestWatermark availability={availability({})} />)
    expect(screen.getAllByText(/未知/).length).toBeGreaterThanOrEqual(2)
  })
})

describe('ApmCorrelationNotice', () => {
  const base: ApmCorrelation = {
    state: 'MATCHED',
    match_basis: 'request_id_to_trace_id',
    candidate_count: 1,
    reason: '',
    candidates: [],
  }

  it('缺失时不渲染（由调用方决定是否提示状态信息不足）', () => {
    const { container } = renderWithRouter(<ApmCorrelationNotice correlation={null} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('MATCHED 展示关联强度标签与匹配依据（文字+颜色，不只靠颜色）', () => {
    renderWithRouter(<ApmCorrelationNotice correlation={base} />)
    expect(screen.getByText('已关联')).toBeInTheDocument()
    expect(screen.getByText(/按请求 ID 解析/)).toBeInTheDocument()
  })

  it('AMBIGUOUS 列出全部候选（时间/服务/匹配依据），不自动任选', () => {
    const onSelect = vi.fn()
    const c1 = 'a'.repeat(32)
    const c2 = 'b'.repeat(32)
    renderWithRouter(
      <ApmCorrelationNotice
        correlation={{
          state: 'AMBIGUOUS',
          match_basis: 'request_id_to_trace_id',
          candidate_count: 2,
          reason: '该请求 ID 命中两条候选调用链',
          candidates: [
            { trace_id: c1, occurred_at: '2026-08-30T00:30:00Z', services: ['shop-web'], match_basis: 'otel_traces.trace_id' },
            { trace_id: c2, occurred_at: null, services: [], match_basis: 'access_logs.trace_id' },
          ],
        }}
        onSelectTrace={onSelect}
      />,
    )
    expect(screen.getByText('存在多个候选')).toBeInTheDocument()
    expect(screen.getByText(/系统不会自动任选其一/)).toBeInTheDocument()
    expect(screen.getByText('aaaaaaaa…')).toBeInTheDocument()
    expect(screen.getByText('bbbbbbbb…')).toBeInTheDocument()
    expect(screen.getByText('shop-web')).toBeInTheDocument()
    // 候选级匹配依据如实展示；未知时间/服务显示「未知」
    expect(screen.getByText('数据面 Span 命中')).toBeInTheDocument()
    expect(screen.getByText('网关访问记录解析（数据面未确认）')).toBeInTheDocument()
    expect(screen.getAllByText('未知').length).toBeGreaterThanOrEqual(2)

    const buttons = screen.getAllByRole('button', { name: '查看该 Trace' })
    fireEvent.click(buttons[1])
    expect(onSelect).toHaveBeenCalledWith(c2)
  })

  it('reason 中的 HTML 按纯文本渲染，不执行脚本', () => {
    const { container } = renderWithRouter(
      <ApmCorrelationNotice correlation={{ ...base, reason: '<img src=x onerror=alert(1)>' }} />,
    )
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(container.querySelector('img')).toBeNull()
  })
})
