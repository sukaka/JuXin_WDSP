import { afterEach, describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import type { ComponentProps } from 'react'
import type {
  SharedDeviceAccount,
  SharedDeviceGroup,
} from '../../../api/apiGroupControl'
import type EChart from '../../../components/EChart'
import SharedDeviceRelationshipGraph from '../SharedDeviceRelationshipGraph'

let latestProps: ComponentProps<typeof EChart> | undefined

vi.mock('../../../components/EChart', () => ({
  default: (props: ComponentProps<typeof EChart>) => {
    latestProps = props
    return <div role="img" aria-label={props.ariaLabel} />
  },
}))

const group: SharedDeviceGroup = {
  application_id: '11111111-1111-1111-1111-111111111111',
  application_name: '订单应用',
  device_fingerprint: 'd'.repeat(64),
  distinct_accounts: 7,
  event_count: 40,
  signal_count: 12,
  endpoint_count: 5,
  gateway_node_count: 2,
  first_seen_at: '2026-11-14T00:00:00Z',
  last_seen_at: '2026-11-15T00:00:00Z',
}

const accounts: SharedDeviceAccount[] = [
  {
    principal_ref: 'a'.repeat(64),
    event_count: 7,
    signal_count: 3,
    endpoint_count: 2,
    first_seen_at: '2026-11-14T01:00:00Z',
    last_seen_at: '2026-11-14T02:00:00Z',
  },
  {
    principal_ref: 'b'.repeat(64),
    event_count: 2,
    signal_count: 0,
    endpoint_count: 1,
    first_seen_at: '2026-11-14T03:00:00Z',
    last_seen_at: '2026-11-14T04:00:00Z',
  },
]

interface TestNode {
  id: string
  name: string
  node_type: 'device' | 'account'
  x: number
  y: number
  value: number
  event_count: number
  signal_count: number
  endpoint_count: number
}

interface TestLink {
  source: string
  target: string
  value: number
  event_count: number
  signal_count: number
}

function getGraphSeries() {
  const series = (latestProps?.option.series ?? []) as unknown as Array<{
    type: string
    data: TestNode[]
    links: TestLink[]
  }>
  return series[0]
}

afterEach(() => {
  latestProps = undefined
})

describe('SharedDeviceRelationshipGraph', () => {
  it('只将当前真实主体映射为设备中心节点、主体节点和关联边', () => {
    render(<SharedDeviceRelationshipGraph group={group} accounts={accounts} />)

    expect(
      screen.getByRole('img', {
        name: '共享设备与当前明细页可信主体关系图',
      }),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        /仅当前明细页\/已采集安全事件，非完整关系图谱或协同定罪/,
      ),
    ).toBeInTheDocument()

    const series = getGraphSeries()
    expect(series.type).toBe('graph')
    expect(series.data).toHaveLength(3)
    expect(series.links).toHaveLength(2)
    expect(series.data.map((node) => node.id)).toEqual([
      `device:${group.device_fingerprint}`,
      `account:${accounts[0].principal_ref}`,
      `account:${accounts[1].principal_ref}`,
    ])

    const device = series.data.find((node) => node.node_type === 'device')
    expect(device).toMatchObject({
      name: group.device_fingerprint,
      x: 0,
      y: 0,
      value: group.event_count,
      event_count: group.event_count,
      signal_count: group.signal_count,
      endpoint_count: group.endpoint_count,
    })

    const firstAccount = series.data.find(
      (node) => node.id === `account:${accounts[0].principal_ref}`,
    )
    expect(firstAccount).toMatchObject({
      name: `${accounts[0].principal_ref.slice(0, 16)}…`,
      value: accounts[0].event_count,
      event_count: accounts[0].event_count,
      signal_count: accounts[0].signal_count,
      endpoint_count: accounts[0].endpoint_count,
    })
    expect(firstAccount?.name).not.toContain(accounts[0].principal_ref)
    expect(series.links).toEqual([
      {
        source: `device:${group.device_fingerprint}`,
        target: `account:${accounts[0].principal_ref}`,
        value: accounts[0].event_count,
        event_count: accounts[0].event_count,
        signal_count: accounts[0].signal_count,
      },
      {
        source: `device:${group.device_fingerprint}`,
        target: `account:${accounts[1].principal_ref}`,
        value: accounts[1].event_count,
        event_count: accounts[1].event_count,
        signal_count: accounts[1].signal_count,
      },
    ])

    expect(latestProps?.summary).toContain(
      '当前明细页展示 2 个可信主体及 2 条真实设备关联',
    )
    expect(latestProps?.summary).toContain('非完整关系图谱或协同定罪')
    expect(latestProps?.summary).not.toContain(accounts[0].principal_ref)
    expect(
      screen.queryByText(accounts[0].principal_ref),
    ).not.toBeInTheDocument()
  })

  it('当前明细页为空时展示真实空态且不创建设备单节点或演示关系', () => {
    render(<SharedDeviceRelationshipGraph group={group} accounts={[]} />)

    expect(
      screen.getByText('当前明细页暂无已采集的可信主体关联'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(
        /仅当前明细页\/已采集安全事件，非完整关系图谱或协同定罪/,
      ),
    ).toBeInTheDocument()
    expect(
      screen.queryByRole('img', {
        name: '共享设备与当前明细页可信主体关系图',
      }),
    ).not.toBeInTheDocument()
    expect(latestProps).toBeUndefined()
    expect(screen.queryByText(group.device_fingerprint)).not.toBeInTheDocument()
  })
})
