import { useMemo } from 'react'
import { Alert, Card, Empty } from 'antd'
import type {
  SharedDeviceAccount,
  SharedDeviceGroup,
} from '../../api/apiGroupControl'
import EChart from '../../components/EChart'
import type { EChartOption } from '../../components/EChart'

interface SharedDeviceRelationshipGraphProps {
  group: SharedDeviceGroup
  accounts: SharedDeviceAccount[]
}

interface RelationshipNode {
  id: string
  name: string
  node_type: 'device' | 'account'
  category: number
  x: number
  y: number
  value: number
  event_count: number
  signal_count: number
  endpoint_count: number
  symbolSize: number
  itemStyle: { color: string }
}

interface RelationshipLink {
  source: string
  target: string
  value: number
  event_count: number
  signal_count: number
}

function shortenHmac(value: string) {
  return `${value.slice(0, 16)}…`
}

export default function SharedDeviceRelationshipGraph({
  group,
  accounts,
}: SharedDeviceRelationshipGraphProps) {
  const option = useMemo<EChartOption>(() => {
    const deviceId = `device:${group.device_fingerprint}`
    const radius = Math.min(240, 140 + accounts.length * 3)
    const deviceNode: RelationshipNode = {
      id: deviceId,
      name: group.device_fingerprint,
      node_type: 'device',
      category: 0,
      x: 0,
      y: 0,
      value: group.event_count,
      event_count: group.event_count,
      signal_count: group.signal_count,
      endpoint_count: group.endpoint_count,
      symbolSize: 76,
      itemStyle: { color: '#1677ff' },
    }
    const accountNodes: RelationshipNode[] = accounts.map((account, index) => {
      const angle = -Math.PI / 2 + (index * Math.PI * 2) / accounts.length
      return {
        id: `account:${account.principal_ref}`,
        name: shortenHmac(account.principal_ref),
        node_type: 'account',
        category: 1,
        x: Math.cos(angle) * radius,
        y: Math.sin(angle) * radius,
        value: account.event_count,
        event_count: account.event_count,
        signal_count: account.signal_count,
        endpoint_count: account.endpoint_count,
        symbolSize: 48,
        itemStyle: { color: '#13c2c2' },
      }
    })
    const links: RelationshipLink[] = accounts.map((account) => ({
      source: deviceId,
      target: `account:${account.principal_ref}`,
      value: account.event_count,
      event_count: account.event_count,
      signal_count: account.signal_count,
    }))

    return {
      tooltip: {
        trigger: 'item',
        confine: true,
        renderMode: 'richText',
        formatter: (params) => {
          const { data, dataType } = params as {
            data?: RelationshipNode & RelationshipLink
            dataType?: string
          }
          if (dataType === 'edge') {
            return `设备与可信主体的真实关联\n关联安全事件：${data?.event_count ?? 0}\n群控观察信号：${data?.signal_count ?? 0}`
          }
          const title =
            data?.node_type === 'device'
              ? `共享设备\n设备指纹：${data.name}`
              : `可信主体 HMAC：${data?.name ?? ''}`
          return `${title}\n关联安全事件：${data?.event_count ?? 0}\n群控观察信号：${data?.signal_count ?? 0}\n涉及接口：${data?.endpoint_count ?? 0}`
        },
      },
      legend: {
        top: 0,
        data: ['共享设备', '可信主体'],
      },
      series: [
        {
          type: 'graph',
          layout: 'none',
          roam: true,
          left: 48,
          right: 48,
          top: 40,
          bottom: 40,
          categories: [{ name: '共享设备' }, { name: '可信主体' }],
          data: [deviceNode, ...accountNodes],
          links,
          label: {
            show: true,
            position: 'bottom',
            fontSize: 11,
            formatter: (params) => {
              const data = (params as { data?: RelationshipNode }).data
              return data?.node_type === 'device'
                ? `共享设备\n${shortenHmac(data.name)}`
                : (data?.name ?? '')
            },
          },
          lineStyle: { color: '#91caff', width: 1.5 },
          emphasis: { focus: 'adjacency' },
          scaleLimit: { min: 0.5, max: 3 },
        },
      ],
    }
  }, [accounts, group])

  const summary = `中心设备累计 ${group.event_count} 件已采集安全事件、${group.signal_count} 个群控观察信号。当前明细页展示 ${accounts.length} 个可信主体及 ${accounts.length} 条真实设备关联：${accounts
    .map(
      (account) =>
        `${shortenHmac(account.principal_ref)}，${account.event_count} 件安全事件、${account.signal_count} 个群控观察信号`,
    )
    .join('；')}。仅当前明细页/已采集安全事件，非完整关系图谱或协同定罪。`

  return (
    <Card size="small" title="共享设备关系图">
      <Alert
        type="info"
        showIcon
        title="关系范围说明"
        description="仅当前明细页/已采集安全事件，非完整关系图谱或协同定罪。可信主体 HMAC 仅显示前 16 位。"
        style={{ marginBottom: 16 }}
      />
      {accounts.length === 0 ? (
        <Empty description="当前明细页暂无已采集的可信主体关联" />
      ) : (
        <EChart
          option={option}
          height={420}
          ariaLabel="共享设备与当前明细页可信主体关系图"
          summary={summary}
        />
      )}
    </Card>
  )
}
