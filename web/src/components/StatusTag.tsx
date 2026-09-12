import { Tag } from 'antd'

/** 通用状态标签：按给定映射渲染，未命中时原样展示 */
export default function StatusTag({
  value,
  map,
}: {
  value: string
  map: Record<string, { color: string; label: string }>
}) {
  if (!value) return <Tag>-</Tag>
  const item = map[value]
  if (!item) return <Tag>{value}</Tag>
  return <Tag color={item.color}>{item.label}</Tag>
}
