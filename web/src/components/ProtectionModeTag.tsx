import { Tag } from 'antd'
import { PROTECTION_MODE_META } from '../utils/stage3'

/** 防护模式标签：OFF 灰 / OBSERVE 蓝 / PROTECT 绿 / BYPASS 火山橙 */
export default function ProtectionModeTag({ mode }: { mode: string }) {
  const item = PROTECTION_MODE_META[mode]
  if (!item) return <Tag>{mode}</Tag>
  return <Tag color={item.color}>{item.label}</Tag>
}
