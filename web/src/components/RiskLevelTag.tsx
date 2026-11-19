import { Tag } from 'antd'

const RISK_MAP: Record<string, { color: string; label: string }> = {
  NONE: { color: 'default', label: '无' },
  INFO: { color: 'default', label: '信息' },
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: '#7f1d1d', label: '严重' },
}

/** 风险等级标签：NONE/INFO 灰 / LOW 蓝 / MEDIUM 橙 / HIGH 红 / CRITICAL 深红 */
export default function RiskLevelTag({ level }: { level: string }) {
  const key = (level || '').trim().toUpperCase()
  const item = RISK_MAP[key]
  if (!item) return <Tag>{level}</Tag>
  return <Tag color={item.color}>{item.label}</Tag>
}
