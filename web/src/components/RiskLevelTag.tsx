import { Tag } from 'antd'

const RISK_MAP: Record<string, { color: string; label: string }> = {
  LOW: { color: 'blue', label: '低' },
  MEDIUM: { color: 'orange', label: '中' },
  HIGH: { color: 'red', label: '高' },
  CRITICAL: { color: '#7f1d1d', label: '严重' },
}

/** 审计风险等级标签：LOW 蓝 / MEDIUM 橙 / HIGH 红 / CRITICAL 深红 */
export default function RiskLevelTag({ level }: { level: string }) {
  const item = RISK_MAP[level]
  if (!item) return <Tag>{level}</Tag>
  return <Tag color={item.color}>{item.label}</Tag>
}
