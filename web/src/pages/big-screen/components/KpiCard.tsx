import type { CSSProperties, ReactNode } from 'react'
import CountUp from './CountUp'

/** KPI 指标卡：霓虹底线 + 数字滚动动画 */
export default function KpiCard({
  label,
  value,
  suffix,
  accent = '#00e5ff',
  accentGlow = 'rgba(0, 229, 255, 0.55)',
  formatter,
}: {
  label: string
  value: number
  suffix?: ReactNode
  accent?: string
  accentGlow?: string
  formatter?: (v: number) => string
}) {
  const style = { '--bs-accent': accent, '--bs-accent-glow': accentGlow } as CSSProperties
  return (
    <div className="bs-kpi" style={style}>
      <div className="bs-kpi-label">{label}</div>
      <div className="bs-kpi-value" style={style}>
        <CountUp value={value} formatter={formatter} />
        {suffix != null && <small>{suffix}</small>}
      </div>
    </div>
  )
}
