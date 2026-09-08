import { Badge, Tooltip, Typography } from 'antd'
import { healthReasonLabels, healthScoreColor } from './meta'

/** 健康分 Badge（Phase 2）：按分档着色，Tooltip 展示主要扣分项（满分显示「无扣分项」） */
export default function HealthScoreBadge({
  score,
  reasons,
}: {
  score?: number | null
  reasons?: string[] | null
}) {
  if (score === null || score === undefined || !Number.isFinite(score)) {
    return <Typography.Text type="secondary">-</Typography.Text>
  }
  const labels = healthReasonLabels(reasons)
  const badge = <Badge count={score} overflowCount={100} color={healthScoreColor(score)} />
  const tip =
    labels.length === 0 ? (
      '无扣分项'
    ) : (
      <div>
        <div style={{ marginBottom: 4 }}>扣分项：</div>
        {labels.map((l) => (
          <div key={l}>· {l}</div>
        ))}
      </div>
    )
  return <Tooltip title={tip}>{badge}</Tooltip>
}
