import { Link } from 'react-router-dom'
import { Button, Space, Tooltip, Typography } from 'antd'

/**
 * 示例 Trace 跳转链接组（SQL 指纹 / 异常指纹列表共用）：
 * 每个示例 trace 渲染一个跳转按钮（跳 /apm-traces?trace_id=），最多直出 max 个，其余折叠为 +N。
 */
export default function ApmSampleTraceLinks({
  traceIds,
  max = 2,
}: {
  traceIds?: string[] | null
  max?: number
}) {
  const ids = (traceIds ?? []).filter(Boolean)
  if (ids.length === 0) return <Typography.Text type="secondary">-</Typography.Text>
  const shown = ids.slice(0, max)
  const rest = ids.length - shown.length
  return (
    <Space size={4} wrap>
      {shown.map((id, i) => (
        <Tooltip key={id} title={id}>
          <Link to={`/apm-traces?trace_id=${encodeURIComponent(id)}`}>
            <Button type="link" size="small" style={{ padding: 0 }}>
              {`示例 Trace${shown.length > 1 ? ` ${i + 1}` : ''}`}
            </Button>
          </Link>
        </Tooltip>
      ))}
      {rest > 0 && (
        <Tooltip title={ids.slice(max).join('、')}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            +{rest}
          </Typography.Text>
        </Tooltip>
      )}
    </Space>
  )
}
