import { Empty, Popover, Tag, Typography } from 'antd'
import type { AiEvidenceItem } from '../../api/ai'
import { formatJson } from '../../utils/format'

/** AI 证据引用列表（[Ex] 编号与回答中的引用对应；有 detail 时可悬浮查看） */
export default function EvidenceList({ items }: { items?: AiEvidenceItem[] | null }) {
  if (!items || items.length === 0) return null
  return (
    <div>
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>
        证据引用
      </Typography.Text>
      <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {items.map((e) => {
          const content = (
            <div style={{ display: 'flex', gap: 8, alignItems: 'baseline' }}>
              <Tag color="blue" style={{ marginInlineEnd: 0 }}>
                {e.id}
              </Tag>
              <Typography.Text style={{ fontSize: 13 }}>
                <Typography.Text type="secondary">{e.source}：</Typography.Text>
                {e.summary}
              </Typography.Text>
            </div>
          )
          return e.detail !== undefined && e.detail !== null ? (
            <Popover
              key={e.id}
              placement="topLeft"
              content={
                <pre style={{ maxWidth: 480, maxHeight: 320, overflow: 'auto', fontSize: 12, margin: 0 }}>
                  {formatJson(e.detail)}
                </pre>
              }
            >
              <div style={{ cursor: 'pointer' }}>{content}</div>
            </Popover>
          ) : (
            <div key={e.id}>{content}</div>
          )
        })}
      </div>
    </div>
  )
}

/** 空证据占位（保持与 Empty 组件一致的空态风格） */
export function EvidenceEmpty() {
  return <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="本次分析未产生证据引用" />
}
