import type { ReactNode } from 'react'

export interface TickerItem {
  key: string
  /** 左侧状态点颜色 */
  color: string
  /** 时间文本（已格式化） */
  time: string
  /** 主体内容（单行省略） */
  content: ReactNode
  /** 右侧附加内容 */
  tail?: ReactNode
}

/**
 * 纵向无缝滚动列表：内容复制两份实现循环，悬停暂停。
 * duration 根据条目数估算，保证滚动速度稳定。
 */
export default function EventTicker({ items, empty = '暂无数据' }: { items: TickerItem[]; empty?: string }) {
  if (items.length === 0) {
    return <div className="bs-empty">{empty}</div>
  }
  const duration = Math.max(12, items.length * 2.5)
  const doubled = [...items, ...items]
  return (
    <div className="bs-ticker">
      <div className="bs-ticker-track" style={{ ['--bs-ticker-duration' as string]: `${duration}s` }}>
        {doubled.map((item, idx) => (
          <div className="bs-ticker-item" key={`${item.key}-${idx}`}>
            <span className="dot" style={{ background: item.color, color: item.color }} />
            <span className="time">{item.time}</span>
            <span className="grow">{item.content}</span>
            {item.tail}
          </div>
        ))}
      </div>
    </div>
  )
}
