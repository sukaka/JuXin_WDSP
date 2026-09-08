import type { CSSProperties, ReactNode } from 'react'

/** 霓虹面板：四角光效 + 标题栏，body 为 flex 容器以撑满图表 */
export default function ScreenPanel({
  title,
  children,
  style,
}: {
  title: string
  children: ReactNode
  style?: CSSProperties
}) {
  return (
    <div className="bs-panel" style={style}>
      <span className="bs-panel-corner tl" />
      <span className="bs-panel-corner tr" />
      <span className="bs-panel-corner bl" />
      <span className="bs-panel-corner br" />
      <div className="bs-panel-title">{title}</div>
      <div className="bs-panel-body">{children}</div>
    </div>
  )
}
