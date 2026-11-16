import type { CSSProperties } from 'react'

/** 等宽输出样式（日志/命令输出/参数 JSON 通用；网络工具详情与容器运维日志抽屉共用） */
export const PRE_STYLE: CSSProperties = {
  fontFamily: 'monospace',
  fontSize: 12,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  background: 'rgba(0, 0, 0, 0.03)',
  border: '1px solid rgba(0, 0, 0, 0.08)',
  borderRadius: 6,
  padding: 12,
  margin: '8px 0 0',
  maxHeight: 320,
  overflow: 'auto',
}
