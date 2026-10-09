import type { ApiAdmissionMode } from '../../types'

/** API 准入模式展示映射（OFF 灰 / OBSERVE 蓝 / PROTECT 绿） */
export const ADMISSION_MODE_META: Record<ApiAdmissionMode, { color: string; label: string }> = {
  OFF: { color: 'default', label: '关闭' },
  OBSERVE: { color: 'blue', label: '观察' },
  PROTECT: { color: 'green', label: '防护' },
}

/** 命中统计窗口预设（小时），自定义 1–90 天经 Popover 输入换算为小时 */
export const WINDOW_PRESETS: ReadonlyArray<{ hours: number; label: string }> = [
  { hours: 24, label: '24小时' },
  { hours: 72, label: '3天' },
  { hours: 168, label: '7天' },
  { hours: 336, label: '14天' },
  { hours: 720, label: '30天' },
]

export const DEFAULT_HITS_WINDOW_HOURS = 168

/** 自定义窗口下限/上限（天），与服务端 hits_window 1–2160 小时一致 */
export const CUSTOM_WINDOW_MIN_DAYS = 1
export const CUSTOM_WINDOW_MAX_DAYS = 90
