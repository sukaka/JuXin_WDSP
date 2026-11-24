import dayjs from 'dayjs'

/** 本地时区格式化日期时间，空值返回占位符 */
export function formatDateTime(value?: string | null): string {
  if (!value) return '-'
  const d = dayjs(value)
  return d.isValid() ? d.format('YYYY-MM-DD HH:mm:ss') : '-'
}

/** 起止时间差人性化展示（如「43分钟」「1小时23分」）；缺任一端或非法值返回占位符 */
export function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return '-'
  const ms = dayjs(end).valueOf() - dayjs(start).valueOf()
  if (!Number.isFinite(ms) || ms < 0) return '-'
  const totalSeconds = Math.floor(ms / 1000)
  if (totalSeconds < 60) return `${totalSeconds}秒`
  const minutes = Math.floor(totalSeconds / 60)
  if (minutes < 60) return `${minutes}分钟`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return minutes % 60 ? `${hours}小时${minutes % 60}分` : `${hours}小时`
  const days = Math.floor(hours / 24)
  return hours % 24 ? `${days}天${hours % 24}小时` : `${days}天`
}

/** 将 JSON 字符串/对象格式化为可读文本 */
export function formatJson(value: unknown): string {
  if (value === null || value === undefined || value === '') return '-'
  if (typeof value === 'string') {
    try {
      return JSON.stringify(JSON.parse(value), null, 2)
    } catch {
      return value
    }
  }
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

/** HTML 特殊字符转义：不可信文本（如攻击者可控的请求路径）进入 HTML 上下文
 * （ECharts html 模式 tooltip 等）前必须转义，防存储型 XSS */
export function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch] ?? ch)
}

/** 文件大小人性化格式化（1024 进制），空值/非法值返回占位符 */
export function formatBytes(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '-'
  if (value < 1024) return `${value} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let v = value
  let u = -1
  do {
    v /= 1024
    u++
  } while (v >= 1024 && u < units.length - 1)
  const decimals = v >= 100 ? 0 : v >= 10 ? 1 : 2
  return `${v.toFixed(decimals)} ${units[u]}`
}

export type BandwidthUnit = 'B/s' | 'KB/s' | 'MB/s' | 'GB/s'

/** 按峰值速率选择统一带宽单位与换算除数，用于图表 Y 轴自动缩放 */
export function pickBandwidthScale(maxBytesPerSecond: number): { unit: BandwidthUnit; divisor: number } {
  if (!Number.isFinite(maxBytesPerSecond) || maxBytesPerSecond < 1024) {
    return { unit: 'B/s', divisor: 1 }
  }
  if (maxBytesPerSecond < 1024 ** 2) {
    return { unit: 'KB/s', divisor: 1024 }
  }
  if (maxBytesPerSecond < 1024 ** 3) {
    return { unit: 'MB/s', divisor: 1024 ** 2 }
  }
  return { unit: 'GB/s', divisor: 1024 ** 3 }
}

/** 拆分单点带宽速率为数值、单位和小数位，供大屏滚动数字卡片使用 */
export function splitBandwidthRate(value?: number | null): { value: number; unit: BandwidthUnit; digits: number } {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) {
    return { value: 0, unit: 'B/s', digits: 0 }
  }
  const { unit, divisor } = pickBandwidthScale(value)
  const scaled = value / divisor
  const digits = unit === 'B/s' ? 0 : scaled >= 100 ? 0 : scaled >= 10 ? 1 : 2
  return { value: scaled, unit, digits }
}

/** 带宽速率人性化格式化（B/s、KB/s、MB/s、GB/s），空值/非法值返回占位符 */
export function formatBytesPerSecond(value?: number | null): string {
  if (value === null || value === undefined || !Number.isFinite(value) || value < 0) return '-'
  const { value: scaled, unit, digits } = splitBandwidthRate(value)
  return `${scaled.toFixed(digits)} ${unit}`
}
