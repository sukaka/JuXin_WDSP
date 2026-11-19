const HTML_ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

/** 转义 HTML 特殊字符，防止 ECharts tooltip 等原生 HTML 渲染点发生存储型 XSS */
export function escapeHtml(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, (ch) => HTML_ESCAPE_MAP[ch])
}

const SAFE_CSS_COLOR_RE =
  /^(#[0-9a-fA-F]{3,8}|rgba?\(\s*\d{1,3}\s*,\s*\d{1,3}\s*,\s*\d{1,3}(?:\s*,\s*(?:0|1|0?\.\d+))?\s*\))$/

/** 校验并规范化内联 CSS 颜色值，防止注入属性逃逸 */
export function safeCssColor(value: unknown, fallback = '#00e5ff'): string {
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (SAFE_CSS_COLOR_RE.test(trimmed)) return trimmed
  }
  return fallback
}
