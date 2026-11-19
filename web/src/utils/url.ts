/** 仅允许 http: / https: 协议的外链 URL，拦截 javascript:、data:、vbscript: 等危险协议 */
export function isSafeHttpUrl(url: string | null | undefined): boolean {
  if (typeof url !== 'string') return false
  const trimmed = url.trim()
  if (!trimmed) return false
  try {
    const parsed = new URL(trimmed)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}
