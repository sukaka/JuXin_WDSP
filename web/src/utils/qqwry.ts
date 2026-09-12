/**
 * 纯真 IP 地址库（qqwry.dat）浏览器端解析器。
 *
 * 数据源：纯真 CZ88 IP 库（github.com/FW27623/qqwry 镜像，随仓库归档的固定版本，
 * 哈希与来源见 THIRD_PARTY_NOTICES.md）。文件拷贝到 public/assets/geo/qqwry.dat，
 * 运行时懒加载一次并常驻内存。
 *
 * 格式（公开事实，经实库字节级验证）：
 * - 头部 8 字节：索引区起止偏移（u32 LE）；
 * - 索引项 7 字节：4 字节起始 IP（u32 LE）+ 3 字节记录偏移（24 位 LE）；
 * - 记录：4 字节结束 IP，随后 1 字节模式——
 *   0x01：国家与地区整体重定向（3 字节指针）；
 *   0x02：国家名重定向（3 字节指针），地区字符串内联跟随；
 *   其他：国家名内联，地区字符串跟随其后；
 * - 地区字符串自身可用 0x01/0x02 重定向；字符串为 GBK 编码、0x00 结尾。
 */

const QQWRY_URL = '/assets/geo/qqwry.dat'

export interface QqwryLocation {
  /** 位置主字段（如「中国–江苏–南京」「美国–加利福尼亚州–山景城」「局域网」） */
  country: string
  /** 附加字段（运营商/机构，如「电信」「谷歌公司DNS服务器」） */
  area: string
}

/** 纯真库中的特殊保留值（不作为公网归属地） */
const RESERVED_WORDS = ['局域网', '本机地址', 'IANA', '保留地址', '未分配', '共享地址', '本机']

let dbPromise: Promise<Uint8Array | null> | null = null

function loadDb(): Promise<Uint8Array | null> {
  if (!dbPromise) {
    dbPromise = (async () => {
      try {
        const resp = await fetch(QQWRY_URL)
        if (!resp.ok) return null
        return new Uint8Array(await resp.arrayBuffer())
      } catch {
        return null
      }
    })()
  }
  return dbPromise
}

/** 纯函数解析器（注入字节数组，便于测试） */
export function createQqwryReader(buf: Uint8Array) {
  const gbk = new TextDecoder('gbk')
  const u32 = (off: number) => (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) | (buf[off + 3] << 24)) >>> 0
  const u24 = (off: number) => buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16)

  function readStr(off: number): string {
    let end = off
    while (end < buf.length && buf[end] !== 0) end++
    return gbk.decode(buf.subarray(off, end))
  }

  function readArea(off: number): string {
    const mode = buf[off]
    if (mode === 0x01 || mode === 0x02) return readStr(u24(off + 1))
    return readStr(off)
  }

  /** 解析记录数据段（已跳过 4 字节结束 IP） */
  function readData(off: number, depth = 0): QqwryLocation {
    if (depth > 4) return { country: '', area: '' }
    const mode = buf[off]
    if (mode === 0x01) return readData(u24(off + 1), depth + 1)
    if (mode === 0x02) return { country: readStr(u24(off + 1)), area: readArea(off + 4) }
    let end = off
    while (end < buf.length && buf[end] !== 0) end++
    return { country: gbk.decode(buf.subarray(off, end)), area: readArea(end + 1) }
  }

  return function lookup(ip: string): QqwryLocation | null {
    const parts = ip.split('.').map(Number)
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null
    const target = (((parts[0] * 256 + parts[1]) * 256 + parts[2]) * 256 + parts[3]) >>> 0
    const indexStart = u32(0)
    const indexEnd = u32(4)
    // 二分查找最后一个 startIP <= target 的索引项
    let lo = 0
    let hi = Math.floor((indexEnd - indexStart) / 7)
    let best = -1
    while (lo <= hi) {
      const mid = (lo + hi) >> 1
      const off = indexStart + mid * 7
      if (u32(off) <= target) {
        best = mid
        lo = mid + 1
      } else {
        hi = mid - 1
      }
    }
    if (best < 0) return null
    const recOff = u24(indexStart + best * 7 + 4)
    const loc = readData(recOff + 4)
    if (!loc.country) return null
    if (RESERVED_WORDS.some((w) => loc.country.includes(w))) return null
    return loc
  }
}

/** 查询 IPv4 地址的纯真归属地；库未加载/内网/未收录返回 null */
export async function lookupQqwry(ip: string): Promise<QqwryLocation | null> {
  const buf = await loadDb()
  if (!buf) return null
  try {
    return createQqwryReader(buf)(ip)
  } catch {
    return null
  }
}
