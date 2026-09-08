import { describe, expect, it } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { createQqwryReader } from '../qqwry'

/** 构造最小合成库：记录 = 4 字节结束 IP + 内联国家串 + 内联地区串（ASCII 与 GBK 兼容） */
function buildSyntheticDat(): Uint8Array {
  const country = [0x54, 0x45, 0x53, 0x54] // 'TEST'（避开 0x01/0x02 模式字节）
  const area = [0x41, 0x42, 0x43] // 'ABC'
  const record = [
    0xff, 0x03, 0x02, 0x01, // endIP = 1.2.3.255（u32 LE）
    ...country, 0x00,
    ...area, 0x00,
  ]
  const headerSize = 8
  const indexStart = headerSize + record.length
  const index = [
    0x04, 0x03, 0x02, 0x01, // startIP = 1.2.3.4（u32 LE，字节序与真实库一致）
    headerSize & 0xff, (headerSize >> 8) & 0xff, (headerSize >> 16) & 0xff, // 记录偏移 u24
  ]
  const total = indexStart + index.length
  const buf = new Uint8Array(total)
  buf[0] = indexStart & 0xff
  buf[1] = (indexStart >> 8) & 0xff
  buf[2] = (indexStart >> 16) & 0xff
  buf[3] = (indexStart >> 24) & 0xff
  const indexEnd = indexStart + index.length - 1
  buf[4] = indexEnd & 0xff
  buf[5] = (indexEnd >> 8) & 0xff
  buf[6] = (indexEnd >> 16) & 0xff
  buf[7] = (indexEnd >> 24) & 0xff
  buf.set(record, headerSize)
  buf.set(index, indexStart)
  return buf
}

describe('createQqwryReader（合成库）', () => {
  const lookup = createQqwryReader(buildSyntheticDat())

  it('命中范围内的 IP 返回国家与地区', () => {
    expect(lookup('1.2.3.4')).toEqual({ country: 'TEST', area: 'ABC' })
    expect(lookup('1.2.3.200')).toEqual({ country: 'TEST', area: 'ABC' })
  })

  it('起始 IP 之前返回 null；之后命中最后一个覆盖条目（与真实库语义一致）', () => {
    expect(lookup('1.2.2.255')).toBeNull() // 早于唯一条目的起始 IP
    // 真实库全量覆盖 0.0.0.0-255.255.255.255，解析器不校验记录 endIP：
    // 晚于最后一个 startIP 的地址归到最后一个条目（与真实库行为一致）
    expect(lookup('9.9.9.9')).toEqual({ country: 'TEST', area: 'ABC' })
  })

  it('非法输入返回 null', () => {
    expect(lookup('not-an-ip')).toBeNull()
  })
})

const REAL_DAT = join(process.cwd(), 'public/assets/geo/qqwry.dat')

describe('createQqwryReader（真实纯真库，文件存在时）', () => {
  const hasDat = existsSync(REAL_DAT)

  it.skipIf(!hasDat)('真实库中文解析与城市精度', () => {
    const lookup = createQqwryReader(new Uint8Array(readFileSync(REAL_DAT)))
    // 114.114.114.114 为南京（DB-IP 误标济南的典型样本）
    const nanjing = lookup('114.114.114.114')
    expect(nanjing?.country).toContain('南京')
    // 8.8.8.8 为美国
    expect(lookup('8.8.8.8')?.country).toContain('美国')
    // 阿里 DNS 为杭州
    expect(lookup('223.5.5.5')?.country).toContain('杭州')
    // 内网/本机为保留值，返回 null
    expect(lookup('10.0.0.1')).toBeNull()
    expect(lookup('127.0.0.1')).toBeNull()
  })
})
