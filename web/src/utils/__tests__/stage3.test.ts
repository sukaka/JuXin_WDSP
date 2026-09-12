import { describe, expect, it } from 'vitest'
import dayjs from 'dayjs'
import {
  certRemainingColor,
  certRemainingDays,
  DEPLOYMENT_MODE_META,
  isTerminalTaskStatus,
  parseBusinessSnapshot,
  PROTECTION_MODE_META,
  truncateHash,
} from '../stage3'

describe('DEPLOYMENT_MODE_META', () => {
  it('覆盖四种部署模式且颜色两两可区分', () => {
    const modes = ['REVERSE_PROXY', 'ROUTED', 'MIRROR', 'TRANSPARENT']
    for (const mode of modes) {
      expect(DEPLOYMENT_MODE_META[mode], `missing meta for ${mode}`).toBeDefined()
    }
    expect(DEPLOYMENT_MODE_META.MIRROR.label).toBe('镜像')
    expect(DEPLOYMENT_MODE_META.TRANSPARENT.label).toBe('透明串接')
    const colors = modes.map((m) => DEPLOYMENT_MODE_META[m].color)
    expect(new Set(colors).size).toBe(modes.length)
  })
})

describe('PROTECTION_MODE_META', () => {
  it('覆盖四种防护模式且 BYPASS 颜色醒目区别于其他模式', () => {
    for (const mode of ['OFF', 'OBSERVE', 'PROTECT', 'BYPASS']) {
      expect(PROTECTION_MODE_META[mode], `missing meta for ${mode}`).toBeDefined()
    }
    expect(PROTECTION_MODE_META.BYPASS.label).toBe('透传')
    const otherColors = ['OFF', 'OBSERVE', 'PROTECT'].map((m) => PROTECTION_MODE_META[m].color)
    expect(otherColors).not.toContain(PROTECTION_MODE_META.BYPASS.color)
  })
})

describe('certRemainingDays', () => {
  it('空值与非法日期返回 null', () => {
    expect(certRemainingDays(null)).toBeNull()
    expect(certRemainingDays(undefined)).toBeNull()
    expect(certRemainingDays('')).toBeNull()
    expect(certRemainingDays('not-a-date')).toBeNull()
  })

  it('未来日期返回正数天数', () => {
    const future = dayjs().add(10, 'day').format('YYYY-MM-DD HH:mm:ss')
    expect(certRemainingDays(future)).toBe(10)
  })

  it('过去日期返回负数（已过期）', () => {
    const past = dayjs().subtract(3, 'day').format('YYYY-MM-DD HH:mm:ss')
    expect(certRemainingDays(past)).toBe(-3)
  })
})

describe('certRemainingColor', () => {
  it('按剩余天数分级：<7 红 / <15 橙 / <30 黄 / 其余绿', () => {
    expect(certRemainingColor(-1)).toBe('red')
    expect(certRemainingColor(0)).toBe('red')
    expect(certRemainingColor(6)).toBe('red')
    expect(certRemainingColor(7)).toBe('orange')
    expect(certRemainingColor(14)).toBe('orange')
    expect(certRemainingColor(15)).toBe('gold')
    expect(certRemainingColor(29)).toBe('gold')
    expect(certRemainingColor(30)).toBe('green')
    expect(certRemainingColor(365)).toBe('green')
  })
})

describe('isTerminalTaskStatus', () => {
  it('SUCCESS/FAILED/ROLLED_BACK 为终态', () => {
    expect(isTerminalTaskStatus('SUCCESS')).toBe(true)
    expect(isTerminalTaskStatus('FAILED')).toBe(true)
    expect(isTerminalTaskStatus('ROLLED_BACK')).toBe(true)
  })

  it('进行中的状态不是终态', () => {
    expect(isTerminalTaskStatus('PENDING')).toBe(false)
    expect(isTerminalTaskStatus('VALIDATING')).toBe(false)
    expect(isTerminalTaskStatus('PUBLISHING')).toBe(false)
    expect(isTerminalTaskStatus('')).toBe(false)
  })
})

describe('parseBusinessSnapshot', () => {
  it('解析合法 JSON 字符串', () => {
    const json = '{"apps":[{"code":"waf-test","mode":"PROTECT","domains":1,"upstreams":1}]}'
    expect(parseBusinessSnapshot(json)).toEqual({
      apps: [{ code: 'waf-test', mode: 'PROTECT', domains: 1, upstreams: 1 }],
    })
  })

  it('空值/非法 JSON/缺 apps 字段返回 null', () => {
    expect(parseBusinessSnapshot('')).toBeNull()
    expect(parseBusinessSnapshot('{bad json')).toBeNull()
    expect(parseBusinessSnapshot('{"foo":1}')).toBeNull()
  })
})

describe('truncateHash', () => {
  it('长哈希截断并追加省略号', () => {
    const hash = '3506b789b678333b235620cd8b50f9611e4a34c161bdf0d63a9d7deccd1faf18'
    expect(truncateHash(hash)).toBe('3506b789b678…')
  })

  it('短值原样返回，空值返回占位符', () => {
    expect(truncateHash('abc')).toBe('abc')
    expect(truncateHash('')).toBe('-')
  })
})
