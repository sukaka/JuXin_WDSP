import { describe, expect, it } from 'vitest'
import { BIG_SCREENS, filterBigScreens } from '../screens'

describe('filterBigScreens', () => {
  it('注册 6 个大屏且 id/path 唯一', () => {
    expect(BIG_SCREENS).toHaveLength(6)
    expect(new Set(BIG_SCREENS.map((s) => s.id)).size).toBe(6)
    expect(new Set(BIG_SCREENS.map((s) => s.path)).size).toBe(6)
    for (const s of BIG_SCREENS) {
      expect(s.path).toBe(`/big-screen/${s.id}`)
    }
  })

  it('无权限时返回空', () => {
    expect(filterBigScreens([], { apiDynamicProtection: true })).toEqual([])
    expect(filterBigScreens(null, { apiDynamicProtection: true })).toEqual([])
  })

  it('安全管理员可见安全态势、攻击监控与全球攻击态势', () => {
    const ids = filterBigScreens(['dashboard.security.read', 'analytics.security.read'], {
      apiDynamicProtection: true,
    }).map((s) => s.id)
    expect(ids).toEqual(['security-posture', 'attack-monitor', 'globe-attack', 'traffic-access'])
  })

  it('API 大屏依赖产品能力开关', () => {
    const permissions = ['api_runtime.read']
    expect(filterBigScreens(permissions, { apiDynamicProtection: true }).map((s) => s.id)).toEqual([
      'api-security',
    ])
    expect(filterBigScreens(permissions, { apiDynamicProtection: false })).toEqual([])
  })

  it('系统管理员仅可见运行监控大屏', () => {
    const ids = filterBigScreens(['system_health.read'], { apiDynamicProtection: true }).map((s) => s.id)
    expect(ids).toEqual(['runtime-ops'])
  })
})
