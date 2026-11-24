import { describe, expect, it } from 'vitest'
import { BIG_SCREENS, filterBigScreens } from '../screens'

describe('filterBigScreens', () => {
  it('注册 7 个大屏且 id/path 唯一，运维大屏由 big_screen.runtime.read 门控', () => {
    expect(BIG_SCREENS).toHaveLength(7)
    expect(new Set(BIG_SCREENS.map((s) => s.id)).size).toBe(7)
    expect(new Set(BIG_SCREENS.map((s) => s.path)).size).toBe(7)
    for (const s of BIG_SCREENS) {
      expect(s.path).toBe(`/big-screen/${s.id}`)
    }
    const gw = BIG_SCREENS.find((s) => s.id === 'gateway-connections')
    expect(gw).toBeDefined()
    expect(gw?.title).toBe('网关连接与会话')
    expect(gw?.permissions).toEqual(['big_screen.runtime.read'])
    expect(gw?.accent).toBe('#26c6da')

    const runtimeOps = BIG_SCREENS.find((s) => s.id === 'runtime-ops')
    expect(runtimeOps).toBeDefined()
    expect(runtimeOps?.title).toBe('系统运行监控')
    expect(runtimeOps?.permissions).toEqual(['big_screen.runtime.read'])
  })

  it('无权限时返回空', () => {
    expect(filterBigScreens([], { apiDynamicProtection: true })).toEqual([])
    expect(filterBigScreens(null, { apiDynamicProtection: true })).toEqual([])
  })

  it('系统管理员仅持系统运维权限（system_health.read / dashboard.runtime.read）时可见 0 块大屏', () => {
    expect(
      filterBigScreens(['system_health.read', 'dashboard.runtime.read'], {
        apiDynamicProtection: true,
      }),
    ).toEqual([])
  })

  it('运维管理员持有全部安全与运行监控大屏权限时可见全部 7 块大屏', () => {
    const ids = filterBigScreens(
      [
        'dashboard.security.read',
        'analytics.security.read',
        'security_events.read',
        'api_runtime.read',
        'big_screen.runtime.read',
      ],
      { apiDynamicProtection: true },
    ).map((s) => s.id)
    expect(ids).toEqual([
      'security-posture',
      'attack-monitor',
      'globe-attack',
      'traffic-access',
      'api-security',
      'gateway-connections',
      'runtime-ops',
    ])
  })

  it('API 大屏依赖产品能力开关', () => {
    const permissions = ['api_runtime.read']
    expect(filterBigScreens(permissions, { apiDynamicProtection: true }).map((s) => s.id)).toEqual([
      'api-security',
    ])
    expect(filterBigScreens(permissions, { apiDynamicProtection: false })).toEqual([])
  })

  it('仅持 big_screen.runtime.read 时可见网关连接与会话及系统运行监控大屏', () => {
    const ids = filterBigScreens(['big_screen.runtime.read'], {
      apiDynamicProtection: true,
    }).map((s) => s.id)
    expect(ids).toEqual(['gateway-connections', 'runtime-ops'])
  })
})
