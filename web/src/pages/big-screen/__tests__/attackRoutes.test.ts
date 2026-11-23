import { afterEach, describe, expect, it, vi } from 'vitest'
import { aggregateAttackRoutes, buildAttackRoutes, geoInfoToGeoPoint } from '../attackRoutes'
import { geoipApi } from '../../../api/geoip'
import { isPublicIp } from '../../../utils/ipgeo'
import type { GeoPoint } from '../../../utils/ipgeo'

const centroids = new Map<string, [number, number]>([
  ['CN', [104.2, 35.9]],
  ['US', [-95.7, 37.1]],
])

const geo = (countryCode: string, city = '', location: [number, number] | null = null): GeoPoint => ({
  countryCode,
  city,
  state: '',
  location,
})

/** 测试用 IP→归属地映射：1.x=济南/CN（真实坐标），8.x=US（无坐标回退质心），9.x=青岛/CN */
const resolve = (ip: string): GeoPoint | null => {
  if (ip.startsWith('1.')) return geo('CN', 'Jinan', [117.1, 36.65])
  if (ip.startsWith('9.')) return geo('CN', 'Qingdao', [120.38, 36.07])
  if (ip.startsWith('8.')) return geo('US')
  return null
}

describe('aggregateAttackRoutes', () => {
  it('城市级坐标直接作为弧线起点，同国不同城市分开聚合', () => {
    const routes = aggregateAttackRoutes(
      [
        { client_ip: '1.2.3.4', severity: 'LOW' },
        { client_ip: '9.9.9.9', severity: 'HIGH' },
      ],
      resolve,
      centroids,
    )
    expect(routes).toHaveLength(2)
    const jinan = routes.find((r) => r.city === 'Jinan')!
    const qingdao = routes.find((r) => r.city === 'Qingdao')!
    expect(jinan.from).toEqual([117.1, 36.65])
    expect(qingdao.from).toEqual([120.38, 36.07])
    expect(qingdao.severity).toBe('HIGH')
  })

  it('同城市多次攻击聚合计数并取最高严重级别', () => {
    const routes = aggregateAttackRoutes(
      [
        { client_ip: '1.2.3.4', severity: 'LOW' },
        { client_ip: '1.2.3.5', severity: 'HIGH' },
        { client_ip: '8.8.8.8', severity: 'MEDIUM' },
      ],
      resolve,
      centroids,
    )
    expect(routes).toHaveLength(2)
    // 按 count 降序，CN:Jinan 2 条在前
    expect(routes[0]).toEqual({ country: 'CN', city: 'Jinan', from: [117.1, 36.65], count: 2, severity: 'HIGH' })
    // US 无坐标 → 回退国家质心
    expect(routes[1]).toEqual({ country: 'US', city: '', from: [-95.7, 37.1], count: 1, severity: 'MEDIUM' })
  })

  it('内网/未识别/无质心的来源被跳过；空输入返回空', () => {
    const routes = aggregateAttackRoutes(
      [
        { client_ip: '10.0.0.1', severity: 'HIGH' }, // resolve 返回 null
        { client_ip: '1.1.1.1', severity: 'INFO' },
      ],
      resolve,
      centroids,
    )
    expect(routes).toHaveLength(1)
    expect(routes[0].city).toBe('Jinan')

    expect(aggregateAttackRoutes([], resolve, centroids)).toEqual([])
    // 国家无质心且无坐标 → 跳过
    const noCentroid = aggregateAttackRoutes(
      [{ client_ip: '8.8.8.8', severity: 'HIGH' }],
      () => geo('XX'),
      centroids,
    )
    expect(noCentroid).toEqual([])
  })
})

describe('isPublicIp', () => {
  it('公网地址返回 true', () => {
    expect(isPublicIp('8.8.8.8')).toBe(true)
    expect(isPublicIp('114.114.114.114')).toBe(true)
    expect(isPublicIp('2606:4700:4700::1111')).toBe(true)
  })

  it('内网/保留地址返回 false', () => {
    for (const ip of ['10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '169.254.0.1', '100.64.0.1', '224.0.0.1']) {
      expect(isPublicIp(ip)).toBe(false)
    }
    expect(isPublicIp('::1')).toBe(false)
    expect(isPublicIp('fe80::1')).toBe(false)
    expect(isPublicIp('fc00::1')).toBe(false)
  })
})

describe('geoInfoToGeoPoint & buildAttackRoutes', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('后端中国归属地按省市去后缀补全坐标，内网地址忽略', () => {
    expect(
      geoInfoToGeoPoint({
        ip: '202.96.128.86',
        scope: 'PUBLIC',
        country_code: 'CN',
        province: '广东省',
        city: '广州市',
        isp: '电信',
        label: '中国 广东省 广州市',
      }),
    ).toEqual({
      countryCode: 'CN',
      city: '广州市',
      state: '广东省',
      location: [113.26, 23.13],
    })

    expect(
      geoInfoToGeoPoint({
        ip: '10.0.0.1',
        scope: 'INTERNAL',
        label: '内网地址',
      }),
    ).toBeNull()
  })

  it('事件已携带 client_ip_geo 时直接复用且不发起批量请求', async () => {
    const spy = vi.spyOn(geoipApi, 'lookupBatch')
    const routes = await buildAttackRoutes([
      {
        client_ip: '202.96.128.86',
        severity: 'HIGH',
        client_ip_geo: {
          ip: '202.96.128.86',
          scope: 'PUBLIC',
          country_code: 'CN',
          province: '广东省',
          city: '广州市',
          isp: '电信',
          label: '中国 广东省 广州市',
          longitude: 113.26,
          latitude: 23.13,
        },
      },
    ])
    expect(spy).not.toHaveBeenCalled()
    expect(routes).toHaveLength(1)
    expect(routes[0]).toMatchObject({ country: 'CN', city: '广州市', from: [113.26, 23.13], count: 1 })
  })

  it('缺失 client_ip_geo 的公网 IP 走后端批量接口解析', async () => {
    const spy = vi.spyOn(geoipApi, 'lookupBatch').mockResolvedValue({
      geo_enabled: true,
      sources: ['ip2region_v4', 'dbip_city_v6'],
      items: {
        '45.148.10.75': {
          ip: '45.148.10.75',
          scope: 'PUBLIC',
          country_code: 'NL',
          country: '荷兰',
          province: 'South Holland',
          label: '荷兰 South Holland',
          longitude: 4.9041,
          latitude: 52.3676,
        },
      },
    })
    const routes = await buildAttackRoutes([
      { client_ip: '45.148.10.75', severity: 'MEDIUM' },
      { client_ip: '192.168.1.1', severity: 'LOW' },
    ])
    expect(spy).toHaveBeenCalledWith(['45.148.10.75'])
    expect(routes).toHaveLength(1)
    expect(routes[0]).toMatchObject({ country: 'NL', name: '荷兰', from: [4.9041, 52.3676] })
  })
})
