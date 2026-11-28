import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ipLibrariesApi } from '../ipLibraries'
import { setCsrfToken, setSessionExpiredHandler } from '../client'

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function stubFetch(body: unknown, status = 200) {
  const fn = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(() =>
    Promise.resolve(jsonResponse(status, { code: 'SUCCESS', message: 'ok', data: body })),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('ipLibrariesApi', () => {
  beforeEach(() => {
    setCsrfToken('csrf-test-token')
    setSessionExpiredHandler(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setCsrfToken(null)
    setSessionExpiredHandler(null)
  })

  it('出站设置：GET 与 PUT /api/v1/ip-libraries/outbound-settings 携带 CSRF 头并透传写只读凭据标志', async () => {
    const fetchMock = stubFetch({
      outbound_allowlist: '10.0.0.0/8',
      allow_insecure_http_mirror: true,
      proxy_url: 'http://proxy.corp.local:3128',
      has_proxy_auth: true,
      http_timeout_seconds: 180,
    })

    const cur = await ipLibrariesApi.getOutboundSettings()
    expect(cur.has_proxy_auth).toBe(true)
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/ip-libraries/outbound-settings')

    await ipLibrariesApi.updateOutboundSettings({
      outbound_allowlist: '10.0.0.0/8',
      allow_insecure_http_mirror: true,
      proxy_url: 'http://proxy.corp.local:3128',
      clear_proxy_auth: true,
      http_timeout_seconds: 180,
    })
    const [putUrl, putInit] = fetchMock.mock.calls[1]
    expect(String(putUrl)).toBe('/api/v1/ip-libraries/outbound-settings')
    expect(putInit?.method).toBe('PUT')
    expect((putInit?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-test-token')
    expect(JSON.parse(String(putInit?.body))).toMatchObject({
      clear_proxy_auth: true,
      http_timeout_seconds: 180,
    })
  })

  it('GeoIP 状态/设置/同步/回滚/HA重同步/运行历史接口路径与空数组归一化正确', async () => {
    const fetchMock = stubFetch({
      geo_enabled: true,
      sources: null,
      revision: 'rev-1',
      schedule: {
        auto_update_enabled: false,
        schedule_cron: '0 3 2 * *',
        ha_sync_enabled: true,
        maxmind_account_id: '12345',
        has_maxmind_license_key: true,
      },
      slots: [
        {
          slot: 'ip2region_v4',
          display_name: 'ip2region IPv4',
          canonical_file: 'ip2region_v4.xdb',
          format: 'xdb',
          max_bytes: 67108864,
          enabled: false,
          source_mode: 'OFFLINE_ONLY',
          official_preset: 'ip2region_v4',
          custom_url: '',
          active_origin: 'runtime',
          active_filename: 'ip2region_v4.xdb',
          active_source_type: 'OFFLINE',
          sha256: 'a'.repeat(64),
          size_bytes: 1024,
          last_status: 'SUCCESS',
          last_error: '',
          backups: null,
        },
      ],
      ha_nodes: null,
      presets: null,
    })

    const status = await ipLibrariesApi.getGeoIpStatus()
    expect(status.sources).toEqual([])
    expect(status.slots[0].backups).toEqual([])
    expect(status.ha_nodes).toEqual([])
    expect(status.presets).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/geoip/status')

    await ipLibrariesApi.updateGeoIpSettings({
      auto_update_enabled: true,
      schedule_cron: '0 4 * * *',
      ha_sync_enabled: true,
      maxmind_account_id: '12345',
      clear_maxmind_license_key: true,
      slots: [],
    })
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/geoip/settings')
    expect(fetchMock.mock.calls[1][1]?.method).toBe('PUT')

    await ipLibrariesApi.syncGeoIp('dbip_city')
    expect(String(fetchMock.mock.calls[2][0])).toBe('/api/v1/geoip/sync')
    expect(JSON.parse(String(fetchMock.mock.calls[2][1]?.body))).toEqual({ slot: 'dbip_city' })

    await ipLibrariesApi.rollbackGeoIp('ip2region_v4', '1700000000-abcdef123456.xdb')
    expect(String(fetchMock.mock.calls[3][0])).toBe('/api/v1/geoip/rollback')
    expect(JSON.parse(String(fetchMock.mock.calls[3][1]?.body))).toEqual({
      slot: 'ip2region_v4',
      backup_id: '1700000000-abcdef123456.xdb',
    })

    const haResyncFetch = stubFetch({
      runs: null,
      succeeded: 1,
      skipped: 0,
      partial_ha_failed: 0,
      failed: 0,
    })
    const haRes = await ipLibrariesApi.haResyncGeoIp('')
    expect(haRes.runs).toEqual([])
    expect(haRes.succeeded).toBe(1)
    expect(String(haResyncFetch.mock.calls[0][0])).toBe('/api/v1/geoip/ha-resync')
    expect(JSON.parse(String(haResyncFetch.mock.calls[0][1]?.body))).toEqual({ slot: '' })

    const runsFetch = stubFetch({
      items: [
        {
          id: 'run-1',
          slot: 'ip2region_v4',
          trigger_type: 'OFFLINE_UPLOAD',
          status: 'SUCCESS',
          source_label: 'ip2region_v4.xdb',
          previous_sha256: '',
          new_sha256: 'b'.repeat(64),
          file_size_bytes: 2048,
          ha_results: null,
          error_message: '',
          started_at: '2026-11-28T01:00:00Z',
          finished_at: '2026-11-28T01:00:02Z',
        },
      ],
      total: 1,
      page: 1,
      page_size: 10,
    })
    const runs = await ipLibrariesApi.listGeoIpRuns({
      slot: 'ip2region_v4',
      status: 'SUCCESS',
      page: 1,
      page_size: 10,
    })
    expect(runs.items[0].ha_results).toEqual([])
    const runsUrl = String(runsFetch.mock.calls[0][0])
    expect(runsUrl).toContain('/api/v1/geoip/runs?')
    expect(runsUrl).toContain('slot=ip2region_v4')
    expect(runsUrl).toContain('status=SUCCESS')
  })

  it('GeoIP 离线上传：POST /api/v1/geoip/upload 使用 multipart FormData 并携带 X-CSRF-Token 头', async () => {
    const fetchMock = stubFetch({
      slot: 'ip2region_v4',
      filename: 'ip2region_v4.xdb',
      previous_sha256: '',
      new_sha256: 'c'.repeat(64),
      size_bytes: 512,
      revision: 'rev-2',
      unchanged: false,
      loaded_sources: ['ip2region_v4'],
    })

    const file = new File(['dummy-xdb'], 'ip2region_v4.xdb', {
      type: 'application/octet-stream',
    })
    const sha = 'c'.repeat(64)
    const res = await ipLibrariesApi.uploadGeoIp('ip2region_v4', file, sha)

    expect(res.revision).toBe('rev-2')
    const [url, init] = fetchMock.mock.calls[0]
    expect(String(url)).toBe('/api/v1/geoip/upload')
    expect(init?.method).toBe('POST')
    expect((init?.headers as Record<string, string>)['X-CSRF-Token']).toBe('csrf-test-token')
    expect(init?.body).toBeInstanceOf(FormData)
    const form = init?.body as FormData
    expect(form.get('slot')).toBe('ip2region_v4')
    expect(form.get('expected_sha256')).toBe(sha)
    expect((form.get('file') as File).name).toBe('ip2region_v4.xdb')
  })

  it('威胁情报接口：订阅源 CRUD、全局设置、强制同步、离线导入与运行历史均对齐契约', async () => {
    const fetchMock = stubFetch({
      settings: { auto_update_enabled: false, circuit_threshold: 5 },
      summary: { enabled_count: 1, total_active_rules: 42, circuit_open_count: 0 },
      presets: null,
      feeds: null,
    })

    const listRes = await ipLibrariesApi.listThreatIntelFeeds()
    expect(listRes.presets).toEqual([])
    expect(listRes.feeds).toEqual([])
    expect(String(fetchMock.mock.calls[0][0])).toBe('/api/v1/threat-intel/feeds')

    await ipLibrariesApi.updateThreatIntelSettings({
      auto_update_enabled: true,
      circuit_threshold: 3,
    })
    expect(String(fetchMock.mock.calls[1][0])).toBe('/api/v1/threat-intel/settings')
    expect(fetchMock.mock.calls[1][1]?.method).toBe('PUT')

    await ipLibrariesApi.createThreatIntelFeed({
      feed_key: 'corp_soc',
      name: '企业 SOC 源',
      enabled: true,
      source_mode: 'CUSTOM_URL',
      custom_url: 'https://soc.internal/blocklist.txt',
      format: 'text',
      allow_cidr: true,
      ttl_days: 15,
      schedule_cron: '0 */4 * * *',
      min_entries_guard: true,
      max_drop_ratio: 0.75,
    })
    expect(String(fetchMock.mock.calls[2][0])).toBe('/api/v1/threat-intel/feeds')
    expect(fetchMock.mock.calls[2][1]?.method).toBe('POST')

    await ipLibrariesApi.updateThreatIntelFeed('feed-1', {
      name: '企业 SOC 源 v2',
      enabled: false,
      source_mode: 'OFFLINE_ONLY',
      format: 'text',
      allow_cidr: false,
      ttl_days: 30,
      schedule_cron: '0 */6 * * *',
      min_entries_guard: true,
      max_drop_ratio: 0.8,
    })
    expect(String(fetchMock.mock.calls[3][0])).toBe('/api/v1/threat-intel/feeds/feed-1')
    expect(fetchMock.mock.calls[3][1]?.method).toBe('PUT')

    await ipLibrariesApi.syncThreatIntelFeed('feed-1', true)
    expect(String(fetchMock.mock.calls[4][0])).toBe('/api/v1/threat-intel/feeds/feed-1/sync')
    expect(JSON.parse(String(fetchMock.mock.calls[4][1]?.body))).toEqual({
      force_ignore_guard: true,
    })

    await ipLibrariesApi.deleteThreatIntelFeed('feed-1')
    expect(String(fetchMock.mock.calls[5][0])).toBe('/api/v1/threat-intel/feeds/feed-1')
    expect(fetchMock.mock.calls[5][1]?.method).toBe('DELETE')

    const importFetch = stubFetch({
      batch_id: 'b-001',
      feed: 'feodo',
      ttl_days: 30,
      total_parsed: 2,
      added: 1,
      refreshed: 0,
      expired: 0,
      skipped_conflict: 1,
      invalid: 0,
      truncated: false,
      conflicts: null,
      invalid_entries: null,
    })
    const imp = await ipLibrariesApi.importThreatIntelSnapshot({
      feed: 'feodo',
      format: 'text',
      ttl_days: 30,
      content: '203.0.113.1\n198.51.100.2',
    })
    expect(imp.conflicts).toEqual([])
    expect(imp.invalid_entries).toEqual([])
    expect(String(importFetch.mock.calls[0][0])).toBe('/api/v1/threat-intel/import')

    const runsFetch = stubFetch({ items: null, total: 0, page: 1, page_size: 10 })
    const runs = await ipLibrariesApi.listThreatIntelRuns({
      feed_key: 'feodo',
      trigger_type: 'MANUAL',
      page: 1,
      page_size: 10,
    })
    expect(runs.items).toEqual([])
    const runsUrl = String(runsFetch.mock.calls[0][0])
    expect(runsUrl).toContain('/api/v1/threat-intel/runs?')
    expect(runsUrl).toContain('feed_key=feodo')
    expect(runsUrl).toContain('trigger_type=MANUAL')
  })
})
