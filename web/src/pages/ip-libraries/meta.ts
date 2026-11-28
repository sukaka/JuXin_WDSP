import type { GeoIpPresetInfo, ThreatIntelPresetInfo } from '../../api/ipLibraries'

export interface TagMeta {
  color: string
  label: string
}

/** 更新来源模式 */
export const SOURCE_MODE_META: Record<string, TagMeta> = {
  OFFLINE_ONLY: { color: 'default', label: '纯离线' },
  OFFICIAL: { color: 'blue', label: '官方源' },
  CUSTOM_URL: { color: 'purple', label: '内网镜像 / 自定义源' },
}

export const SOURCE_MODE_OPTIONS = [
  { value: 'OFFLINE_ONLY', label: '纯离线（不发起出站请求）' },
  { value: 'OFFICIAL', label: '官方源（硬编码域名白名单 HTTPS）' },
  { value: 'CUSTOM_URL', label: '内网镜像 / 自定义源' },
]

/** GeoIP 活跃文件来源位置 */
export const GEO_ACTIVE_ORIGIN_META: Record<string, TagMeta> = {
  runtime: { color: 'green', label: '运行期热加载' },
  builtin: { color: 'geekblue', label: '镜像内置' },
  missing: { color: 'default', label: '未加载' },
}

/** GeoIP 活跃文件入库来源类型 */
export const GEO_SOURCE_TYPE_META: Record<string, TagMeta> = {
  BUILTIN: { color: 'default', label: '内置' },
  ONLINE: { color: 'blue', label: '在线同步' },
  OFFLINE: { color: 'cyan', label: '离线上传' },
  HA_SYNC: { color: 'purple', label: 'HA 同步' },
  ROLLBACK: { color: 'orange', label: '版本回滚' },
}

/** GeoIP 触发方式 */
export const GEO_TRIGGER_META: Record<string, TagMeta> = {
  SCHEDULED: { color: 'blue', label: '定时任务' },
  MANUAL: { color: 'geekblue', label: '手动同步' },
  OFFLINE_UPLOAD: { color: 'cyan', label: '离线上传' },
  ROLLBACK: { color: 'orange', label: '历史回滚' },
  HA_RESYNC: { color: 'purple', label: 'HA 重同步' },
}

/** GeoIP 执行状态 */
export const GEO_RUN_STATUS_META: Record<string, TagMeta> = {
  IDLE: { color: 'default', label: '未执行' },
  SUCCESS: { color: 'green', label: '成功' },
  SKIPPED_UNCHANGED: { color: 'blue', label: '无变更跳过' },
  PARTIAL_HA_FAILED: { color: 'orange', label: '本机成功 / 备机部分失败' },
  FAILED: { color: 'red', label: '失败' },
}

/** HA 单节点推送状态 */
export const HA_PUSH_STATUS_META: Record<string, TagMeta> = {
  SUCCESS: { color: 'green', label: '已同步' },
  FAILED: { color: 'red', label: '推送失败' },
  SKIPPED: { color: 'default', label: '已跳过' },
}

/** 威胁情报触发方式 */
export const THREAT_TRIGGER_META: Record<string, TagMeta> = {
  SCHEDULED: { color: 'blue', label: '定时拉取' },
  MANUAL: { color: 'geekblue', label: '手动拉取' },
  OFFLINE_IMPORT: { color: 'cyan', label: '离线导入' },
}

/** 威胁情报同步状态 */
export const THREAT_RUN_STATUS_META: Record<string, TagMeta> = {
  IDLE: { color: 'default', label: '未同步' },
  SUCCESS: { color: 'green', label: '同步成功' },
  SKIPPED_NOT_MODIFIED: { color: 'blue', label: '未变化跳过' },
  GUARD_ABORTED: { color: 'orange', label: '护栏中止' },
  FAILED: { color: 'red', label: '失败' },
}

/** 威胁情报解析格式 */
export const THREAT_FORMAT_META: Record<string, TagMeta> = {
  text: { color: 'geekblue', label: '纯文本（TEXT）' },
  csv: { color: 'purple', label: 'Feodo CSV' },
}

/** GeoIP 槽位名称兜底映射 */
export const GEO_SLOT_LABELS: Record<string, string> = {
  ip2region_v4: 'ip2region IPv4（国内省市/运营商）',
  ip2region_v6: 'ip2region IPv6（国内省市/运营商）',
  dbip_city: '全球城市库（DB-IP Lite / MaxMind GeoLite2 City）',
  city_ipv6: 'IPv6 专用城市库（MMDB）',
  country: '国家码回退库（DB-IP / GeoLite2 / Country MMDB）',
}

/** GeoIP 官方预置源兜底清单（后端 presets 未下发或加载中时使用） */
export const DEFAULT_GEO_PRESETS: GeoIpPresetInfo[] = [
  {
    id: 'ip2region_v4',
    slot: 'ip2region_v4',
    name: 'ip2region IPv4 官方 XDB（Apache-2.0 / MIT）',
    license: 'Apache-2.0 OR MIT',
  },
  {
    id: 'ip2region_v6',
    slot: 'ip2region_v6',
    name: 'ip2region IPv6 官方 XDB（Apache-2.0 / MIT）',
    license: 'Apache-2.0 OR MIT',
  },
  {
    id: 'dbip_city_lite',
    slot: 'dbip_city',
    name: 'DB-IP City Lite 月度免费版（CC BY 4.0）',
    license: 'CC BY 4.0',
    monthly_fallback: true,
  },
  {
    id: 'maxmind_geolite2_city',
    slot: 'dbip_city',
    name: 'MaxMind GeoLite2 City（需 Account ID + License Key）',
    license: 'MaxMind GeoLite2 EULA',
    requires_maxmind_auth: true,
  },
  {
    id: 'dbip_country_lite',
    slot: 'country',
    name: 'DB-IP Country Lite 月度免费版（CC BY 4.0）',
    license: 'CC BY 4.0',
    monthly_fallback: true,
  },
  {
    id: 'geo_country_mmdb',
    slot: 'country',
    name: 'geo-whois-asn-country MMDB（CC0-1.0）',
    license: 'CC0-1.0',
  },
  {
    id: 'maxmind_geolite2_country',
    slot: 'country',
    name: 'MaxMind GeoLite2 Country（需 Account ID + License Key）',
    license: 'MaxMind GeoLite2 EULA',
    requires_maxmind_auth: true,
  },
]

/** 威胁情报内置 CC0 官方预置源兜底清单（不含 GPL 源） */
export const DEFAULT_THREAT_PRESETS: ThreatIntelPresetInfo[] = [
  {
    key: 'feodo',
    name: 'abuse.ch Feodo C2 IP 清单（CC0-1.0）',
    format: 'text',
    license: 'CC0-1.0',
  },
  {
    key: 'sslbl',
    name: 'abuse.ch SSLBL 恶意 C2 IP 清单（CC0-1.0）',
    format: 'text',
    license: 'CC0-1.0',
  },
]

/** 短 SHA-256 展示（前 12 位），空值返回占位符 */
export function shortSha256(hash?: string | null): string {
  if (!hash) return '-'
  const trimmed = hash.trim()
  if (!trimmed) return '-'
  return trimmed.length > 12 ? trimmed.slice(0, 12) : trimmed
}
