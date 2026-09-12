/**
 * 全球攻击态势屏 / 攻击路线地球的演示数据（无真实数据时兜底）。
 *
 * 触发原则：仅当接口查询失败，或查询成功但返回数据为空（无攻击事件）时启用；
 * 一旦接口返回真实数据，立即切换为真实数据展示，本文件数据不再参与渲染。
 * IP 一律使用 RFC 5737 文档保留段（203.0.113.x / 198.51.100.x / 192.0.2.x），
 * 域名使用 demo- 前缀的 example.com 保留域，不冒充任何真实站点。
 */

/**
 * 演示攻击路线（演示数据，无真实数据时兜底）：来源国按攻击量降序、红黄蓝（高/中/低危）混合。
 * 国家质心坐标由 geoData.getCountryCentroids() 按 Natural Earth 真实地理数据解析；
 * 注意 world-atlas 110m 数据集不含新加坡/中国香港等超小区域，选型时已规避。
 */
export const DEMO_ATTACK_ROUTES: { country: string; count: number; color: string }[] = [
  { country: 'US', count: 96, color: '#ff5252' },
  { country: 'RU', count: 88, color: '#ff5252' },
  { country: 'VN', count: 72, color: '#ff5252' },
  { country: 'BR', count: 64, color: '#ff5252' },
  { country: 'NL', count: 57, color: '#ff5252' },
  { country: 'IN', count: 49, color: '#ffd54f' },
  { country: 'DE', count: 43, color: '#ffd54f' },
  { country: 'KR', count: 38, color: '#ffd54f' },
  { country: 'FR', count: 33, color: '#ffd54f' },
  { country: 'GB', count: 29, color: '#ffd54f' },
  { country: 'ID', count: 24, color: '#ffd54f' },
  { country: 'TH', count: 19, color: '#2979ff' },
  { country: 'JP', count: 16, color: '#2979ff' },
  { country: 'TR', count: 13, color: '#2979ff' },
  { country: 'CA', count: 11, color: '#2979ff' },
  { country: 'AU', count: 9, color: '#2979ff' },
  { country: 'MX', count: 7, color: '#2979ff' },
  { country: 'ZA', count: 6, color: '#2979ff' },
]

/** 演示 KPI（演示数据，无真实数据时兜底）：24h 攻击总量 / 已拦截 */
export const DEMO_KPI = { totalAttacks: 3842, blocked: 2967 }

/** 演示风险等级分布（演示数据，无真实数据时兜底）：四项合计与 DEMO_KPI.totalAttacks 保持一致 */
export const DEMO_RISK_LEVELS = [
  { key: 'HIGH', value: 326 },
  { key: 'MEDIUM', value: 1047 },
  { key: 'LOW', value: 1689 },
  { key: 'INFO', value: 780 },
]

/** 演示攻击类型 TOP5（演示数据，无真实数据时兜底）：key 对应 ATTACK_TYPE_META 中文名 */
export const DEMO_ATTACK_TYPES = [
  { key: 'SQL_INJECTION', value: 1186 },
  { key: 'XSS', value: 942 },
  { key: 'SCANNER_DETECTION', value: 763 },
  { key: 'LOCAL_FILE_INCLUSION', value: 518 },
  { key: 'COMMAND_INJECTION', value: 433 },
]

/** 演示实时攻击事件（演示数据，无真实数据时兜底）：secondsAgo 相对当前时刻回推，保持“正在发生”的观感 */
export const DEMO_TICKER_EVENTS: {
  id: string
  secondsAgo: number
  ip: string
  domain: string
  path: string
  attackType: string
  severity: string
  action: 'BLOCK' | 'OBSERVE'
}[] = [
  { id: 'demo-01', secondsAgo: 8, ip: '203.0.113.17', domain: 'demo-mall.example.com', path: '/login', attackType: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { id: 'demo-02', secondsAgo: 26, ip: '198.51.100.42', domain: 'demo-api.example.com', path: '/v1/users', attackType: 'SCANNER_DETECTION', severity: 'LOW', action: 'OBSERVE' },
  { id: 'demo-03', secondsAgo: 55, ip: '203.0.113.88', domain: 'demo-crm.example.com', path: '/admin/config', attackType: 'COMMAND_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { id: 'demo-04', secondsAgo: 120, ip: '192.0.2.115', domain: 'demo-mall.example.com', path: '/search', attackType: 'XSS', severity: 'MEDIUM', action: 'BLOCK' },
  { id: 'demo-05', secondsAgo: 168, ip: '203.0.113.201', domain: 'demo-oa.example.com', path: '/download', attackType: 'LOCAL_FILE_INCLUSION', severity: 'MEDIUM', action: 'BLOCK' },
  { id: 'demo-06', secondsAgo: 245, ip: '198.51.100.77', domain: 'demo-api.example.com', path: '/v2/pay', attackType: 'PROTOCOL_VIOLATION', severity: 'LOW', action: 'OBSERVE' },
  { id: 'demo-07', secondsAgo: 312, ip: '203.0.113.34', domain: 'demo-mall.example.com', path: '/upload', attackType: 'REMOTE_CODE_EXECUTION', severity: 'HIGH', action: 'BLOCK' },
  { id: 'demo-08', secondsAgo: 430, ip: '192.0.2.66', domain: 'demo-crm.example.com', path: '/export', attackType: 'INFORMATION_DISCLOSURE', severity: 'MEDIUM', action: 'OBSERVE' },
  { id: 'demo-09', secondsAgo: 588, ip: '203.0.113.150', domain: 'demo-api.example.com', path: '/v1/auth', attackType: 'SESSION_FIXATION', severity: 'LOW', action: 'OBSERVE' },
  { id: 'demo-10', secondsAgo: 742, ip: '198.51.100.230', domain: 'demo-mall.example.com', path: '/cart', attackType: 'XSS', severity: 'MEDIUM', action: 'BLOCK' },
  { id: 'demo-11', secondsAgo: 1050, ip: '203.0.113.5', domain: 'demo-oa.example.com', path: '/sso/callback', attackType: 'SQL_INJECTION', severity: 'HIGH', action: 'BLOCK' },
  { id: 'demo-12', secondsAgo: 1480, ip: '192.0.2.190', domain: 'demo-crm.example.com', path: '/report', attackType: 'SCANNER_DETECTION', severity: 'INFO', action: 'OBSERVE' },
]
