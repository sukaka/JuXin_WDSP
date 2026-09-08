import type { ReactNode } from 'react'
import {
  AimOutlined,
  AlertOutlined,
  ApartmentOutlined,
  GlobalOutlined,
  MonitorOutlined,
  RadarChartOutlined,
} from '@ant-design/icons'
import { useAuthStore } from '../../stores/auth'
import { useProductStore } from '../../stores/product'
import { hasAnyPermission } from '../../utils/permission'

/** 大屏轮询刷新间隔（毫秒）：30 秒级轮询，兼顾实时性与渲染性能 */
export const REFRESH_INTERVAL = 30_000

export interface BigScreenDef {
  id: string
  path: string
  title: string
  description: string
  /** 任一权限即可进入 */
  permissions: string[]
  /** 依赖的产品能力 */
  capability?: 'api_dynamic_protection'
  icon: ReactNode
  /** 主题强调色 */
  accent: string
  accentGlow: string
}

export const BIG_SCREENS: BigScreenDef[] = [
  {
    id: 'security-posture',
    path: '/big-screen/security-posture',
    title: '安全态势总览',
    description: '全局防护态势一屏尽览：今日请求与攻击拦截指标、安全事件趋势、风险等级分布、攻击类型与高危事件动态。',
    permissions: ['dashboard.security.read'],
    icon: <RadarChartOutlined />,
    accent: '#00e5ff',
    accentGlow: 'rgba(0, 229, 255, 0.45)',
  },
  {
    id: 'attack-monitor',
    path: '/big-screen/attack-monitor',
    title: '攻击监控中心',
    description: '实时攻击监控：攻击类型构成、攻击源 IP 与目标 URI 排行、命中规则 TOP、最新安全事件滚动播报。',
    permissions: ['analytics.security.read', 'security_events.read'],
    icon: <AlertOutlined />,
    accent: '#ff5252',
    accentGlow: 'rgba(255, 82, 82, 0.45)',
  },
  {
    id: 'globe-attack',
    path: '/big-screen/globe-attack',
    title: '全球攻击态势',
    description: '全球攻击态势感知：全屏 3D 地球实时渲染攻击来源国路线与强度，配套今日攻击指标、风险等级分布、攻击类型 TOP 与实时事件播报。',
    permissions: ['analytics.security.read', 'security_events.read'],
    icon: <AimOutlined />,
    accent: '#00b0ff',
    accentGlow: 'rgba(0, 176, 255, 0.45)',
  },
  {
    id: 'traffic-access',
    path: '/big-screen/traffic-access',
    title: '流量与访问控制',
    description: '业务流量与访问控制态势：请求趋势与时延、CC 防护拦截、黑白名单命中、临时封禁趋势与受影响应用。',
    permissions: ['analytics.security.read'],
    icon: <GlobalOutlined />,
    accent: '#69f0ae',
    accentGlow: 'rgba(105, 240, 174, 0.45)',
  },
  {
    id: 'api-security',
    path: '/big-screen/api-security',
    title: 'API 安全态势',
    description: 'API 动态防护：接口资产与学习覆盖、模型冻结率、风险发现等级分布、运行时拦截与热点接口。',
    permissions: ['api_runtime.read'],
    capability: 'api_dynamic_protection',
    icon: <ApartmentOutlined />,
    accent: '#b388ff',
    accentGlow: 'rgba(179, 136, 255, 0.45)',
  },
  {
    id: 'runtime-ops',
    path: '/big-screen/runtime-ops',
    title: '系统运行监控',
    description: '平台运行健康：组件在线状态点阵、网关运行时长、发布与报告成功率、数据库存储与磁盘容量水位。',
    permissions: ['system_health.read'],
    icon: <MonitorOutlined />,
    accent: '#ffd54f',
    accentGlow: 'rgba(255, 213, 79, 0.45)',
  },
]

/** 按权限与产品能力过滤可进入的大屏（纯函数，便于测试） */
export function filterBigScreens(
  permissions: string[] | null | undefined,
  capabilities?: { apiDynamicProtection?: boolean },
): BigScreenDef[] {
  return BIG_SCREENS.filter((s) => {
    if (!hasAnyPermission(permissions, s.permissions)) return false
    if (s.capability === 'api_dynamic_protection') return capabilities?.apiDynamicProtection === true
    return true
  })
}

/** 按登录用户权限与产品能力过滤可进入的大屏 */
export function useAvailableScreens(): BigScreenDef[] {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const apiDynamicProtection = useProductStore((s) => s.apiDynamicProtection)
  return filterBigScreens(permissions, { apiDynamicProtection })
}
