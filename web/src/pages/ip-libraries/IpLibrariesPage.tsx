import { useMemo, useState } from 'react'
import { Button, Card, Space, Tabs, Typography } from 'antd'
import type { TabsProps } from 'antd'
import { GlobalOutlined, SafetyOutlined, SettingOutlined } from '@ant-design/icons'
import { useAuthStore } from '../../stores/auth'
import { hasPermission } from '../../utils/permission'
import GeoIpTab from './GeoIpTab'
import OutboundSettingsDrawer from './OutboundSettingsDrawer'
import ThreatIntelTab from './ThreatIntelTab'

/**
 * IP 库与威胁情报统一管理页（路由：/ip-libraries，菜单归属：访问控制）。
 * 权限（遵循 000232 三权边界）：
 * - GeoIP：geoip.read（查看）/ geoip.manage（上传、同步、回滚、配置、HA 重同步及出站代理设置）
 * - 威胁情报：threat_intel.read（查看）/ threat_intel.manage（增改删订阅源、定时与拉取）/ access_rules.import（离线导入）
 */
export default function IpLibrariesPage() {
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canReadGeo = hasPermission(permissions, 'geoip.read')
  const canManageGeo = hasPermission(permissions, 'geoip.manage')
  const canReadThreat = hasPermission(permissions, 'threat_intel.read')
  const canManageThreat = hasPermission(permissions, 'threat_intel.manage')
  const canImportThreat = hasPermission(permissions, 'access_rules.import')

  const defaultTab = canReadGeo ? 'geoip' : 'threat-intel'
  const [activeTab, setActiveTab] = useState<string>(defaultTab)
  const [outboundOpen, setOutboundOpen] = useState(false)

  const tabItems = useMemo<NonNullable<TabsProps['items']>>(() => {
    const items: NonNullable<TabsProps['items']> = []
    if (canReadGeo) {
      items.push({
        key: 'geoip',
        label: (
          <Space size={6}>
            <GlobalOutlined />
            <span>GeoIP 归属地库</span>
          </Space>
        ),
        children: <GeoIpTab canManage={canManageGeo} />,
      })
    }
    if (canReadThreat) {
      items.push({
        key: 'threat-intel',
        label: (
          <Space size={6}>
            <SafetyOutlined />
            <span>威胁情报 IP 黑名单库</span>
          </Space>
        ),
        children: (
          <ThreatIntelTab canManage={canManageThreat} canImport={canImportThreat} />
        ),
      })
    }
    return items
  }, [canReadGeo, canManageGeo, canReadThreat, canManageThreat, canImportThreat])

  const effectiveTab = tabItems.some((i) => i.key === activeTab)
    ? activeTab
    : (tabItems[0]?.key ?? 'geoip')

  return (
    <Space direction="vertical" size="middle" style={{ width: '100%' }}>
      <Card size="small">
        <Space
          style={{ width: '100%', justifyContent: 'space-between' }}
          align="center"
          wrap
        >
          <div>
            <Typography.Title level={4} style={{ margin: 0 }}>
              IP 库与威胁情报
            </Typography.Title>
            <Typography.Text type="secondary">
              统一管理离线/在线 GeoIP 归属地库（零重启热加载与 HA 备节点同步）及威胁情报 IP 黑名单多源订阅对账。
            </Typography.Text>
          </div>
          {(canReadGeo || canReadThreat) && (
            <Button
              icon={<SettingOutlined />}
              onClick={() => setOutboundOpen(true)}
            >
              出站代理与镜像白名单
            </Button>
          )}
        </Space>
      </Card>

      <Card size="small">
        <Tabs
          activeKey={effectiveTab}
          onChange={setActiveTab}
          items={tabItems}
        />
      </Card>

      <OutboundSettingsDrawer
        open={outboundOpen}
        canManage={canManageGeo}
        onClose={() => setOutboundOpen(false)}
      />
    </Space>
  )
}
