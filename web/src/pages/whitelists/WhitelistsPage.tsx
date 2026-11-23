import { Alert, Card, Tabs } from 'antd'
import { Link, useSearchParams } from 'react-router-dom'
import { IPAccessRulePanel } from '../access-rules/AccessRulesPage'
import URLWhitelistsPanel from './URLWhitelistsPanel'

export default function WhitelistsPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') === 'url' ? 'url' : 'ip'

  return (
    <Card title="白名单管理">
      <Alert
        type="info"
        showIcon
        style={{ marginBottom: 16 }}
        message="白名单放行范围说明"
        description={
          <>
            命中 <strong>IP 白名单</strong> 或 <strong>URL 白名单</strong>{' '}
            的请求将跳过 IP 黑名单、L7 访问控制、自动临时封禁、身份风险策略与 CC 限速；但仍坚守安全底线，
            <strong>不会绕过</strong>人工临时封禁、Bot 挑战、API 动态防护与 WAF（Coraza/CRS）攻击检测。如需针对特定误报规则放行，请前往
            <Link to="/exceptions" style={{ marginLeft: 4 }}>
              例外策略
            </Link>
            配置精确例外。
          </>
        }
      />
      <Tabs
        activeKey={activeTab}
        onChange={(key) => setSearchParams(key === 'url' ? { tab: 'url' } : { tab: 'ip' }, { replace: true })}
        items={[
          {
            key: 'ip',
            label: 'IP 白名单',
            children: <IPAccessRulePanel fixedRuleType="ALLOW" embedded />,
          },
          {
            key: 'url',
            label: 'URL 白名单',
            children: <URLWhitelistsPanel />,
          },
        ]}
      />
    </Card>
  )
}
