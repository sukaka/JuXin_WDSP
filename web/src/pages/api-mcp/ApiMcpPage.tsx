import { Alert, Card, Tabs } from 'antd'
import BindingsTab from './BindingsTab'
import CatalogsTab from './CatalogsTab'
import { MCP_COVERAGE_NOTE } from '../../utils/mcp'

/**
 * MCP 工具目录（NG-MCP G1 §1.14 管理面）：MCP 服务工具目录的显式导入、逐行审核
 * （PENDING_REVIEW|APPROVED|REJECTED 状态机——导入与语义变更恒落待审核，旧审批不继承）
 * 与 per-app 绑定（OBSERVE/PROTECT；绑定驱动识别，空绑定=零行为）。
 */
export default function ApiMcpPage() {
  return (
    <Card title="MCP 工具目录">
      <Alert type="info" showIcon style={{ marginBottom: 16 }} message={MCP_COVERAGE_NOTE} />
      <Tabs
        items={[
          { key: 'catalogs', label: '工具目录', children: <CatalogsTab /> },
          { key: 'bindings', label: '绑定管理', children: <BindingsTab /> },
        ]}
      />
    </Card>
  )
}
