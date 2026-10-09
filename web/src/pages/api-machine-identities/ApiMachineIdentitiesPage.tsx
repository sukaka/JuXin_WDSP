import { Alert, Card, Collapse, Tabs, Typography } from 'antd'
import IdentitiesTab from './IdentitiesTab'
import MachineIdentityBindingsTab from './MachineIdentityBindingsTab'
import { MACHINE_IDENTITY_COVERAGE_NOTE, MACHINE_IDENTITY_ONBOARDING_NOTE } from '../../utils/machineIdentity'

/**
 * 机器身份（NG-ID G1 §1.12 管理面）：HTTP Message Signatures（RFC 9421）可信身份登记
 * （公钥唯一来源=管理面静态离线导入）、键状态机（ACTIVE/RETIRED/REVOKED+重叠窗口+撤销水位单调）
 * 与 per-app 绑定（path_exact|path_prefix 二选一、OBSERVE/PROTECT、proof_required 未签名即 401）。
 */
export default function ApiMachineIdentitiesPage() {
  return (
    <Card title="机器身份">
      <Alert type="info" showIcon style={{ marginBottom: 12 }} message={MACHINE_IDENTITY_COVERAGE_NOTE} />
      <Collapse
        style={{ marginBottom: 16 }}
        items={[
          {
            key: 'onboarding',
            label: '接入契约（客户端签名约定）',
            children: <Typography.Paragraph style={{ marginBottom: 0 }}>{MACHINE_IDENTITY_ONBOARDING_NOTE}</Typography.Paragraph>,
          },
        ]}
      />
      <Tabs
        items={[
          { key: 'identities', label: '身份登记', children: <IdentitiesTab /> },
          { key: 'bindings', label: '绑定管理', children: <MachineIdentityBindingsTab /> },
        ]}
      />
    </Card>
  )
}
