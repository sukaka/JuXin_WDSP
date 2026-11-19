import { Descriptions, Space, Tag, Tooltip, Typography } from 'antd'
import { CheckCircleOutlined, CloseCircleOutlined, QuestionCircleOutlined } from '@ant-design/icons'
import {
  ENFORCEMENT_READINESS_META,
  EVIDENCE_SOURCE_META,
  UNKNOWN_NEVER_BLOCKS_NOTE,
} from '../utils/authzEnforcement'
import type { AuthzEnforcementEvidence } from '../utils/authzEnforcement'
import { formatDateTime } from '../utils/format'
import {
  AUTHZ_DECISION_META,
  PRINCIPAL_SOURCE_LABELS,
  formatAuthzReasonCode,
} from '../utils/i18nLabels'

/** readiness 徽章（NG-AZ-04 §1.2）：服务端派生，前端只渲染；tooltip 列全部阻塞因子并固定注明「证据不足永不阻断」 */
export function ReadinessBadge({ readiness, reasons }: { readiness?: string; reasons?: string[] }) {
  if (!readiness) return <Tag>-</Tag>
  const meta = ENFORCEMENT_READINESS_META[readiness]
  const tag = <Tag color={meta?.color}>{meta?.label ?? readiness}</Tag>
  const list = (reasons ?? []).filter(Boolean)
  return (
    <Tooltip
      title={
        <div>
          {list.length > 0 ? (
            <ul style={{ margin: 0, paddingInlineStart: 16 }}>
              {list.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          ) : (
            <div>全部资格因子成立</div>
          )}
          <div style={{ marginTop: 4 }}>{UNKNOWN_NEVER_BLOCKS_NOTE}（就绪度为切换预评估而非决策承诺）</div>
        </div>
      }
    >
      <Space size={2}>
        {tag}
        <QuestionCircleOutlined style={{ color: 'rgba(0,0,0,0.45)' }} />
      </Space>
    </Tooltip>
  )
}

/** eligibility 因子键中文名（未知键原样展示——BFLA 实评键集如实呈现） */
const ELIGIBILITY_KEY_LABELS: Record<string, string> = {
  trusted_identity: '可信身份',
  model_applicable: '模型适用',
  relation_valid: '关系有效',
  no_conflict: '无冲突',
  tenant_consistent: '租户一致',
  evidence_fresh: '证据新鲜',
  other_owner: '他人属主',
  owner_exclusive: '排他所有权',
  baselines_applicable: '基线适用',
  role_violation: '角色违例',
}

function watermarkText(wm?: { manual_seq?: number; sources?: Record<string, number> }): string {
  if (!wm) return '—'
  const sources = Object.entries(wm.sources ?? {})
    .map(([k, v]) => `${k.slice(0, 8)}…:${v}`)
    .join(' ')
  return `手工序号=${wm.manual_seq ?? 0}${sources ? ` · ${sources}` : ''}`
}

/**
 * D7 决策详情 authz_enforcement 区块：eligibility 逐项对错图标、版本/水位/租约读数、
 * 四要素回执；OBSERVE 形态 proposed_decision 展示「拟实断（当前观察模式不实断）」。
 */
export function AuthzEnforcementBlock({ evidence }: { evidence: AuthzEnforcementEvidence }) {
  const eligibility = Object.entries(evidence.eligibility ?? {})
  const decisionMeta = evidence.decision ? AUTHZ_DECISION_META[evidence.decision] : undefined
  const evidenceSourceLabel = evidence.evidence_source
    ? (EVIDENCE_SOURCE_META[evidence.evidence_source]?.label ?? evidence.evidence_source)
    : '—'
  const principalSourceLabel = evidence.principal_source
    ? (PRINCIPAL_SOURCE_LABELS[evidence.principal_source] ?? evidence.principal_source)
    : '—'
  return (
    <Space direction="vertical" size={8} style={{ width: '100%' }}>
      <Space size={8} wrap align="center">
        <Typography.Text strong>实断证据</Typography.Text>
        {evidence.enforced ? <Tag color="red">已实断</Tag> : null}
        {evidence.proposed_decision === 'VERIFIED_VIOLATION' || (evidence.decision === 'VERIFIED_VIOLATION' && evidence.enforced === false) ? (
          <Tag color="gold">拟实断（当前观察模式不实断）</Tag>
        ) : null}
      </Space>
      {eligibility.length > 0 ? (
        <div>
          <Typography.Text type="secondary">阻断资格逐因子：</Typography.Text>
          <Space size={[8, 4]} wrap style={{ marginTop: 4 }}>
            {eligibility.map(([key, ok]) => (
              <Tag key={key} icon={ok ? <CheckCircleOutlined /> : <CloseCircleOutlined />} color={ok ? 'success' : 'error'}>
                {ELIGIBILITY_KEY_LABELS[key] ?? key}
              </Tag>
            ))}
          </Space>
        </div>
      ) : null}
      <Descriptions size="small" column={2} bordered>
        <Descriptions.Item label="决策">
          {decisionMeta ? (
            <Tag color={decisionMeta.color}>{decisionMeta.label}</Tag>
          ) : (
            evidence.decision || '—'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="原因码">
          {evidence.reason_code ? formatAuthzReasonCode(evidence.reason_code) : '—'}
        </Descriptions.Item>
        <Descriptions.Item label="模型版本">{evidence.model_version || '—'}</Descriptions.Item>
        <Descriptions.Item label="策略版本">{evidence.policy_version || '—'}</Descriptions.Item>
        <Descriptions.Item label="撤销水位" span={2}>
          <Typography.Text code>{watermarkText(evidence.revocation_watermark)}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="租约">{evidence.lease_seconds ?? '—'} 秒</Descriptions.Item>
        <Descriptions.Item label="快照应用龄期">{evidence.applied_at_age_seconds ?? '—'} 秒</Descriptions.Item>
        <Descriptions.Item label="业务负责人">{evidence.enforcement_owner || '—'}</Descriptions.Item>
        <Descriptions.Item label="证据来源">{evidenceSourceLabel}</Descriptions.Item>
        <Descriptions.Item label="接口" span={2}>
          <Typography.Text code>{evidence.endpoint_key || '—'}</Typography.Text>
        </Descriptions.Item>
        <Descriptions.Item label="主体来源">{principalSourceLabel}</Descriptions.Item>
        <Descriptions.Item label="对象引用">
          {evidence.object_ref ? <Typography.Text code>{evidence.object_ref}</Typography.Text> : '—'}
        </Descriptions.Item>
        <Descriptions.Item label="记录时间" span={2}>
          {evidence.recorded_at ? formatDateTime(evidence.recorded_at) : '—'}
        </Descriptions.Item>
      </Descriptions>
    </Space>
  )
}
