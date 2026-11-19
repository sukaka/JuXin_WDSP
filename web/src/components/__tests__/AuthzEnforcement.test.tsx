import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { AuthzEnforcementBlock, ReadinessBadge } from '../AuthzEnforcement'
import { extractAuthzEnforcement } from '../../utils/authzEnforcement'

describe('ReadinessBadge（§1.2 六态 + PROTECT_ACTIVE）', () => {
  it.each([
    ['READY', '可实断'],
    ['PROTECT_ACTIVE', '实断中'],
    ['NOT_PUBLISHABLE', '资格不齐'],
    ['BLOCKED_BY_NO_RELATION', '无有效属主关系'],
    ['BLOCKED_BY_CONFLICT', '存在未处理冲突'],
    ['BLOCKED_BY_STALE', '快照/租约过期'],
    ['BLOCKED_BY_NODE', '节点未就绪'],
  ])('渲染 %s 徽章中文标签', (readiness, label) => {
    render(<ReadinessBadge readiness={readiness} reasons={[]} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('tooltip 固定注明「证据不足永不阻断」并列出阻塞因子', async () => {
    render(<ReadinessBadge readiness="BLOCKED_BY_NODE" reasons={['存在 ACK 非 FRESH 节点（快照未应用）', '节点能力自报不足 az/3']} />)
    fireEvent.mouseEnter(screen.getByText('节点未就绪'))
    expect(await screen.findByText(/证据不足永不阻断/)).toBeInTheDocument()
    expect(screen.getByText(/就绪度为切换预评估而非决策承诺/)).toBeInTheDocument()
    expect(screen.getByText('存在 ACK 非 FRESH 节点（快照未应用）')).toBeInTheDocument()
    expect(screen.getByText('节点能力自报不足 az/3')).toBeInTheDocument()
  })

  it('未传 readiness 时占位「-」', () => {
    render(<ReadinessBadge readiness={undefined} />)
    expect(screen.getByText('-')).toBeInTheDocument()
  })
})

describe('AuthzEnforcementBlock（D7 决策详情证据区块）', () => {
  const bolaEvidence = {
    decision: 'VERIFIED_VIOLATION',
    reason_code: 'AUTHZ-BOLA-001',
    enforced: true,
    endpoint_key: 'GET /api/v1/tenants/{id}/projects/p002/items',
    model_version: 'om-20261001',
    policy_version: 'ap-20261002',
    revocation_watermark: { manual_seq: 7, sources: { 'src-a': 12 } },
    principal_source: 'JWT',
    object_ref: 'objref:0a1b2c',
    eligibility: {
      trusted_identity: true,
      model_applicable: true,
      relation_valid: true,
      no_conflict: true,
      tenant_consistent: true,
      evidence_fresh: true,
      other_owner: true,
      owner_exclusive: false,
    },
    lease_seconds: 300,
    applied_at_age_seconds: 42,
    enforcement_owner: 'zhang.lei@example.com',
    evidence_source: 'AUTHORITY_SYNC',
    recorded_at: '2026-10-05T02:00:00Z',
  }

  it('eligibility 逐项对错图标 + 版本/水位/租约读数 + 中文化证据字段', () => {
    render(<AuthzEnforcementBlock evidence={bolaEvidence} />)
    expect(screen.getByText('实断证据')).toBeInTheDocument()
    expect(screen.getByText('已实断')).toBeInTheDocument()
    expect(screen.getByText('实断违规')).toBeInTheDocument()
    expect(screen.getByText('对象级越权（他人属主）')).toBeInTheDocument()
    expect(screen.getByText('权威同步')).toBeInTheDocument()
    expect(screen.getByText('JWT 可信验证')).toBeInTheDocument()
    expect(screen.getByText('阻断资格逐因子：')).toBeInTheDocument()
    expect(screen.getByText('可信身份')).toBeInTheDocument()
    expect(screen.getByText('排他所有权')).toBeInTheDocument()
    expect(screen.getByText('om-20261001')).toBeInTheDocument()
    expect(screen.getByText(/手工序号=7/)).toBeInTheDocument()
    expect(screen.getByText('zhang.lei@example.com')).toBeInTheDocument()
    // eligibility 八键全部渲染（含 false 的排他所有权——不丢因子）
    expect(screen.getAllByText(/^(可信身份|模型适用|关系有效|无冲突|租户一致|证据新鲜|他人属主|排他所有权)$/)).toHaveLength(8)
  })

  it('BFLA 形态：实评键集如实呈现 + object_ref 空', () => {
    render(
      <AuthzEnforcementBlock
        evidence={{
          decision: 'VERIFIED_VIOLATION',
          reason_code: 'AUTHZ-BFLA-001',
          enforced: false,
          object_ref: '',
          eligibility: { trusted_identity: true, baselines_applicable: true, evidence_fresh: true, role_violation: true },
        }}
      />,
    )
    expect(screen.getByText('基线适用')).toBeInTheDocument()
    expect(screen.getByText('角色违例')).toBeInTheDocument()
    expect(screen.queryByText('排他所有权')).not.toBeInTheDocument()
    expect(screen.getByText('拟实断（当前观察模式不实断）')).toBeInTheDocument()
    expect(screen.getByText('功能级越权（角色基线违例）')).toBeInTheDocument()
  })

  it('extractAuthzEnforcement：仅识别 authz_enforcement 子对象', () => {
    expect(extractAuthzEnforcement({ authz_enforcement: { decision: 'VERIFIED_VIOLATION' } })).toEqual({ decision: 'VERIFIED_VIOLATION' })
    expect(extractAuthzEnforcement({})).toBeNull()
    expect(extractAuthzEnforcement({ authz_enforcement: 'bogus' })).toBeNull()
    expect(extractAuthzEnforcement(null)).toBeNull()
    expect(extractAuthzEnforcement(undefined)).toBeNull()
  })
})
