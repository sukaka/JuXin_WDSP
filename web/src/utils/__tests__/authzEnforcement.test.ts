import { describe, expect, it } from 'vitest'
import {
  buildAuthzConfirmTextV1,
  classifyPatchError,
  isConfirmTokenExpired,
  isReadinessBlocking,
} from '../authzEnforcement'

describe('authzEnforcement 纯函数（NG-AZ-04 契约）', () => {
  it('确认文案 v1：占位符替换后与 §1.4 冻结文本逐字一致', () => {
    const text = buildAuthzConfirmTextV1({
      windowDays: 7,
      observeViolationCount: 12,
      distinctPrincipalCount: 5,
      confirmedByName: '张磊',
    })
    expect(text).toBe(
      '我已知悉：本端点切换 PROTECT 后，经显式资格判定成立的违规请求将被实断（403 AUTHZ_VIOLATION_DENIED）；UNKNOWN 永不阻断。近 7 天观测违规 12 次、涉及主体 5 个；我（张磊）作为业务负责人确认承担实断影响。（确认文案 v1）',
    )
  })

  it('classifyPatchError：token 类 / 四要素类 / 其他', () => {
    expect(classifyPatchError('confirm_token 不存在或已消费')).toBe('token')
    expect(classifyPatchError('签署令牌已过期')).toBe('token')
    expect(classifyPatchError('切换 PROTECT 必须同请求提供 enforcement_owner（业务负责人标识）')).toBe('elements')
    expect(classifyPatchError('evidence_source 非法（AUTHORITY_SYNC|MANUAL_CONFIRMED）')).toBe('elements')
    expect(classifyPatchError('on_unknown 非法（首批仅 ALLOW_UNKNOWN——UNKNOWN 永不阻断）')).toBe('elements')
    expect(classifyPatchError('对象模型不存在')).toBe('other')
  })

  it('isConfirmTokenExpired：到期时刻起算过期；缺省不过期', () => {
    const now = Date.parse('2026-10-05T12:00:00Z')
    expect(isConfirmTokenExpired('2026-10-05T11:59:59Z', now)).toBe(true)
    expect(isConfirmTokenExpired('2026-10-05T12:00:00Z', now)).toBe(true)
    expect(isConfirmTokenExpired('2026-10-05T12:00:01Z', now)).toBe(false)
    expect(isConfirmTokenExpired(undefined, now)).toBe(false)
    expect(isConfirmTokenExpired('not-a-date', now)).toBe(false)
  })

  it('isReadinessBlocking：READY/PROTECT_ACTIVE 不阻塞，其余阻塞', () => {
    expect(isReadinessBlocking('READY')).toBe(false)
    expect(isReadinessBlocking('PROTECT_ACTIVE')).toBe(false)
    expect(isReadinessBlocking(undefined)).toBe(false)
    expect(isReadinessBlocking('BLOCKED_BY_NODE')).toBe(true)
    expect(isReadinessBlocking('NOT_PUBLISHABLE')).toBe(true)
  })
})
