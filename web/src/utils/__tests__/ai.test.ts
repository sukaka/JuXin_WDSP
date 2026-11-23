import { describe, expect, it } from 'vitest'
import { AI_DRAFT_TYPE_META, AI_STEP_META } from '../ai'

describe('AI_STEP_META', () => {
  it('用中文警告语义展示模型降级步骤', () => {
    expect(AI_STEP_META.degraded).toEqual({ color: 'orange', label: '模型降级' })
  })
})

describe('AI_DRAFT_TYPE_META', () => {
  it('包含智能降噪（NOISE_REDUCTION）草稿类型映射', () => {
    expect(AI_DRAFT_TYPE_META.NOISE_REDUCTION).toEqual({ color: 'cyan', label: '智能降噪' })
  })
})
