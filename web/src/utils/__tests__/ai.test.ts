import { describe, expect, it } from 'vitest'
import { AI_STEP_META } from '../ai'

describe('AI_STEP_META', () => {
  it('用中文警告语义展示模型降级步骤', () => {
    expect(AI_STEP_META.degraded).toEqual({ color: 'orange', label: '模型降级' })
  })
})
