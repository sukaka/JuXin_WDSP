import { describe, expect, it } from 'vitest'
import { compileClayglExpr } from '../clayglExpr'

const ECHARTS_GL_EXPRS: Array<[string, number | number[]]> = [
  ['expr(width)', 1920],
  ['expr(height)', 1080],
  ['expr(width * 1.0)', 1920],
  ['expr(height * 1.0)', 1080],
  ['expr(width * 1.0 / 2)', 960],
  ['expr(height * 1.0 / 2)', 540],
  ['expr(width * 1.0 / 4)', 480],
  ['expr(height * 1.0 / 4)', 270],
  ['expr(width * 1.0 / 8)', 240],
  ['expr(height * 1.0 / 8)', 135],
  ['expr(width * 1.0 / 16)', 120],
  ['expr(height * 1.0 / 16)', 67.5],
  ['expr(width * 1.0 / 32)', 60],
  ['expr(height * 1.0 / 32)', 33.75],
  ['expr(width * dpr / 2)', 1920],
  ['expr(height * dpr / 2)', 1080],
  ['expr(width * dpr / 4)', 960],
  ['expr(height * dpr / 4)', 540],
  ['expr(width * dpr / 8)', 480],
  ['expr(height * dpr / 8)', 270],
  ['expr(width * dpr / 16)', 240],
  ['expr(height * dpr / 16)', 135],
  ['expr(width * dpr / 32)', 120],
  ['expr(height * dpr / 32)', 67.5],
  ['expr( [width * 1.0, height * 1.0] )', [1920, 1080]],
  ['expr( [width * 1.0 / 2, height * 1.0 / 2] )', [960, 540]],
  ['expr( [width * 1.0 / 2, height / 2] )', [960, 540]],
  ['expr([width * 1.0 / 2, height / 2])', [960, 540]],
  ['expr( [width * 1.0 / 4, height * 1.0 / 4] )', [480, 270]],
  ['expr( [width * 1.0 / 4, height / 4] )', [480, 270]],
  ['expr( [width * 1.0 / 8, height * 1.0 / 8] )', [240, 135]],
  ['expr( [width * 1.0 / 8, height / 8] )', [240, 135]],
  ['expr( [width * 1.0 / 16, height * 1.0 / 16] )', [120, 67.5]],
  ['expr( [width * 1.0 / 16, height / 16] )', [120, 67.5]],
  ['expr( [width * 1.0 / 32, height / 32] )', [60, 33.75]],
  ['expr( [width * dpr, height * dpr] )', [3840, 2160]],
  ['expr( [width * dpr / 2, height * dpr / 2] )', [1920, 1080]],
  ['expr( [width * dpr / 4, height * dpr / 4] )', [960, 540]],
  ['expr([width * dpr / 4, height * dpr / 4])', [960, 540]],
  ['expr( [width * dpr / 8, height * dpr / 8] )', [480, 270]],
  ['expr( [width * dpr / 16, height * dpr / 16] )', [240, 135]],
  ['expr( [width * dpr / 32, height * dpr / 32] )', [120, 67.5]],
]

describe('compileClayglExpr (CSP-safe replacement for claygl new Function)', () => {
  it('准确求值 echarts-gl / claygl 全部 42 个内置合成器表达式', () => {
    for (const [expr, expected] of ECHARTS_GL_EXPRS) {
      const fn = compileClayglExpr(expr)
      expect(fn, expr).toBeDefined()
      expect(fn!(1920, 1080, 2), expr).toEqual(expected)
    }
  })

  it('支持括号、加减乘除优先级与一元负号', () => {
    const fn = compileClayglExpr('expr((width + height) / 2 - -10)')
    expect(fn).toBeDefined()
    expect(fn!(100, 200, 1)).toBe(160)
  })

  it('非 expr(...) 字符串返回 undefined', () => {
    expect(compileClayglExpr('100')).toBeUndefined()
    expect(compileClayglExpr('#texture')).toBeUndefined()
  })

  it('拒绝非法表达式与任意 JS 代码注入并抛出 Invalid expression.', () => {
    expect(() => compileClayglExpr('expr(window.alert(1))')).toThrow('Invalid expression.')
    expect(() => compileClayglExpr('expr(constructor)')).toThrow('Invalid expression.')
    expect(() => compileClayglExpr('expr(width + )')).toThrow('Invalid expression.')
    expect(() => compileClayglExpr('expr()')).toThrow('Invalid expression.')
    expect(() => compileClayglExpr('expr([width, height)')).toThrow('Invalid expression.')
  })
})
