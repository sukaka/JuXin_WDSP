/**
 * CSP 安全的 claygl 合成器表达式解析器。
 *
 * 背景：echarts-gl 依赖的 claygl 在 createCompositor.js 中使用
 * `new Function('width', 'height', 'dpr', 'return ' + expr)` 解析诸如
 * `expr(width * dpr / 2)`、`expr([width * dpr / 4, height * dpr / 4])` 的尺寸表达式。
 * 在生产环境严格 CSP（`script-src 'self'`，禁止 `'unsafe-eval'`）下会触发 EvalError，
 * 被 claygl 捕获后抛出 `Error: Invalid expression.` 导致 3D 地球大屏白屏崩溃。
 *
 * 本模块用纯递归下降解析器在零 `eval` / 零 `new Function` 下求值，
 * 保持严格 CSP 安全底线不变。
 */

export type ClayglExprResult = number | number[]
export type ClayglExprFn = (width: number, height: number, dpr?: number) => ClayglExprResult

type Token =
  | { type: 'num'; value: number }
  | { type: 'ident'; name: 'width' | 'height' | 'dpr' }
  | { type: 'op'; op: '+' | '-' | '*' | '/' }
  | { type: 'punct'; ch: '(' | ')' | '[' | ']' | ',' }

const ALLOWED_IDENTS = new Set(['width', 'height', 'dpr'])

function tokenize(input: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  const n = input.length
  while (i < n) {
    const ch = input[i]
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') {
      i++
      continue
    }
    if (ch === '+' || ch === '-' || ch === '*' || ch === '/') {
      tokens.push({ type: 'op', op: ch })
      i++
      continue
    }
    if (ch === '(' || ch === ')' || ch === '[' || ch === ']' || ch === ',') {
      tokens.push({ type: 'punct', ch })
      i++
      continue
    }
    if ((ch >= '0' && ch <= '9') || ch === '.') {
      const start = i
      let hasDot = false
      let hasDigit = false
      while (i < n) {
        const c = input[i]
        if (c >= '0' && c <= '9') {
          hasDigit = true
          i++
        } else if (c === '.' && !hasDot) {
          hasDot = true
          i++
        } else {
          break
        }
      }
      if (!hasDigit) throw new Error('Invalid expression.')
      const value = Number(input.slice(start, i))
      if (!Number.isFinite(value)) throw new Error('Invalid expression.')
      tokens.push({ type: 'num', value })
      continue
    }
    if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch === '_') {
      const start = i
      while (i < n) {
        const c = input[i]
        if (
          (c >= 'a' && c <= 'z') ||
          (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') ||
          c === '_'
        ) {
          i++
        } else {
          break
        }
      }
      const name = input.slice(start, i)
      if (!ALLOWED_IDENTS.has(name)) {
        throw new Error('Invalid expression.')
      }
      tokens.push({ type: 'ident', name: name as 'width' | 'height' | 'dpr' })
      continue
    }
    throw new Error('Invalid expression.')
  }
  return tokens
}

type ScalarEval = (w: number, h: number, dpr: number) => number

class Parser {
  private readonly tokens: Token[]
  private pos = 0

  constructor(tokens: Token[]) {
    this.tokens = tokens
  }

  private peek(): Token | undefined {
    return this.tokens[this.pos]
  }

  private consume(): Token {
    const t = this.tokens[this.pos]
    if (!t) throw new Error('Invalid expression.')
    this.pos++
    return t
  }

  parseRoot(): ClayglExprFn {
    const next = this.peek()
    if (!next) throw new Error('Invalid expression.')
    let fn: ClayglExprFn
    if (next.type === 'punct' && next.ch === '[') {
      fn = this.parseArray()
    } else {
      const scalar = this.parseAddSub()
      fn = (w, h, dpr = 1) => scalar(w, h, dpr)
    }
    if (this.pos !== this.tokens.length) {
      throw new Error('Invalid expression.')
    }
    return fn
  }

  private parseArray(): ClayglExprFn {
    const open = this.consume()
    if (open.type !== 'punct' || open.ch !== '[') throw new Error('Invalid expression.')
    const items: ScalarEval[] = []
    const first = this.peek()
    if (!first) throw new Error('Invalid expression.')
    if (first.type === 'punct' && first.ch === ']') {
      this.consume()
      return () => []
    }
    items.push(this.parseAddSub())
    while (true) {
      const tok = this.peek()
      if (!tok || tok.type !== 'punct') throw new Error('Invalid expression.')
      if (tok.ch === ',') {
        this.consume()
        items.push(this.parseAddSub())
      } else if (tok.ch === ']') {
        this.consume()
        break
      } else {
        throw new Error('Invalid expression.')
      }
    }
    return (w, h, dpr = 1) => items.map((item) => item(w, h, dpr))
  }

  private parseAddSub(): ScalarEval {
    let left = this.parseMulDiv()
    while (true) {
      const tok = this.peek()
      if (tok && tok.type === 'op' && (tok.op === '+' || tok.op === '-')) {
        this.consume()
        const right = this.parseMulDiv()
        const lhs = left
        left = tok.op === '+'
          ? (w, h, dpr) => lhs(w, h, dpr) + right(w, h, dpr)
          : (w, h, dpr) => lhs(w, h, dpr) - right(w, h, dpr)
      } else {
        break
      }
    }
    return left
  }

  private parseMulDiv(): ScalarEval {
    let left = this.parseUnary()
    while (true) {
      const tok = this.peek()
      if (tok && tok.type === 'op' && (tok.op === '*' || tok.op === '/')) {
        this.consume()
        const right = this.parseUnary()
        const lhs = left
        left = tok.op === '*'
          ? (w, h, dpr) => lhs(w, h, dpr) * right(w, h, dpr)
          : (w, h, dpr) => lhs(w, h, dpr) / right(w, h, dpr)
      } else {
        break
      }
    }
    return left
  }

  private parseUnary(): ScalarEval {
    const tok = this.peek()
    if (tok && tok.type === 'op' && (tok.op === '+' || tok.op === '-')) {
      this.consume()
      const inner = this.parseUnary()
      return tok.op === '-' ? (w, h, dpr) => -inner(w, h, dpr) : inner
    }
    return this.parsePrimary()
  }

  private parsePrimary(): ScalarEval {
    const tok = this.consume()
    if (tok.type === 'num') {
      const v = tok.value
      return () => v
    }
    if (tok.type === 'ident') {
      if (tok.name === 'width') return (w) => w
      if (tok.name === 'height') return (_w, h) => h
      return (_w, _h, dpr) => dpr
    }
    if (tok.type === 'punct' && tok.ch === '(') {
      const inner = this.parseAddSub()
      const close = this.consume()
      if (close.type !== 'punct' || close.ch !== ')') {
        throw new Error('Invalid expression.')
      }
      return inner
    }
    throw new Error('Invalid expression.')
  }
}

/**
 * 编译 claygl `expr(...)` 字符串为纯 JS 求值函数；非 `expr(...)` 输入返回 undefined。
 * 非法表达式抛出与 claygl 原实现一致的 `Error('Invalid expression.')`。
 */
export function compileClayglExpr(input: string): ClayglExprFn | undefined {
  const match = /^expr\((.*)\)$/.exec(input)
  if (!match) return undefined
  try {
    const tokens = tokenize(match[1])
    const fn = new Parser(tokens).parseRoot()
    // 预校验与 claygl 语义保持一致
    fn(1, 1, 1)
    return fn
  } catch {
    throw new Error('Invalid expression.')
  }
}
