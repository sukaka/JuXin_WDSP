import { afterEach, describe, expect, it, vi } from 'vitest'
import { generateIdempotencyKey } from '../idempotency'

const UUID_V4_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

describe('generateIdempotencyKey', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('支持 crypto.randomUUID 时直接返回合法 UUID', () => {
    const key = generateIdempotencyKey()
    expect(key).toMatch(UUID_V4_RE)
  })

  it('非 HTTPS 局域网缺失 crypto.randomUUID 时回退 crypto.getRandomValues 生成合法 UUIDv4', () => {
    const getRandomValues = vi.fn((arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i++) arr[i] = (i * 17 + 5) & 0xff
      return arr
    })
    vi.stubGlobal('crypto', { getRandomValues })

    const key = generateIdempotencyKey()
    expect(getRandomValues).toHaveBeenCalledTimes(1)
    expect(key).toMatch(UUID_V4_RE)
  })

  it('即使 crypto 对象整体缺失也能生成合法 UUIDv4 而不崩溃', () => {
    vi.stubGlobal('crypto', undefined)
    const key = generateIdempotencyKey()
    expect(key).toMatch(UUID_V4_RE)
  })
})
