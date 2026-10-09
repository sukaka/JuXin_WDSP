import { describe, expect, it } from 'vitest'
import { shortFingerprint, validateBindingPath, validatePemText } from '../machineIdentity'

describe('machineIdentity 纯函数（NG-ID G1）', () => {
  it('validatePemText：恰一个 PUBLIC KEY 块', () => {
    expect(validatePemText('')).toBe('公钥 PEM 必填')
    expect(validatePemText('not a pem')).toContain('PEM 形态非法')
    expect(
      validatePemText('-----BEGIN PUBLIC KEY-----\nMFkwEw==\n-----END PUBLIC KEY-----'),
    ).toBeUndefined()
    expect(
      validatePemText('-----BEGIN RSA PUBLIC KEY-----\nMIIBCg==\n-----END RSA PUBLIC KEY-----'),
    ).toBeUndefined()
    // 两个块拒收（恰一个公钥块）
    expect(
      validatePemText(
        '-----BEGIN PUBLIC KEY-----\nA==\n-----END PUBLIC KEY-----\n-----BEGIN PUBLIC KEY-----\nB==\n-----END PUBLIC KEY-----',
      ),
    ).toContain('恰一个 PUBLIC KEY 块')
    expect(validatePemText(`${'x'.repeat(9000)}`)).toBe('PEM 不超过 8192 字符')
  })

  it('validateBindingPath：二选一 + / 开头 + 不含 query/fragment', () => {
    expect(validateBindingPath('', '/mcp')).toBe('请选择路径形态（精确/前缀二选一）')
    expect(validateBindingPath('path_exact', 'mcp')).toBe('路径须为 / 开头')
    expect(validateBindingPath('path_exact', '/mcp?x=1')).toBe('路径不含 query/fragment')
    expect(validateBindingPath('path_prefix', '/mcp#f')).toBe('路径不含 query/fragment')
    expect(validateBindingPath('path_exact', '/mcp')).toBeUndefined()
    expect(validateBindingPath('path_prefix', '/api/v1/')).toBeUndefined()
    expect(validateBindingPath('path_exact', `/${'a'.repeat(513)}`)).toBe('路径不超过 512 字符')
  })

  it('shortFingerprint：16 hex 原文展示，长值截断', () => {
    expect(shortFingerprint('a1b2c3d4e5f60718')).toBe('a1b2c3d4e5f60718')
    expect(shortFingerprint('a1b2c3d4e5f607180000ffff')).toBe('a1b2c3d4e5f60718…')
    expect(shortFingerprint('')).toBe('—')
    expect(shortFingerprint(null)).toBe('—')
  })
})
