import { describe, expect, it } from 'vitest'
import {
  ACCESS_RULE_TYPE_META,
  AC_EVENT_TYPE_META,
  CUSTOM_HEADER_NAME_PATTERN,
  RATE_LIMIT_ACTION_META,
  TEMP_BLOCK_STATUS_META,
  isCIDRAddress,
  isValidIPLiteral,
  isValidIPv4,
  isValidIPv6,
  validateIPOrCIDR,
} from '../stage5'

describe('isValidIPv4（镜像 Go netip）', () => {
  it('接受合法 IPv4', () => {
    expect(isValidIPv4('192.168.1.1')).toBe(true)
    expect(isValidIPv4('0.0.0.0')).toBe(true)
    expect(isValidIPv4('255.255.255.255')).toBe(true)
  })

  it('拒绝越界/前导零/非四段', () => {
    expect(isValidIPv4('256.1.1.1')).toBe(false)
    expect(isValidIPv4('01.2.3.4')).toBe(false)
    expect(isValidIPv4('1.2.3')).toBe(false)
    expect(isValidIPv4('1.2.3.4.5')).toBe(false)
    expect(isValidIPv4('a.b.c.d')).toBe(false)
  })
})

describe('isValidIPv6（镜像 Go netip）', () => {
  it('接受完整/压缩/内嵌 IPv4 形态', () => {
    expect(isValidIPv6('2001:db8:85a3:0:0:8a2e:370:7334')).toBe(true)
    expect(isValidIPv6('2001:db8::1')).toBe(true)
    expect(isValidIPv6('::')).toBe(true)
    expect(isValidIPv6('::1')).toBe(true)
    expect(isValidIPv6('::ffff:1.2.3.4')).toBe(true)
  })

  it('拒绝多处压缩/组数错误/带区域地址', () => {
    expect(isValidIPv6('1::2::3')).toBe(false)
    expect(isValidIPv6('1:2:3:4:5:6:7:8:9')).toBe(false)
    expect(isValidIPv6('1:2:3:4:5:6:7')).toBe(false)
    expect(isValidIPv6('fe80::1%eth0')).toBe(false)
    expect(isValidIPv6('2001:db8::g1')).toBe(false)
  })
})

describe('validateIPOrCIDR（镜像后端 NormalizeAddress）', () => {
  it('接受单 IP 与 CIDR', () => {
    expect(validateIPOrCIDR('10.0.0.1')).toBeNull()
    expect(validateIPOrCIDR('10.0.0.0/8')).toBeNull()
    expect(validateIPOrCIDR('192.168.0.0/24')).toBeNull()
    expect(validateIPOrCIDR('2001:db8::/32')).toBeNull()
    expect(validateIPOrCIDR('2001:db8::1')).toBeNull()
  })

  it('拒绝域名/协议/端口/通配符', () => {
    expect(validateIPOrCIDR('example.com')).not.toBeNull()
    expect(validateIPOrCIDR('http://10.0.0.1')).not.toBeNull()
    expect(validateIPOrCIDR('10.0.0.1:8080')).not.toBeNull()
    expect(validateIPOrCIDR('10.0.0.*')).not.toBeNull()
  })

  it('拒绝非法前缀长度', () => {
    expect(validateIPOrCIDR('10.0.0.0/33')).not.toBeNull()
    expect(validateIPOrCIDR('10.0.0.0/abc')).not.toBeNull()
    expect(validateIPOrCIDR('2001:db8::/129')).not.toBeNull()
    expect(validateIPOrCIDR('/24')).not.toBeNull()
  })

  it('拒绝空值与超长输入', () => {
    expect(validateIPOrCIDR('')).not.toBeNull()
    expect(validateIPOrCIDR('   ')).not.toBeNull()
    expect(validateIPOrCIDR('1'.repeat(65))).not.toBeNull()
  })
})

describe('isValidIPLiteral / isCIDRAddress', () => {
  it('isValidIPLiteral 只接受单 IP', () => {
    expect(isValidIPLiteral('8.8.8.8')).toBe(true)
    expect(isValidIPLiteral('2001:db8::1')).toBe(true)
    expect(isValidIPLiteral('8.8.8.0/24')).toBe(false)
    expect(isValidIPLiteral('dns.google')).toBe(false)
  })

  it('isCIDRAddress 区分网段与单 IP', () => {
    expect(isCIDRAddress('10.0.0.0/8')).toBe(true)
    expect(isCIDRAddress('10.0.0.1')).toBe(false)
    expect(isCIDRAddress('bad-input/8')).toBe(false)
  })
})

describe('展示元数据完整性', () => {
  it('规则类型 ALLOW 绿 / DENY 红', () => {
    expect(ACCESS_RULE_TYPE_META.ALLOW.color).toBe('green')
    expect(ACCESS_RULE_TYPE_META.DENY.color).toBe('red')
  })

  it('访问控制事件类型覆盖后端全部 11 种', () => {
    expect(Object.keys(AC_EVENT_TYPE_META)).toHaveLength(11)
    expect(AC_EVENT_TYPE_META.CC_THRESHOLD_EXCEEDED.label).toBe('频率超阈值')
    expect(AC_EVENT_TYPE_META.IP_ALLOW_MATCH.label).toBe('命中白名单')
  })

  it('CC 动作与临时封禁状态元数据', () => {
    expect(RATE_LIMIT_ACTION_META.TEMP_BLOCK.label).toBe('临时封禁')
    expect(TEMP_BLOCK_STATUS_META.MANUALLY_RELEASED.label).toBe('已人工解封')
  })

  it('自定义代理头名规则（与后端 customHeaderRe 一致）', () => {
    expect(CUSTOM_HEADER_NAME_PATTERN.test('X-Proxy-IP')).toBe(true)
    expect(CUSTOM_HEADER_NAME_PATTERN.test('X_Custom.Real-1')).toBe(true)
    expect(CUSTOM_HEADER_NAME_PATTERN.test('X Custom')).toBe(false)
    expect(CUSTOM_HEADER_NAME_PATTERN.test('头名')).toBe(false)
  })
})
