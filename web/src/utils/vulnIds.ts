/**
 * CNNVD 兼容性 P1：漏洞编号格式校验（与服务端口径一致）。
 * CNNVD：CNNVD-YYYYMM-NNN+；CVE：CVE-YYYY-NNNN+。
 */
export const CNNVD_ID_PATTERN = /^CNNVD-\d{6}-\d{3,}$/
export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/

/** 列表多值校验：返回非法值列表（空数组 = 全部合法） */
export function findInvalidVulnIds(values: string[] | undefined | null, pattern: RegExp): string[] {
  return (values ?? []).filter((v) => !pattern.test(v.trim()))
}
