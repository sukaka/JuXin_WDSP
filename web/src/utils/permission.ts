/** 判断当前用户是否拥有指定权限码 */
export function hasPermission(
  permissions: string[] | null | undefined,
  code: string,
): boolean {
  if (!permissions || !code) return false
  return permissions.includes(code)
}

/** 判断当前用户是否拥有任一指定权限码 */
export function hasAnyPermission(
  permissions: string[] | null | undefined,
  codes: string[],
): boolean {
  return codes.some((code) => hasPermission(permissions, code))
}
