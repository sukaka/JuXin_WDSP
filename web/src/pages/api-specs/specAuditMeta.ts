import { SPEC_FORMAT_LABELS, formatLocation } from '../../utils/i18nLabels'

export const SPEC_AUDIT_RULE_META: Record<
  string,
  { color: string; label: string }
> = {
  PATH_PARAMETER_MISSING: { color: 'red', label: '路径参数缺失' },
  PATH_PARAMETER_NOT_REQUIRED: { color: 'orange', label: '路径参数未标记必填' },
  PATH_PARAMETER_UNDECLARED: { color: 'red', label: '路径参数未声明' },
  SENSITIVE_QUERY_PARAMETER: { color: 'orange', label: '敏感查询参数' },
  SUCCESS_RESPONSE_MISSING: { color: 'red', label: '成功响应未声明' },
  ERROR_RESPONSE_MISSING: { color: 'orange', label: '错误响应未声明' },
  SECURITY_SCHEME_UNDEFINED: { color: 'red', label: '认证方案未定义' },
  API_KEY_IN_QUERY: { color: 'red', label: '查询参数传递 API Key' },
}

export const SPEC_AUDIT_SEVERITY_META: Record<
  string,
  { color: string; label: string }
> = {
  HIGH: { color: 'red', label: '高' },
  MEDIUM: { color: 'orange', label: '中' },
}

export function formatSpecAuditFormat(format: string): string {
  if (!format) return ''
  const trimmed = format.trim()
  return (
    SPEC_FORMAT_LABELS[trimmed] ??
    SPEC_FORMAT_LABELS[trimmed.toLowerCase()] ??
    SPEC_FORMAT_LABELS[trimmed.toUpperCase()] ??
    format
  )
}

export function formatSpecAuditRule(ruleId: string): string {
  if (!ruleId) return ''
  const trimmed = ruleId.trim()
  return (
    SPEC_AUDIT_RULE_META[trimmed]?.label ??
    SPEC_AUDIT_RULE_META[trimmed.toUpperCase()]?.label ??
    ruleId
  )
}

export function formatSpecAuditSeverity(severity: string): string {
  if (!severity) return ''
  const trimmed = severity.trim()
  return (
    SPEC_AUDIT_SEVERITY_META[trimmed]?.label ??
    SPEC_AUDIT_SEVERITY_META[trimmed.toUpperCase()]?.label ??
    severity
  )
}

export function formatSpecAuditParamIn(paramIn: string): string {
  if (!paramIn) return ''
  if (paramIn.trim().toUpperCase() === 'SECURITY') return '认证方案'
  return formatLocation(paramIn)
}
