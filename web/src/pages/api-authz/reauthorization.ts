export interface ISODateValue {
  toISOString: () => string
}

export function validateReauthorizationWindow(validFrom?: ISODateValue, validUntil?: ISODateValue) {
  if (!validUntil || !validFrom) return undefined
  try {
    return validUntil.toISOString() <= validFrom.toISOString()
      ? '失效时间必须晚于生效时间'
      : undefined
  } catch {
    return '请选择有效时间'
  }
}
