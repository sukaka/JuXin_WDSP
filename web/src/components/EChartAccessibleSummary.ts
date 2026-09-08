type UnknownRecord = Record<string, unknown>

function asRecord(value: unknown): UnknownRecord | undefined {
  return value !== null && typeof value === 'object' ? (value as UnknownRecord) : undefined
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : value === undefined || value === null ? [] : [value]
}

function numericValue(value: unknown): number | undefined {
  if (typeof value === 'number' && Number.isFinite(value)) return value
  const record = asRecord(value)
  if (record) return numericValue(record.value)
  if (Array.isArray(value)) {
    for (let index = value.length - 1; index >= 0; index -= 1) {
      const numeric = numericValue(value[index])
      if (numeric !== undefined) return numeric
    }
  }
  return undefined
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 4 }).format(value)
}

/** 从常见折线、柱状、饼图和关系图配置生成屏幕阅读器可朗读的数据摘要。 */
export function buildAccessibleSummary(option: unknown, ariaLabel: string): string {
  const rawOption = option as UnknownRecord
  const series = asArray(rawOption.series).map(asRecord).filter((item): item is UnknownRecord => Boolean(item))
  if (series.length === 0) return `${ariaLabel}：暂无可供朗读的数据。`

  const pieSeries = series.filter((item) => item.type === 'pie')
  if (pieSeries.length > 0) {
    const items = pieSeries
      .flatMap((item) => asArray(item.data))
      .map(asRecord)
      .filter((item): item is UnknownRecord => Boolean(item))
    const values = items
      .map((item) => ({ name: String(item.name ?? '未命名'), value: numericValue(item.value) }))
      .filter((item): item is { name: string; value: number } => item.value !== undefined)
    if (values.length === 0) return `${ariaLabel}：暂无可供朗读的数据。`
    const total = values.reduce((sum, item) => sum + item.value, 0)
    const details = values
      .sort((left, right) => right.value - left.value)
      .slice(0, 5)
      .map((item) => `${item.name} ${formatNumber(item.value)}`)
      .join('，')
    return `${ariaLabel}：总计 ${formatNumber(total)}；${details}。`
  }

  const graphSeries = series.filter((item) => item.type === 'graph')
  if (graphSeries.length > 0) {
    const nodeCount = graphSeries.reduce((sum, item) => sum + asArray(item.data ?? item.nodes).length, 0)
    const linkCount = graphSeries.reduce((sum, item) => sum + asArray(item.links ?? item.edges).length, 0)
    if (nodeCount === 0 && linkCount === 0) return `${ariaLabel}：暂无可供朗读的数据。`
    return `${ariaLabel}：共 ${nodeCount} 个节点、${linkCount} 条连接。`
  }

  const axis = asArray(rawOption.xAxis).map(asRecord).find((item) => Array.isArray(item?.data))
  const categories = asArray(axis?.data).map(String)
  const range = categories.length > 0 ? `数据范围 ${categories[0]} 至 ${categories[categories.length - 1]}；` : ''
  const descriptions = series.flatMap((item, index) => {
    const values = asArray(item.data).map(numericValue).filter((value): value is number => value !== undefined)
    if (values.length === 0) return []
    const first = values[0]
    const last = values[values.length - 1]
    const trend = last > first ? '总体上升' : last < first ? '总体下降' : '总体持平'
    const name = String(item.name ?? `序列 ${index + 1}`)
    return `${name}共 ${values.length} 个数据点，首值 ${formatNumber(first)}，末值 ${formatNumber(last)}，最低 ${formatNumber(Math.min(...values))}，最高 ${formatNumber(Math.max(...values))}，${trend}`
  })
  if (descriptions.length === 0) return `${ariaLabel}：暂无可供朗读的数据。`
  return `${ariaLabel}：${range}${descriptions.join('；')}。`
}
