import { Tag, Tooltip } from 'antd'
import { Link } from 'react-router-dom'

/**
 * CNNVD/CVE 编号标签组（CNNVD 兼容性 P1）：CNNVD 红 Tag / CVE 蓝 Tag，悬停 Tooltip 显示完整值。
 * collapseAfter 之后的折叠为 +N（悬停展示全部）；缺省不折叠。
 * linkCnnvd=true 时 CNNVD 标签渲染为「漏洞档案」页跳转链接（?focus=<cnnvd_id>）。
 */
export default function VulnIdTags({
  cnnvdIds,
  cveIds,
  collapseAfter,
  linkCnnvd = false,
}: {
  cnnvdIds?: string[] | null
  cveIds?: string[] | null
  collapseAfter?: number
  linkCnnvd?: boolean
}) {
  const items = [
    ...(cnnvdIds ?? []).map((id) => ({ id, color: 'red', cnnvd: true })),
    ...(cveIds ?? []).map((id) => ({ id, color: 'blue', cnnvd: false })),
  ]
  if (items.length === 0) return null

  const shown = collapseAfter === undefined ? items : items.slice(0, collapseAfter)
  const hidden = collapseAfter === undefined ? [] : items.slice(collapseAfter)

  const renderTag = (item: (typeof items)[number]) => {
    const tag = (
      <Tag color={item.color} style={item.cnnvd && linkCnnvd ? { cursor: 'pointer' } : undefined}>
        {item.id}
      </Tag>
    )
    const wrapped =
      item.cnnvd && linkCnnvd ? (
        <Link to={`/waf/vuln-refs?focus=${encodeURIComponent(item.id)}`}>{tag}</Link>
      ) : (
        tag
      )
    return (
      <Tooltip key={`${item.cnnvd ? 'cnnvd' : 'cve'}-${item.id}`} title={item.id}>
        {wrapped}
      </Tooltip>
    )
  }

  return (
    <>
      {shown.map(renderTag)}
      {hidden.length > 0 && (
        <Tooltip title={hidden.map((i) => i.id).join('、')}>
          <Tag>+{hidden.length}</Tag>
        </Tooltip>
      )}
    </>
  )
}
