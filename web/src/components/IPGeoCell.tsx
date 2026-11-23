import { Space, Tag, Tooltip, Typography } from 'antd'
import type { IPGeoInfo } from '../types'
import { formatGeoDisplay } from '../utils/ipgeo'

/** 表格内紧凑展示 IP 归属地与运营商（用于安全事件列表与访问日志列表） */
export default function IPGeoCell({ geo }: { geo?: IPGeoInfo | null }) {
  const { location, isp } = formatGeoDisplay(geo)
  if (!location && !isp) {
    return <Typography.Text type="secondary">-</Typography.Text>
  }
  if (geo?.scope === 'INTERNAL') {
    return <Tag style={{ marginInlineEnd: 0 }}>{location || '内网地址'}</Tag>
  }
  const fullText = [location, isp].filter(Boolean).join(' · ')
  return (
    <Tooltip title={fullText} placement="topLeft">
      <Space size={4} style={{ maxWidth: '100%' }}>
        <Typography.Text ellipsis style={{ maxWidth: isp ? 120 : 170 }}>
          {location || '-'}
        </Typography.Text>
        {isp && (
          <Tag bordered={false} style={{ marginInlineEnd: 0, maxWidth: 68, overflow: 'hidden', textOverflow: 'ellipsis' }}>
            {isp}
          </Tag>
        )}
      </Space>
    </Tooltip>
  )
}
