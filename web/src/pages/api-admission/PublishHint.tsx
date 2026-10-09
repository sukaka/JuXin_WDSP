import { Link } from 'react-router-dom'
import { Space } from 'antd'

/**
 * 发布提醒：确认/忽略/模式切换仅改库，随整站发布生效（配置发布为现有发布入口）。
 * 用于操作成功 message 内容（ReactNode）。
 */
export default function PublishHint({ prefix }: { prefix: string }) {
  return (
    <Space size={4} wrap>
      <span>{prefix}；确认集变更需发布后生效。</span>
      <Link to="/config-publish">前往配置发布</Link>
    </Space>
  )
}
