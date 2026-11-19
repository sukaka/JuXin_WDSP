import { Tag, Tooltip } from 'antd'
import dayjs from 'dayjs'
import { formatDateTime } from '../utils/format'

interface UserStatusTagProps {
  status: string
  lockedUntil?: string | null
}

/** 用户状态标签：ACTIVE 绿 / DISABLED 灰 / 锁定 红 */
export default function UserStatusTag({ status, lockedUntil }: UserStatusTagProps) {
  const normalized = (status || '').trim().toUpperCase()
  const locked =
    normalized === 'LOCKED' || Boolean(lockedUntil && dayjs(lockedUntil).isAfter(dayjs()))
  if (locked) {
    const tip = lockedUntil ? `锁定至 ${formatDateTime(lockedUntil)}` : '账号已锁定'
    return (
      <Tooltip title={tip}>
        <Tag color="red">已锁定</Tag>
      </Tooltip>
    )
  }
  if (normalized === 'ACTIVE') return <Tag color="green">正常</Tag>
  if (normalized === 'DISABLED') return <Tag color="default">已停用</Tag>
  return <Tag>{status}</Tag>
}
