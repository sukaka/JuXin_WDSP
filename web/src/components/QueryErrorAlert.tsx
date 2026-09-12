import { Alert } from 'antd'
import { ApiError } from '../api/client'

/**
 * 查询失败统一提示：无 error 时不渲染；403 展示无权限提示，其余错误展示后端消息。
 */
export default function QueryErrorAlert({
  error,
  message = '加载数据失败',
}: {
  error: unknown
  message?: string
}) {
  if (error == null) {
    return null
  }
  if (error instanceof ApiError && error.status === 403) {
    return (
      <Alert
        type="warning"
        showIcon
        message="暂无权限查看"
        description="当前账号没有该模块数据的查看权限，如需访问请联系系统管理员分配权限。"
      />
    )
  }
  return (
    <Alert
      type="error"
      showIcon
      message={message}
      description={error instanceof ApiError ? error.message : undefined}
    />
  )
}
