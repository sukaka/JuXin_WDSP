import { Button, Result } from 'antd'
import { useNavigate } from 'react-router-dom'

function ErrorResult({ status, title, subTitle }: { status: '403' | '404' | '500'; title: string; subTitle: string }) {
  const navigate = useNavigate()
  return (
    <Result
      status={status}
      title={title}
      subTitle={subTitle}
      extra={
        <Button type="primary" onClick={() => navigate('/dashboard')}>
          返回工作台
        </Button>
      }
      style={{ paddingTop: 96 }}
    />
  )
}

export function ForbiddenPage() {
  return <ErrorResult status="403" title="无访问权限" subTitle="您没有访问该页面的权限，请联系系统管理员。" />
}

export function NotFoundPage() {
  return <ErrorResult status="404" title="页面不存在" subTitle="您访问的页面不存在或已被移除。" />
}

export function ServerErrorPage() {
  return <ErrorResult status="500" title="系统错误" subTitle="系统发生未知错误，请稍后重试。" />
}
