import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { ApiError } from '../../api/client'
import QueryErrorAlert from '../QueryErrorAlert'

describe('QueryErrorAlert', () => {
  it('renders nothing when error is null or undefined', () => {
    const { container: c1 } = render(<QueryErrorAlert error={null} />)
    expect(c1).toBeEmptyDOMElement()
    const { container: c2 } = render(<QueryErrorAlert error={undefined} />)
    expect(c2).toBeEmptyDOMElement()
  })

  it('shows permission warning on 403', () => {
    render(<QueryErrorAlert error={new ApiError('denied', 'PERMISSION_DENIED', 403)} />)
    expect(screen.getByText('暂无权限查看')).toBeInTheDocument()
  })

  it('shows load failure with backend message on other errors', () => {
    render(
      <QueryErrorAlert
        error={new ApiError('服务器内部错误，请稍后重试', 'INTERNAL_ERROR', 500)}
        message="加载数据失败"
      />,
    )
    expect(screen.getByText('加载数据失败')).toBeInTheDocument()
    expect(screen.getByText('服务器内部错误，请稍后重试')).toBeInTheDocument()
  })
})
