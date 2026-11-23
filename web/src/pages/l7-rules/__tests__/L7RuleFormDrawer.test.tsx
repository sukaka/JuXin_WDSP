import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import L7RuleFormDrawer from '../L7RuleFormDrawer'
import type { L7RuleFormValues } from '../formValues'

function renderDrawer(initialValues: L7RuleFormValues | null = null) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <L7RuleFormDrawer
          open
          editing={null}
          initialValues={initialValues}
          onClose={vi.fn()}
          onSaved={vi.fn()}
        />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('L7RuleFormDrawer（请求域名 Host 条件与重定向保留路径查询参数）', () => {
  it('展示请求域名条件、保留路径和查询参数选项、实时预览与 HTTPS 证书提示', async () => {
    renderDrawer({
      name: '裸域跳www',
      priority: 10,
      enabled: true,
      conditions: [{ type: 'host', op: 'eq', value: 'jxdr.cn' }],
      action: 'redirect',
      redirect_status: 301,
      redirect_url: 'https://www.jxdr.cn',
      redirect_preserve_path_query: true,
    })

    expect(await screen.findByText('请求域名（Host）')).toBeInTheDocument()
    const preserveCheckbox = screen.getByRole('checkbox', { name: '保留路径和查询参数' })
    expect(preserveCheckbox).toBeChecked()
    expect(
      await screen.findByText('效果示例：https://jxdr.cn/news?id=1 → https://www.jxdr.cn/news?id=1'),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/请确保裸域和 www 域名均已在应用管理中接入，并且 HTTPS 证书同时覆盖两个域名/),
    ).toBeInTheDocument()
  })

  it('新建默认含 1 条条件；清空全部条件、URI contains 无前导 /、custom_page 空 body 均被表单校验拦截', async () => {
    renderDrawer(null)
    // 默认带 1 条条件行
    expect(await screen.findByRole('button', { name: '删除条件' })).toBeInTheDocument()
    fireEvent.change(screen.getByPlaceholderText('如：拦截后台路径外部访问'), {
      target: { value: '规则1' },
    })
    // 删除唯一条件后提交：提示至少需要 1 条匹配条件
    fireEvent.click(screen.getByRole('button', { name: '删除条件' }))
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }))
    expect(await screen.findByText('至少需要 1 条匹配条件')).toBeInTheDocument()

    // 添加条件并填无前导 / 的 URI 值
    fireEvent.click(screen.getByRole('button', { name: /添加条件/ }))
    const valInput = await screen.findByPlaceholderText('匹配值')
    fireEvent.change(valInput, { target: { value: 'admin' } })
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }))
    expect(await screen.findByText('URI 须以 / 开头')).toBeInTheDocument()

    // block 状态码 InputNumber min=400 max=599
    const statusSpin = screen.getByRole('spinbutton', { name: '响应状态码' })
    expect(statusSpin).toHaveAttribute('aria-valuemin', '400')
    expect(statusSpin).toHaveAttribute('aria-valuemax', '599')

    // 切换 custom_page：状态码 min=200 max=599 且页面内容必填
    fireEvent.click(screen.getByRole('radio', { name: '自定义页面' }))
    await screen.findByPlaceholderText('text/html; charset=utf-8')
    const customSpin = screen.getByRole('spinbutton', { name: '响应状态码' })
    expect(customSpin).toHaveAttribute('aria-valuemin', '200')
    expect(customSpin).toHaveAttribute('aria-valuemax', '599')
    fireEvent.click(screen.getByRole('button', { name: /创\s*建/ }))
    expect(await screen.findByText('请输入页面内容')).toBeInTheDocument()
  })
})
