import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import SystemContainersPage from '../SystemContainersPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'
import type { ContainerActionJob, ContainerInfo, ContainerLogsResp } from '../../../api/containerOps'

vi.mock('../../../api/containerOps', () => ({
  CONTAINER_UPDATE_CONFIRM_TEXT: '更新容器',
  containerOpsApi: {
    list: vi.fn(),
    logs: vi.fn(),
    actionStatus: vi.fn(),
    start: vi.fn(),
    stop: vi.fn(),
    restart: vi.fn(),
    update: vi.fn(),
  },
}))

import { containerOpsApi } from '../../../api/containerOps'

const ALL_PERMISSIONS = ['containers.read', 'containers.logs', 'containers.control', 'containers.update']

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sys',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
    permissions,
    must_change_password: false,
  }
}

function makeContainer(partial: Partial<ContainerInfo> = {}): ContainerInfo {
  return {
    service: 'gateway',
    project: 'jiuzhang',
    id: 'c-gateway',
    name: 'jiuzhang-gateway',
    image: 'jiuzhang/gateway:1.0.0',
    image_id: 'sha256:aaa',
    state: 'running',
    status: 'Up 2 hours',
    health: 'healthy',
    running: true,
    restart_count: 0,
    started_at: '2026-10-19T01:00:00Z',
    ...partial,
  }
}

function makeLogsResp(partial: Partial<ContainerLogsResp> = {}): ContainerLogsResp {
  return {
    service: 'gateway',
    lines: [],
    truncated: false,
    next_since: 0,
    ...partial,
  }
}

function makeJob(partial: Partial<ContainerActionJob> = {}): ContainerActionJob {
  return {
    job_id: 'job-1',
    service: 'gateway',
    action: 'update',
    status: 'SUCCESS',
    message: '容器已更新',
    started_at: '2026-10-19T02:00:00Z',
    finished_at: '2026-10-19T02:00:30Z',
    ...partial,
  }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SystemContainersPage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 伪定时器下刷新 microtask，让 react-query / 抽屉内 fetch 完成 settle */
async function flush() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0)
  })
}

describe('SystemContainersPage', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [] })
    vi.mocked(containerOpsApi.logs).mockResolvedValue(makeLogsResp())
    vi.mocked(containerOpsApi.actionStatus).mockResolvedValue(makeJob())
    vi.mocked(containerOpsApi.start).mockResolvedValue({ job_id: 'job-start', status: 'PENDING' })
    vi.mocked(containerOpsApi.stop).mockResolvedValue({ job_id: 'job-stop', status: 'PENDING' })
    vi.mocked(containerOpsApi.restart).mockResolvedValue({ job_id: 'job-restart', status: 'PENDING' })
    vi.mocked(containerOpsApi.update).mockResolvedValue({ job_id: 'job-update', status: 'PENDING' })
    useAuthStore.setState({
      user: makeUser(ALL_PERMISSIONS),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('渲染容器列表：服务/名称/镜像、状态、健康、重启次数、启动时间与自动刷新提示', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({
      containers: [
        makeContainer(),
        makeContainer({
          service: 'postgres',
          id: 'c-postgres',
          name: 'jiuzhang-postgres',
          image: 'postgres:16.4',
          state: 'exited',
          status: 'Exited (0) 10 minutes ago',
          health: '',
          running: false,
          restart_count: 3,
          started_at: '2026-10-18T12:00:00Z',
        }),
      ],
    })
    renderPage()

    // 第一行（运行中）
    const row1 = (await screen.findByText('jiuzhang-gateway')).closest('tr')!
    expect(within(row1).getByText('gateway')).toBeInTheDocument()
    expect(within(row1).getByText('jiuzhang/gateway:1.0.0')).toBeInTheDocument()
    expect(within(row1).getByText('运行中')).toBeInTheDocument()
    expect(within(row1).getByText('健康')).toBeInTheDocument()
    expect(within(row1).getByText('0')).toBeInTheDocument()
    expect(within(row1).getByText(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/)).toBeInTheDocument()

    // 第二行（已退出、未配置健康探针）
    const row2 = screen.getByText('jiuzhang-postgres').closest('tr')!
    expect(within(row2).getByText('已退出')).toBeInTheDocument()
    expect(within(row2).getByText('3')).toBeInTheDocument()

    // 自动刷新提示与手动刷新按钮
    expect(screen.getByText(/5 秒自动刷新/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /刷\s*新/ })).toBeInTheDocument()
  })

  it('仅有 containers.read 权限时隐藏日志与全部操作按钮', async () => {
    useAuthStore.setState({ user: makeUser(['containers.read']), csrfToken: null, initialized: true })
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    renderPage()
    await screen.findByText('jiuzhang-gateway')
    expect(screen.queryByRole('button', { name: '日志' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '启动' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停止' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '重启' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '更新' })).not.toBeInTheDocument()
  })

  it('按权限点分别控制按钮：logs 仅日志、control 仅启停、update 仅更新', async () => {
    useAuthStore.setState({ user: makeUser(['containers.read', 'containers.logs']), csrfToken: null, initialized: true })
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    const { unmount } = renderPage()
    await screen.findByText('jiuzhang-gateway')
    expect(screen.getByRole('button', { name: '日志' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '停止' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '更新' })).not.toBeInTheDocument()
    unmount()

    useAuthStore.setState({ user: makeUser(['containers.read', 'containers.control']), csrfToken: null, initialized: true })
    renderPage()
    await screen.findByText('jiuzhang-gateway')
    expect(screen.queryByRole('button', { name: '日志' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: '停止' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '重启' })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '更新' })).not.toBeInTheDocument()
  })

  it('日志抽屉：首屏 tail=200，之后每 2 秒携带 since=next_since 增量拉取；暂停停止轮询、继续恢复', async () => {
    vi.useFakeTimers()
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    vi.mocked(containerOpsApi.logs).mockResolvedValue(
      makeLogsResp({
        lines: [{ timestamp: '2026-10-19T01:02:03Z', stream: 'stdout', message: 'first line' }],
        next_since: 1234567890,
      }),
    )
    renderPage()
    await flush()
    fireEvent.click(screen.getByRole('button', { name: '日志' }))
    await flush()

    // 首屏：tail=200 且不携带 since
    expect(containerOpsApi.logs).toHaveBeenCalledTimes(1)
    expect(containerOpsApi.logs).toHaveBeenLastCalledWith('gateway', { tail: 200, since: undefined })
    expect(screen.getByText(/first line/)).toBeInTheDocument()

    // 2 秒后按上次 next_since 增量拉取
    vi.mocked(containerOpsApi.logs).mockResolvedValue(
      makeLogsResp({
        lines: [{ timestamp: '2026-10-19T01:02:05Z', stream: 'stderr', message: 'second line' }],
        next_since: 1234567892,
      }),
    )
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(containerOpsApi.logs).toHaveBeenCalledTimes(2)
    expect(containerOpsApi.logs).toHaveBeenLastCalledWith('gateway', { tail: 200, since: 1234567890 })
    expect(screen.getByText(/second line/)).toBeInTheDocument()

    // 暂停后不再轮询；继续后恢复（antd 默认按钮对两个汉字自动插入空格，按名称正则匹配）
    fireEvent.click(screen.getByRole('button', { name: /暂\s*停/ }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(4000)
    })
    expect(containerOpsApi.logs).toHaveBeenCalledTimes(2)
    fireEvent.click(screen.getByRole('button', { name: /继\s*续/ }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2000)
    })
    expect(containerOpsApi.logs).toHaveBeenCalledTimes(3)
    expect(containerOpsApi.logs).toHaveBeenLastCalledWith('gateway', { tail: 200, since: 1234567892 })
  })

  it('日志 truncated 时展示截断提示，tail 可切换为 100/500/1000', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    vi.mocked(containerOpsApi.logs).mockResolvedValue(
      makeLogsResp({
        lines: [{ timestamp: '2026-10-19T01:02:03Z', stream: 'stdout', message: 'boom' }],
        truncated: true,
        next_since: 1234567890,
      }),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '日志' }))
    expect(await screen.findByText(/内容可能不完整/)).toBeInTheDocument()

    // 切换 tail 为 500：重置为首屏快照（不携带 since）
    fireEvent.mouseDown(screen.getByLabelText('日志行数'))
    const option = await screen.findByText('tail 500')
    fireEvent.click(option)
    await waitFor(() =>
      expect(containerOpsApi.logs).toHaveBeenLastCalledWith('gateway', { tail: 500, since: undefined }),
    )
  })

  it('启动按钮仅对未运行容器展示，确认后调用 start 接口', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({
      containers: [
        makeContainer(),
        makeContainer({ service: 'valkey', id: 'c-valkey', name: 'jiuzhang-valkey', running: false, state: 'exited' }),
      ],
    })
    renderPage()
    const stoppedRow = (await screen.findByText('jiuzhang-valkey')).closest('tr')!
    expect(within(stoppedRow).getByRole('button', { name: '启动' })).toBeInTheDocument()
    const runningRow = screen.getByText('jiuzhang-gateway').closest('tr')!
    expect(within(runningRow).queryByRole('button', { name: '启动' })).toBeNull()

    fireEvent.click(within(stoppedRow).getByRole('button', { name: '启动' }))
    fireEvent.change(await screen.findByPlaceholderText('请输入当前账号密码'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /确认执行/ }))
    await waitFor(() => expect(containerOpsApi.start).toHaveBeenCalledWith('valkey', 'pw'))
    expect(await screen.findByText(/启动指令已受理/)).toBeInTheDocument()
  })

  it('更新容器：需输入固定确认文本「更新容器」与密码，提交后调用 update 并轮询任务至成功提示', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    vi.mocked(containerOpsApi.actionStatus).mockResolvedValue(makeJob({ job_id: 'job-update' }))
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '更新' }))
    expect(await screen.findByText('高风险操作确认：更新容器')).toBeInTheDocument()

    const okButton = screen.getByRole('button', { name: /确认执行/ })
    expect(okButton).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText('请输入当前账号密码'), { target: { value: 'secret' } })
    // 仅密码不足以确认，必须输入固定确认文本
    expect(okButton).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText('请输入「更新容器」以确认'), { target: { value: '更新容' } })
    expect(okButton).toBeDisabled()
    fireEvent.change(screen.getByPlaceholderText('请输入「更新容器」以确认'), { target: { value: '更新容器' } })
    expect(okButton).toBeEnabled()
    fireEvent.click(okButton)

    await waitFor(() => expect(containerOpsApi.update).toHaveBeenCalledWith('gateway', 'secret', '更新容器'))
    expect(await screen.findByText('更新指令已受理，正在后台执行')).toBeInTheDocument()
    // 轮询 GET action 状态，终态以后端 message 提示并刷新列表
    await waitFor(() => expect(containerOpsApi.actionStatus).toHaveBeenCalledWith('job-update'))
    expect(await screen.findByText('容器已更新')).toBeInTheDocument()
  })

  it('任务失败时以后端 message 提示并刷新列表', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({ containers: [makeContainer()] })
    vi.mocked(containerOpsApi.actionStatus).mockResolvedValue(
      makeJob({ job_id: 'job-restart', action: 'restart', status: 'FAILED', message: '容器重启超时' }),
    )
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: '重启' }))
    fireEvent.change(await screen.findByPlaceholderText('请输入当前账号密码'), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /确认执行/ }))
    await waitFor(() => expect(containerOpsApi.restart).toHaveBeenCalledWith('gateway', 'pw'))
    expect(await screen.findByText('容器重启超时')).toBeInTheDocument()
  })

  it('api 容器仅渲染重启操作：启动/停止/更新隐藏并提示安全边界', async () => {
    vi.mocked(containerOpsApi.list).mockResolvedValue({
      containers: [
        makeContainer({ service: 'api', id: 'c-api', name: 'jiuzhang-api' }),
        makeContainer(),
      ],
    })
    renderPage()
    // api 行：仅重启，停止/更新不渲染，提示仅支持重启
    const apiRow = (await screen.findByText('jiuzhang-api')).closest('tr')!
    expect(within(apiRow).getByRole('button', { name: '重启' })).toBeInTheDocument()
    expect(within(apiRow).queryByRole('button', { name: '启动' })).toBeNull()
    expect(within(apiRow).queryByRole('button', { name: '停止' })).toBeNull()
    expect(within(apiRow).queryByRole('button', { name: '更新' })).toBeNull()
    expect(within(apiRow).getByText('仅支持重启')).toBeInTheDocument()
    // 其他容器不受影响：停止/更新照常渲染
    const gatewayRow = screen.getByText('jiuzhang-gateway').closest('tr')!
    expect(within(gatewayRow).getByRole('button', { name: '停止' })).toBeInTheDocument()
    expect(within(gatewayRow).getByRole('button', { name: '更新' })).toBeInTheDocument()
  })
})
