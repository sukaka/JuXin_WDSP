import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import dayjs from 'dayjs'
import SystemUpgradePage from '../SystemUpgradePage'
import { useAuthStore } from '../../../stores/auth'
import { ApiError, type UploadProgress } from '../../../api/client'
import { formatDateTime } from '../../../utils/format'
import type { CurrentUser } from '../../../types'

// 在 client 层打桩：保留 upgradesApi.uploadPackage 真实的 FormData 组装逻辑，直接断言最终请求体
vi.mock('../../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/client')>()
  return { ...actual, request: vi.fn(), upload: vi.fn() }
})

import { request, upload } from '../../../api/client'

const requestMock = vi.mocked(
  request as unknown as (path: string, options?: { method?: string }) => Promise<unknown>,
)
const uploadMock = vi.mocked(
  upload as unknown as (
    path: string,
    form: FormData,
    options?: { onProgress?: (progress: UploadProgress) => void },
  ) => Promise<unknown>,
)

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'ops',
    display_name: '系统管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SYSTEM_ADMIN', name: '系统管理员' }],
    permissions,
    must_change_password: false,
  }
}

function uploadedPackage() {
  return {
    id: 'pkg-1',
    file_name: 'jiuzhang-wdsp-offline-2.6.0-amd64.tar.gz',
    version_from: '2.5.5',
    version_to: '2.6.0',
    file_size: 1024,
    file_hash: 'a'.repeat(64),
    status: 'VERIFIED',
    uploaded_at: '2026-09-14T00:00:00Z',
  }
}

function startedExecution() {
  return {
    id: 'job-1',
    package_id: 'pkg-1',
    version_from: '2.5.5',
    version_to: '2.6.0',
    status: 'PRECHECK',
    created_at: '2026-09-14T00:00:00Z',
  }
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <SystemUpgradePage />
      </AntdApp>
    </QueryClientProvider>,
  )
}

/** 全量并行跑时机器负载高，关键异步等待在全局 10s 基础上再放宽 */
const SLOW = { timeout: 30000 }

/** 打开上传弹窗并返回升级包文件输入框（accept=".tar.gz"） */
async function openUploadModal() {
  fireEvent.click(screen.getByRole('button', { name: /上传升级包/ }))
  await screen.findByText('点击或拖拽升级包文件到此区域', undefined, SLOW)
  const pkgInput = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')
  expect(pkgInput).toBeTruthy()
  return pkgInput as HTMLInputElement
}

function okButton() {
  return screen.getByRole('button', { name: /确认上传/ })
}

function selectPackageFile(input: HTMLInputElement) {
  const file = new File(['pkg-bytes'], 'jiuzhang-wdsp-offline-2.6.0-amd64.tar.gz')
  fireEvent.change(input, { target: { files: [file] } })
  return file
}

/** 选择「定时更新」时机并等待 DatePicker 出现 */
async function chooseScheduledTiming() {
  fireEvent.click(screen.getByLabelText('定时更新'))
  await screen.findByPlaceholderText('选择升级开始时间', undefined, SLOW)
}

/**
 * 在定时 DatePicker 面板点「此刻」提交一个有效时间并关闭面板
 * （focus + mouseDown 容器 + click 输入框组合为 antd 6 下可靠打开面板的方式，与 ApiScanPage 用例一致）
 */
async function pickTimeViaNowButton() {
  const pickerInput = screen.getByPlaceholderText('选择升级开始时间')
  const picker = pickerInput.closest('.ant-picker') as HTMLElement
  expect(picker).toBeTruthy()
  fireEvent.focus(pickerInput)
  fireEvent.mouseDown(picker)
  fireEvent.click(pickerInput)
  const nowBtn = await waitFor(() => {
    const el = document.querySelector('.ant-picker-now-btn')
    expect(el).toBeTruthy()
    return el as HTMLElement
  }, SLOW)
  fireEvent.click(nowBtn)
}

describe('SystemUpgradePage 升级包上传（单文件 + 自动识别版本 + 自动升级）', () => {
  beforeEach(() => {
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/upgrades') {
        return { items: [], page: 1, page_size: 20, total: 0 }
      }
      if (method === 'GET' && path === '/upgrade-packages') {
        return { items: [], page: 1, page_size: 50, total: 0 }
      }
      throw new ApiError(`未打桩的请求：${method} ${path}`, 'MOCK_MISS', 500)
    })
    uploadMock.mockResolvedValue({ package: uploadedPackage(), execution: startedExecution() })
    useAuthStore.setState({
      user: makeUser(['upgrades.execute', 'upgrades.precheck', 'upgrades.rollback']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
    useAuthStore.getState().reset()
  })

  it('只选文件即可提交：FormData 仅含 file，不含 signature/version 字段', async () => {
    renderPage()
    const pkgInput = await openUploadModal()

    // 旧交互已移除：签名文件选择区、旧/新版本输入框
    expect(document.querySelector('input[type="file"][accept=".sig"]')).toBeNull()
    expect(screen.queryByPlaceholderText('如：2.5.5')).toBeNull()
    expect(screen.queryByPlaceholderText('如：2.6.0')).toBeNull()

    // 未选文件时上传按钮不可用
    expect(okButton()).toBeDisabled()

    const file = selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    fireEvent.click(okButton())

    await waitFor(() => expect(uploadMock).toHaveBeenCalledTimes(1), SLOW)
    const [path, form] = uploadMock.mock.calls[0]
    expect(path).toBe('/upgrades/packages/upload')
    expect(Array.from(form.keys())).toEqual(['file'])
    expect(form.get('signature')).toBeNull()
    expect(form.get('version_from')).toBeNull()
    expect(form.get('version_to')).toBeNull()
    expect(form.get('manifest')).toBeNull()
    expect((form.get('file') as File).name).toBe(file.name)
  })

  it('上传入口明确升级仅可从本页面发起，并展示升级包命名示例', async () => {
    renderPage()
    await openUploadModal()

    expect(screen.getByText(/升级仅可通过本页面发起/)).toBeInTheDocument()
    expect(screen.getByText(/jiuzhang-wdsp-upgrade-1\.3\.0-amd64\.tar\.gz/)).toBeInTheDocument()
  })

  it('成功响应带 execution：展示检测到的版本与自动开始升级提示，并刷新执行列表', async () => {
    renderPage()
    const pkgInput = await openUploadModal()
    // 挂载后首次执行列表加载完成，作为刷新前基线
    await waitFor(() => expect(requestMock.mock.calls.some(([p]) => p === '/upgrades')).toBe(true), SLOW)
    const listCallsBefore = requestMock.mock.calls.filter(([p]) => p === '/upgrades').length

    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    fireEvent.click(okButton())

    expect(await screen.findByText('检测到的版本：从 2.5.5 → 2.6.0', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('已开始自动升级，可在下方列表查看进度')).toBeInTheDocument()
    // 上传成功后失效并重新拉取执行列表（轮询复用现有列表查询）
    await waitFor(
      () => expect(requestMock.mock.calls.filter(([p]) => p === '/upgrades').length).toBeGreaterThan(listCallsBefore),
      SLOW,
    )
  })

  it('execution 为 null 且带 warning：黄色警告展示未自动开始的原因', async () => {
    uploadMock.mockResolvedValue({
      package: uploadedPackage(),
      execution: null,
      warning: '已有执行中的升级任务，完成后可手动执行',
    })
    renderPage()
    const pkgInput = await openUploadModal()
    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    fireEvent.click(okButton())

    expect(await screen.findByText('检测到的版本：从 2.5.5 → 2.6.0', undefined, SLOW)).toBeInTheDocument()
    expect(await screen.findByText('已有执行中的升级任务，完成后可手动执行', undefined, SLOW)).toBeInTheDocument()
    expect(document.querySelector('.ant-alert-warning')).toBeTruthy()
  })

  it('上传失败：展示服务端错误 message（如验签失败），弹窗保持打开', async () => {
    uploadMock.mockRejectedValue(new ApiError('升级包签名校验失败', 'SIGNATURE_VERIFY_FAILED', 400))
    renderPage()
    const pkgInput = await openUploadModal()
    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    fireEvent.click(okButton())

    expect(await screen.findByText('升级包签名校验失败', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('点击或拖拽升级包文件到此区域')).toBeInTheDocument()
  })

  it('上传中显示真实字节与百分比，100% 后提示等待验签而非升级成功', async () => {
    let reportProgress: ((progress: UploadProgress) => void) | undefined
    let resolveUpload: ((value: unknown) => void) | undefined
    uploadMock.mockImplementation((_path, _form, options) => {
      reportProgress = options?.onProgress
      return new Promise((resolve) => {
        resolveUpload = resolve
      })
    })
    renderPage()
    const pkgInput = await openUploadModal()
    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    fireEvent.click(okButton())

    await waitFor(() => expect(reportProgress).toBeDefined(), SLOW)
    act(() => reportProgress?.({ loaded: 50, total: 100, lengthComputable: true }))
    expect(await screen.findByText('50%', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('正在上传：50 B / 100 B')).toBeInTheDocument()

    act(() => reportProgress?.({ loaded: 100, total: 100, lengthComputable: true }))
    expect(await screen.findByText('100%', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('升级包已上传，正在等待服务端验签并创建升级任务…')).toBeInTheDocument()
    expect(screen.queryByText('已开始自动升级，可在下方列表查看进度')).toBeNull()
    expect(okButton()).toBeDisabled()

    act(() => resolveUpload?.({ package: uploadedPackage(), execution: startedExecution() }))
    expect(await screen.findByText('已开始自动升级，可在下方列表查看进度', undefined, SLOW)).toBeInTheDocument()
  })

  it('非 .tar.gz 文件：拒绝选择并提示，不发起上传', async () => {
    renderPage()
    const pkgInput = await openUploadModal()

    fireEvent.change(pkgInput, { target: { files: [new File(['pkg-bytes'], 'pkg.zip')] } })

    expect(await screen.findByText('仅支持 .tar.gz 格式的升级包', undefined, SLOW)).toBeInTheDocument()
    expect(okButton()).toBeDisabled()
    fireEvent.click(okButton())
    expect(uploadMock).not.toHaveBeenCalled()
  })
})

/** 打桩 GET 列表请求；execution 任务清单可自定义 */
function stubListRequests(jobs: Record<string, unknown>[]) {
  requestMock.mockImplementation(async (path, options) => {
    const method = options?.method ?? 'GET'
    if (method === 'GET' && path === '/upgrades') {
      return { items: jobs, page: 1, page_size: 20, total: jobs.length }
    }
    if (method === 'GET' && path === '/upgrade-packages') {
      return { items: [], page: 1, page_size: 50, total: 0 }
    }
    if (method === 'POST' && path === '/upgrades/job-sched-1/cancel') {
      return { job: { ...scheduledJob(), status: 'CANCELLED' } }
    }
    throw new ApiError(`未打桩的请求：${method} ${path}`, 'MOCK_MISS', 500)
  })
}

function scheduledJob() {
  return {
    id: 'job-sched-1',
    package_id: 'pkg-1',
    version_from: '2.5.5',
    version_to: '2.6.0',
    status: 'SCHEDULED',
    scheduled_at: '2026-09-15T02:00:00Z',
    created_at: '2026-09-14T00:00:00Z',
  }
}

describe('SystemUpgradePage 定时更新（scheduled_at + SCHEDULED 任务取消）', () => {
  beforeEach(() => {
    stubListRequests([])
    uploadMock.mockResolvedValue({ package: uploadedPackage(), execution: startedExecution() })
    useAuthStore.setState({
      user: makeUser(['upgrades.execute', 'upgrades.precheck', 'upgrades.rollback']),
      csrfToken: null,
      initialized: true,
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
    useAuthStore.getState().reset()
  })

  it('定时更新但未选择时间：提示「请选择升级开始时间」且不提交', async () => {
    renderPage()
    const pkgInput = await openUploadModal()
    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    await chooseScheduledTiming()

    fireEvent.click(okButton())

    expect(await screen.findByText('请选择升级开始时间', undefined, SLOW)).toBeInTheDocument()
    expect(uploadMock).not.toHaveBeenCalled()
    // 弹窗保持打开
    expect(screen.getByText('点击或拖拽升级包文件到此区域')).toBeInTheDocument()
  })

  it('定时更新并选择时间：FormData 追加 scheduled_at（RFC3339 带时区 ISO 串）', async () => {
    renderPage()
    const pkgInput = await openUploadModal()
    const file = selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    await chooseScheduledTiming()
    await pickTimeViaNowButton()

    fireEvent.click(okButton())

    await waitFor(() => expect(uploadMock).toHaveBeenCalledTimes(1), SLOW)
    const [path, form] = uploadMock.mock.calls[0]
    expect(path).toBe('/upgrades/packages/upload')
    expect(Array.from(form.keys())).toEqual(['file', 'scheduled_at'])
    expect((form.get('file') as File).name).toBe(file.name)
    const scheduledAt = form.get('scheduled_at')
    expect(typeof scheduledAt).toBe('string')
    expect(String(scheduledAt)).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/)
    expect(dayjs(String(scheduledAt)).isValid()).toBe(true)
  })

  it('execution.status=SCHEDULED：蓝色 info 提示已创建定时升级，含本地化计划时间', async () => {
    uploadMock.mockResolvedValue({
      package: uploadedPackage(),
      execution: { ...startedExecution(), status: 'SCHEDULED', scheduled_at: '2026-09-15T02:00:00Z' },
    })
    renderPage()
    const pkgInput = await openUploadModal()
    selectPackageFile(pkgInput)
    await waitFor(() => expect(okButton()).toBeEnabled(), SLOW)
    await chooseScheduledTiming()
    await pickTimeViaNowButton()
    fireEvent.click(okButton())

    expect(
      await screen.findByText('已创建定时升级：检测版本 2.5.5 → 2.6.0', undefined, SLOW),
    ).toBeInTheDocument()
    expect(
      screen.getByText(`将于 ${formatDateTime('2026-09-15T02:00:00Z')} 自动开始；开始升级前会自动创建全量备份`),
    ).toBeInTheDocument()
    expect(document.querySelector('.ant-alert-info')).toBeTruthy()
    // 立即升级的成功提示不出现
    expect(screen.queryByText('已开始自动升级，可在下方列表查看进度')).toBeNull()
  })

  it('列表 SCHEDULED 行：蓝色「定时中」标签、本地化计划时间与取消按钮，确认后调用取消接口并刷新列表', async () => {
    stubListRequests([scheduledJob()])
    renderPage()

    expect(await screen.findByText('定时中', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText(formatDateTime('2026-09-15T02:00:00Z'))).toBeInTheDocument()

    const listCallsBefore = requestMock.mock.calls.filter(([p]) => p === '/upgrades').length
    fireEvent.click(screen.getByRole('button', { name: '取消' }))
    // Popconfirm 确认（autoInsertSpace 下「确 定」带空格，正则兼容）
    fireEvent.click(await screen.findByRole('button', { name: /确\s*定/ }, SLOW))

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(
            ([p, o]) => p === '/upgrades/job-sched-1/cancel' && (o?.method ?? 'GET') === 'POST',
          ),
        ).toBe(true),
      SLOW,
    )
    // 取消成功后失效并重新拉取执行列表
    await waitFor(
      () => expect(requestMock.mock.calls.filter(([p]) => p === '/upgrades').length).toBeGreaterThan(listCallsBefore),
      SLOW,
    )
  })

  it('PENDING 行：不展示取消按钮', async () => {
    stubListRequests([{ ...startedExecution(), id: 'job-pending-1', status: 'PENDING' }])
    renderPage()

    expect(await screen.findByText('排队中', undefined, SLOW)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '取消' })).toBeNull()
  })

  it('预检竞态防护：切换升级包后，旧包在途预检晚到不得覆盖新包或启用执行按钮', async () => {
    const pkgA = { ...uploadedPackage(), id: 'pkg-a', file_name: 'pkg-a.tar.gz', version_to: '2.6.0' }
    const pkgB = { ...uploadedPackage(), id: 'pkg-b', file_name: 'pkg-b.tar.gz', version_to: '2.7.0' }
    let resolvePrecheckA: ((value: unknown) => void) | undefined

    requestMock.mockImplementation((path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/upgrades') {
        return Promise.resolve({ items: [], page: 1, page_size: 20, total: 0 })
      }
      if (method === 'GET' && path === '/upgrade-packages') {
        return Promise.resolve({ items: [pkgA, pkgB], page: 1, page_size: 50, total: 2 })
      }
      if (method === 'POST' && path === '/upgrades/precheck') {
        return new Promise((resolve) => {
          resolvePrecheckA = resolve
        })
      }
      return Promise.reject(new ApiError(`未打桩的请求：${method} ${path}`, 'MOCK_MISS', 500))
    })

    renderPage()
    const select = await screen.findByRole('combobox', undefined, SLOW)

    // 选择 pkg-a 并触发预检（请求挂起）
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByText(/pkg-a\.tar\.gz/, undefined, SLOW))
    const precheckBtn = screen.getByRole('button', { name: /执行预检/ })
    const executeBtn = screen.getByRole('button', { name: /执行升级/ })
    expect(executeBtn).toBeDisabled()
    fireEvent.click(precheckBtn)
    await waitFor(() => expect(resolvePrecheckA).toBeDefined(), SLOW)

    // 预检返回前切换为 pkg-b
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByText(/pkg-b\.tar\.gz/, undefined, SLOW))

    // 旧包 pkg-a 的预检结果延迟返回 PASS
    act(() => {
      resolvePrecheckA?.({
        package_id: 'pkg-a',
        overall_result: 'PASS',
        items: [{ name: '磁盘空间', result: 'PASS', message: 'ok' }],
      })
    })

    // 执行升级按钮必须继续保持禁用，且不得渲染 pkg-a 的预检结果
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /执行升级/ })).toBeDisabled()
    }, SLOW)
    expect(screen.queryByText(/预检结果：通过/)).toBeNull()
  })

  it('预检列表将后端英文检查项编码映射为中文名称展示', async () => {
    const pkg = uploadedPackage()
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/upgrades') {
        return { items: [], page: 1, page_size: 20, total: 0 }
      }
      if (method === 'GET' && path === '/upgrade-packages') {
        return { items: [pkg], page: 1, page_size: 50, total: 1 }
      }
      if (method === 'POST' && path === '/upgrades/precheck') {
        return {
          passed: true,
          precheck: [
            { name: 'version_match', result: 'PASS', critical: true, message: '版本兼容' },
            { name: 'disk_space', result: 'PASS', critical: true, message: '剩余空间充足' },
            { name: 'postgres_reachable', result: 'PASS', critical: true, message: '连接正常' },
            { name: 'valkey_reachable', result: 'PASS', critical: true, message: '连接正常' },
            { name: 'package_artifact', result: 'PASS', critical: true, message: '签名校验通过' },
          ],
        }
      }
      throw new ApiError(`未打桩的请求：${method} ${path}`, 'MOCK_MISS', 500)
    })

    renderPage()
    const select = await screen.findByRole('combobox', undefined, SLOW)
    fireEvent.mouseDown(select)
    fireEvent.click(await screen.findByText(/jiuzhang-wdsp-offline-2\.6\.0-amd64\.tar\.gz/, undefined, SLOW))
    fireEvent.click(screen.getByRole('button', { name: /执行预检/ }))

    expect(await screen.findByText('版本兼容性检查', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('磁盘空间检查')).toBeInTheDocument()
    expect(screen.getByText('数据库连接检查')).toBeInTheDocument()
    expect(screen.getByText('缓存服务连接检查')).toBeInTheDocument()
    expect(screen.getByText('升级包产物校验')).toBeInTheDocument()
    expect(screen.queryByText('version_match')).not.toBeInTheDocument()
    expect(screen.queryByText('postgres_reachable')).not.toBeInTheDocument()
  })
})
