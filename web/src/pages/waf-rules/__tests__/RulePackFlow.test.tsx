import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp } from 'antd'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import WafRulesPage from '../WafRulesPage'
import { useAuthStore } from '../../../stores/auth'
import { ApiError, type UploadProgress } from '../../../api/client'
import type {
  CurrentUser,
  RulePackCurrentStatus,
  RulePackItem,
  RulePackJob,
} from '../../../types'

// 在 client 层打桩：保留 rulePacksApi.upload 真实的 FormData 组装与所有 8 个端点路径/方法
vi.mock('../../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../api/client')>()
  return { ...actual, request: vi.fn(), upload: vi.fn() }
})

import { request, upload } from '../../../api/client'

const requestMock = vi.mocked(
  request as unknown as (
    path: string,
    options?: { method?: string; body?: unknown; query?: Record<string, unknown> },
  ) => Promise<unknown>,
)
const uploadMock = vi.mocked(
  upload as unknown as (
    path: string,
    form: FormData,
    options?: { onProgress?: (progress: UploadProgress) => void },
  ) => Promise<unknown>,
)

const SLOW = { timeout: 15_000 }

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u-sec',
    username: 'secops',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function makeCurrentStatus(overrides: Partial<RulePackCurrentStatus> = {}): RulePackCurrentStatus {
  return {
    storage_mode: 'VERSIONED',
    writable: true,
    retention: 5,
    active_pack: {
      id: 'pack-active',
      rulepack_version: '20261201.1',
      crs_version: '4.28.0',
      min_system_version: '1.19.1',
      coraza_compat: '>=3.7.0 <4.0.0',
      is_builtin: false,
      file_name: 'jiuzhang-wdsp-rulepack-20261201.1.tar.gz',
      file_size: 512000,
      file_sha256: 'a'.repeat(64),
      manifest_sha256: 'b'.repeat(64),
      status: 'APPLIED',
      uploaded_at: '2026-12-01T08:00:00Z',
      applied_at: '2026-12-01T09:00:00Z',
      created_at: '2026-12-01T08:00:00Z',
      updated_at: '2026-12-01T09:00:00Z',
      can_rollback: false,
    },
    active_version: '20261201.1',
    active_crs_version: '4.28.0',
    gateway_rules_base_path: '/etc/caddy/rules/releases/20261201.1',
    latest_job: null,
    ha_sync_enabled: true,
    nodes: [
      {
        node_name: 'gw-primary',
        role: 'PRIMARY',
        reachable: true,
        rulepack_ready: true,
        current_version: '20261201.1',
        aligned: true,
      },
      {
        node_id: 'node-standby-1',
        node_name: 'gw-standby',
        role: 'STANDBY',
        reachable: true,
        rulepack_ready: true,
        current_version: '20261201.1',
        aligned: true,
      },
    ],
    drift_detected: false,
    ...overrides,
  }
}

function makeVerifiedPack(overrides: Partial<RulePackItem> = {}): RulePackItem {
  return {
    id: 'pack-20261215',
    rulepack_version: '20261215.1',
    crs_version: '4.29.0',
    min_system_version: '1.19.1',
    coraza_compat: '>=3.7.0 <4.0.0',
    is_builtin: false,
    file_name: 'jiuzhang-wdsp-rulepack-20261215.1.tar.gz',
    file_size: 620000,
    file_sha256: 'c'.repeat(64),
    manifest_sha256: 'd'.repeat(64),
    status: 'VERIFIED',
    uploaded_at: '2026-12-15T08:00:00Z',
    applied_at: null,
    created_at: '2026-12-15T08:00:00Z',
    updated_at: '2026-12-15T08:00:00Z',
    can_rollback: false,
    preview_report: {
      verified_at: '2026-12-15T08:00:05Z',
      signature_verified: true,
      integrity_verified: true,
      static_gate_passed: true,
      previous_version: '20261201.1',
      previous_crs_version: '4.28.0',
      target_version: '20261215.1',
      target_crs_version: '4.29.0',
      changelog: ['新增 CVE-2026-109618 应急防护规则', '升级 OWASP CRS 至 4.29.0'],
      highlighted_cves: ['CVE-2026-109618', 'CVE-2026-109619'],
      diff: {
        total_rules: 3120,
        added_count: 15,
        updated_count: 8,
        removed_count: 2,
        unchanged_count: 3097,
        by_source: { OWASP_CRS: 622, CUSTOM_PACK: 2498 },
        added_samples: [
          {
            rule_id: 1096180,
            rule_source: 'CUSTOM_PACK',
            file_name: 'cve-emergency.conf',
            name: 'CVE-2026-109618 应急检测规则',
            attack_type: 'REMOTE_CODE_EXECUTION',
            severity: 'CRITICAL',
          },
        ],
        updated_samples: [],
        removed_samples: [
          {
            rule_id: 942100,
            rule_source: 'OWASP_CRS',
            file_name: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
            name: '旧版 SQL 注入规则',
            attack_type: 'SQL_INJECTION',
            severity: 'CRITICAL',
          },
        ],
      },
      policy_warnings: [
        {
          kind: 'OVERRIDE_RULE_REMOVED',
          object_id: 'ov-1',
          object_name: '规则覆盖 #942100 (DISABLE)',
          rule_id: 942100,
          message: '已启用的规则覆盖指向规则 942100，但该规则在新规则包中已移除',
        },
        {
          kind: 'EXCEPTION_TAG_NEW_RULES',
          object_id: 'ex-1',
          object_name: '支付回调例外',
          tag: 'attack-rce',
          message: '按标签冻结的例外策略「支付回调例外」关联标签 "attack-rce"，新规则包新增 2 条规则',
        },
      ],
      node_prechecks: [
        {
          node_name: 'gw-primary',
          role: 'PRIMARY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
        {
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
      ],
      disk_free_bytes: 2 * 1024 * 1024 * 1024,
      disk_ok: true,
      split_brain_detected: false,
      active_upgrade_job: false,
    },
    ...overrides,
  }
}

function makeBaseMocks(currentStatus: RulePackCurrentStatus) {
  requestMock.mockImplementation(async (path, options) => {
    const method = options?.method ?? 'GET'
    if (method === 'GET' && path === '/rule-packs/current') {
      return currentStatus
    }
    if (method === 'GET' && path === '/waf-rules') {
      return { items: [], page: 1, page_size: 20, total: 0 }
    }
    if (method === 'GET' && path === '/waf-rules/categories') {
      return { items: [{ attack_type: 'SQL_INJECTION', count: 10 }] }
    }
    if (method === 'GET' && path === '/waf-rules/versions') {
      return { versions: [currentStatus.active_crs_version || '4.28.0'] }
    }
    throw new ApiError(`未打桩请求: ${method} ${path}`, 'MOCK_MISS', 500)
  })
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <AntdApp>
        <WafRulesPage rulePackPollIntervalMs={20} />
      </AntdApp>
    </QueryClientProvider>,
  )
}

describe('WafRulesPage 纯离线规则包热更新（R4）', () => {
  beforeEach(() => {
    useAuthStore.setState({
      user: makeUser(['waf_rules.read', 'waf_rules.pack.manage', 'waf_rules.sync']),
      csrfToken: 'csrf-test-token',
      initialized: true,
    })
  })

  afterEach(() => {
    vi.clearAllMocks()
    useAuthStore.getState().reset()
  })

  it('版本化与 HA 对齐态：页头展示规则包版本、CRS 版本、已对齐徽标，并将「同步CRS规则」降级至次级运维菜单', async () => {
    const status = makeCurrentStatus()
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return status
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'POST' && path === '/waf-rules/sync') {
        return {
          total_parsed: 10,
          total_in_db: 10,
          added: 0,
          updated: 0,
          unchanged: 10,
          missing: 0,
          parse_failed: 0,
          conflicts: 0,
          failed_rules: [],
        }
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })

    renderPage()

    expect(await screen.findByText('20261201.1', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText(/CRS 版本：4\.28\.0/)).toBeInTheDocument()
    expect(screen.getByText('已对齐')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /更新离线规则包/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /版本历史与回滚/ })).toBeInTheDocument()

    // 旧按钮不再作为一级主按钮直接暴露，而是收纳在「更多运维」下拉菜单中
    expect(screen.queryByRole('button', { name: /同步CRS规则/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /更多运维/ }))
    const syncItem = await screen.findByText('同步CRS规则', undefined, SLOW)
    fireEvent.click(syncItem)

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(([p, o]) => p === '/waf-rules/sync' && o?.method === 'POST'),
        ).toBe(true),
      SLOW,
    )
  })

  it('LEGACY_FLAT 模式：页头显示传统目录模式，打开更新抽屉展示 WAF_RULES_STORE_DIR 诊断告警并禁用上传', async () => {
    makeBaseMocks(
      makeCurrentStatus({
        storage_mode: 'LEGACY_FLAT',
        writable: false,
        active_pack: null,
        active_version: '',
        ha_sync_enabled: false,
        nodes: [
          {
            node_name: 'primary',
            role: 'PRIMARY',
            reachable: true,
            rulepack_ready: false,
            current_version: '',
            aligned: true,
          },
        ],
      }),
    )

    renderPage()
    expect(await screen.findByText('传统目录模式', undefined, SLOW)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /更新离线规则包/ }))
    expect(
      await screen.findByText(/当前未启用版本化规则包存储（LEGACY_FLAT 传统扁平模式）/, undefined, SLOW),
    ).toBeInTheDocument()
    expect(screen.getByText(/WAF_RULES_STORE_DIR/)).toBeInTheDocument()
    const fileInput = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')
    expect(fileInput).toBeDisabled()
  })

  it('HA 节点漂移态：展示「存在漂移」告警并支持打开漂移弹窗触发 retryNodeSync 补齐备机', async () => {
    const driftedStatus = makeCurrentStatus({
      drift_detected: true,
      nodes: [
        {
          node_name: 'gw-primary',
          role: 'PRIMARY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
        {
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          reachable: true,
          rulepack_ready: true,
          current_version: 'builtin-1.19.1',
          aligned: false,
          error: '备节点版本滞后',
        },
      ],
    })
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return driftedStatus
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'POST' && path === '/rule-packs/nodes/node-standby-1/retry-sync') {
        return { message: '节点规则包与配置已补齐同步' }
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })

    renderPage()
    expect(await screen.findByText('存在漂移', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('检测到 HA 备节点规则包版本存在漂移')).toBeInTheDocument()

    // 点击漂移横幅中的「查看与补齐」打开节点弹窗
    fireEvent.click(screen.getByRole('button', { name: '查看与补齐' }))
    expect(await screen.findByText('HA 节点规则包对齐状态与补齐同步', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('gw-standby')).toBeInTheDocument()

    const retryButtons = screen.getAllByRole('button', { name: /补齐同步/ })
    fireEvent.click(retryButtons[retryButtons.length - 1]!)

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(
            ([p, o]) => p === '/rule-packs/nodes/node-standby-1/retry-sync' && o?.method === 'POST',
          ),
        ).toBe(true),
      SLOW,
    )
  })

  it('两步式上传与一键应用闭环：展示真实上传进度 → 信任徽章/差异/策略预警 → 确认应用 → 轮询至 SUCCESS 并刷新规则库', async () => {
    const status = makeCurrentStatus()
    const verifiedPack = makeVerifiedPack()
    let pollCount = 0
    const jobRunning: RulePackJob = {
      id: 'job-apply-1',
      job_type: 'APPLY',
      target_pack_id: verifiedPack.id,
      target_version: '20261215.1',
      previous_version: '20261201.1',
      status: 'PUBLISHING',
      current_step: '校验并发布新规则集到网关',
      progress: 55,
      allow_degraded_ha: false,
      created_at: '2026-12-15T08:05:00Z',
      node_states: [
        {
          id: 'ns-1',
          job_id: 'job-apply-1',
          node_name: 'gw-primary',
          role: 'PRIMARY',
          stage_status: 'SUCCESS',
          load_status: 'PENDING',
          activate_status: 'PENDING',
          updated_at: '2026-12-15T08:05:05Z',
        },
        {
          id: 'ns-2',
          job_id: 'job-apply-1',
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          stage_status: 'SUCCESS',
          load_status: 'PENDING',
          activate_status: 'PENDING',
          updated_at: '2026-12-15T08:05:05Z',
        },
      ],
    }
    const jobSuccess: RulePackJob = {
      ...jobRunning,
      status: 'SUCCESS',
      current_step: '离线规则包已生效并完成规则库同步',
      progress: 100,
      publish_task_id: 'pub-12345678-aaaa-bbbb-cccc-1234567890ab',
      finished_at: '2026-12-15T08:05:20Z',
      sync_report: {
        total_parsed: 3120,
        total_in_db: 3120,
        added: 15,
        updated: 8,
        unchanged: 3097,
        missing: 0,
        parse_failed: 0,
        conflicts: 0,
        failed_rules: [],
      },
      node_states: jobRunning.node_states?.map((n) => ({
        ...n,
        stage_status: 'SUCCESS',
        load_status: 'SUCCESS',
        activate_status: 'SUCCESS',
      })),
    }

    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return status
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'POST' && path === `/rule-packs/${verifiedPack.id}/apply`) {
        return { ...jobRunning, status: 'STAGING_LOCAL', progress: 15, current_step: '主节点解包并校验规则快照' }
      }
      if (method === 'GET' && path === '/rule-packs/jobs/job-apply-1') {
        pollCount += 1
        return pollCount === 1 ? jobRunning : jobSuccess
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })

    let reportProgress: ((progress: UploadProgress) => void) | undefined
    let resolveUpload: ((pack: RulePackItem) => void) | undefined
    uploadMock.mockImplementation((_path, _form, options) => {
      reportProgress = options?.onProgress
      return new Promise((resolve) => {
        resolveUpload = resolve as (pack: RulePackItem) => void
      })
    })

    renderPage()
    await screen.findByText('20261201.1', undefined, SLOW)

    // 打开更新抽屉并拒绝非 .tar.gz 文件
    fireEvent.click(screen.getByRole('button', { name: /更新离线规则包/ }))
    await screen.findByText(/点击或拖拽纯离线规则包/, undefined, SLOW)
    const input = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')!
    fireEvent.change(input, { target: { files: [new File(['bad'], 'wrong.zip')] } })
    expect(await screen.findByText('仅支持 .tar.gz 格式的离线规则包', undefined, SLOW)).toBeInTheDocument()
    expect(uploadMock).not.toHaveBeenCalled()

    // 上传合法 .tar.gz 并推进上传进度 50% -> 100%（rc-upload 拒绝一次后会重置内部 input 元素，重新查询）
    const nextInput = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')!
    const packFile = new File(['tar-gz-bytes'], 'jiuzhang-wdsp-rulepack-20261215.1.tar.gz')
    fireEvent.change(nextInput, { target: { files: [packFile] } })
    await waitFor(() => expect(reportProgress).toBeDefined(), SLOW)
    expect(uploadMock.mock.calls[0]?.[0]).toBe('/rule-packs/upload')
    expect((uploadMock.mock.calls[0]?.[1].get('file') as File).name).toBe(packFile.name)

    act(() => reportProgress?.({ loaded: 512, total: 1024, lengthComputable: true }))
    expect(await screen.findByText('50%', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('正在上传：512 B / 1.00 KB')).toBeInTheDocument()

    act(() => reportProgress?.({ loaded: 1024, total: 1024, lengthComputable: true }))
    expect(
      await screen.findByText('规则包已上传，正在执行 Ed25519 验签、静态门禁与差异预检…', undefined, SLOW),
    ).toBeInTheDocument()

    // 上传完成，渲染验签信任徽章、变更差异、CVE、策略影响预警与节点就绪清单
    act(() => resolveUpload?.(verifiedPack))
    expect(await screen.findByText('Ed25519 签名已验证', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('文件完整性通过')).toBeInTheDocument()
    expect(screen.getByText('静态门禁通过')).toBeInTheDocument()
    expect(screen.getByText('版本兼容通过')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-109618')).toBeInTheDocument()
    expect(screen.getByText('新增 CVE-2026-109618 应急防护规则')).toBeInTheDocument()
    expect(screen.getByText(/策略影响预警：检测到 2 项客户规则覆盖或例外策略可能受影响/)).toBeInTheDocument()
    expect(screen.getByText(/系统绝不会自动修改您已配置的规则覆盖/)).toBeInTheDocument()
    expect(screen.getByText('规则覆盖 #942100 (DISABLE)')).toBeInTheDocument()
    expect(screen.getByText('支付回调例外')).toBeInTheDocument()

    // 记录应用前查询次数以验证成功后自动失效刷新
    const wafRulesCallsBefore = requestMock.mock.calls.filter(([p]) => p === '/waf-rules').length
    const currentCallsBefore = requestMock.mock.calls.filter(([p]) => p === '/rule-packs/current').length

    // Step 2：点击「确认应用到网关」并在 Popconfirm 中确认
    fireEvent.click(screen.getByRole('button', { name: /确认应用到网关/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认应用' }, SLOW))

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(
            ([p, o]) =>
              p === `/rule-packs/${verifiedPack.id}/apply` &&
              o?.method === 'POST' &&
              (o.body as Record<string, unknown>)?.allow_degraded_ha === false,
          ),
        ).toBe(true),
      SLOW,
    )

    // 轮询到达 SUCCESS，展示规则库自动同步汇总并刷新 ['waf-rules'] 与 ['rule-packs']
    expect(
      await screen.findByText(/离线规则包 20261215\.1 已生效并完成规则库自动同步/, undefined, SLOW),
    ).toBeInTheDocument()
    expect(
      screen.getByText(/新增 15 条、更新 8 条、未变 3097 条、库中共 3120 条/),
    ).toBeInTheDocument()
    expect(screen.getByText('节点执行明细（2 个节点）')).toBeInTheDocument()

    await waitFor(
      () =>
        expect(requestMock.mock.calls.filter(([p]) => p === '/waf-rules').length).toBeGreaterThan(
          wafRulesCallsBefore,
        ),
      SLOW,
    )
    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.filter(([p]) => p === '/rule-packs/current').length,
        ).toBeGreaterThan(currentCallsBefore),
      SLOW,
    )
  })

  it('应用失败展示：明确显示失败码、失败原因及「现网网关已保持原有规则版本」', async () => {
    const status = makeCurrentStatus()
    const verifiedPack = makeVerifiedPack()
    const failedJob: RulePackJob = {
      id: 'job-fail-1',
      job_type: 'APPLY',
      target_pack_id: verifiedPack.id,
      target_version: '20261215.1',
      previous_version: '20261201.1',
      status: 'FAILED',
      current_step: '执行失败（现网保持原版本）',
      progress: 55,
      allow_degraded_ha: false,
      failure_code: 'GATEWAY_PUBLISH_FAILED',
      failure_message: 'Coraza 编译校验失败：line 42 syntax error',
      created_at: '2026-12-15T08:05:00Z',
      finished_at: '2026-12-15T08:05:10Z',
      node_states: [],
    }
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return status
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'POST' && path === `/rule-packs/${verifiedPack.id}/apply`) {
        return { ...failedJob, status: 'PUBLISHING', failure_code: '', failure_message: '' }
      }
      if (method === 'GET' && path === '/rule-packs/jobs/job-fail-1') {
        return failedJob
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })
    uploadMock.mockResolvedValue(verifiedPack)

    renderPage()
    await screen.findByText('20261201.1', undefined, SLOW)
    fireEvent.click(screen.getByRole('button', { name: /更新离线规则包/ }))
    await screen.findByText(/点击或拖拽纯离线规则包/, undefined, SLOW)

    const input = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')!
    fireEvent.change(input, {
      target: { files: [new File(['bytes'], 'jiuzhang-wdsp-rulepack-20261215.1.tar.gz')] },
    })
    await screen.findByText('Ed25519 签名已验证', undefined, SLOW)

    fireEvent.click(screen.getByRole('button', { name: /确认应用到网关/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认应用' }, SLOW))

    expect(
      await screen.findByText(/任务执行失败：网关发布验证失败（GATEWAY_PUBLISH_FAILED）/, undefined, SLOW),
    ).toBeInTheDocument()
    expect(screen.getByText('Coraza 编译校验失败：line 42 syntax error')).toBeInTheDocument()
    expect(
      screen.getByText(/现网网关已保持原有规则版本（20261201\.1），业务流量未受影响/),
    ).toBeInTheDocument()
  })

  it('HA 备机不可达应急降级校验：默认禁用提交；展开降级开关后空原因拦截，填写原因后携带 allow_degraded_ha=true 提交', async () => {
    const standbyDownStatus = makeCurrentStatus({
      drift_detected: true,
      nodes: [
        {
          node_name: 'gw-primary',
          role: 'PRIMARY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
        {
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          reachable: false,
          rulepack_ready: false,
          current_version: '',
          aligned: false,
          error: 'connection refused',
        },
      ],
    })
    const packWithDownStandby = makeVerifiedPack({
      preview_report: {
        ...(makeVerifiedPack().preview_report as Record<string, unknown>),
        node_prechecks: standbyDownStatus.nodes,
      },
    })
    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return standbyDownStatus
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'POST' && path === `/rule-packs/${packWithDownStandby.id}/apply`) {
        return {
          id: 'job-degraded-1',
          job_type: 'APPLY',
          target_pack_id: packWithDownStandby.id,
          target_version: '20261215.1',
          previous_version: '20261201.1',
          status: 'SUCCESS',
          current_step: '离线规则包已生效并完成规则库同步',
          progress: 100,
          allow_degraded_ha: true,
          degraded_reason: '备机硬件维护断电，急需下发 0day 防护规则',
          created_at: '2026-12-15T08:05:00Z',
          node_states: [],
        }
      }
      if (method === 'GET' && path === '/rule-packs/jobs/job-degraded-1') {
        return {
          id: 'job-degraded-1',
          job_type: 'APPLY',
          target_pack_id: packWithDownStandby.id,
          target_version: '20261215.1',
          previous_version: '20261201.1',
          status: 'SUCCESS',
          current_step: '离线规则包已生效并完成规则库同步',
          progress: 100,
          allow_degraded_ha: true,
          degraded_reason: '备机硬件维护断电，急需下发 0day 防护规则',
          created_at: '2026-12-15T08:05:00Z',
          node_states: [],
        }
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })
    uploadMock.mockResolvedValue(packWithDownStandby)

    renderPage()
    await screen.findByText('20261201.1', undefined, SLOW)
    fireEvent.click(screen.getByRole('button', { name: /更新离线规则包/ }))
    await screen.findByText(/点击或拖拽纯离线规则包/, undefined, SLOW)

    const input = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')!
    fireEvent.change(input, {
      target: { files: [new File(['bytes'], 'jiuzhang-wdsp-rulepack-20261215.1.tar.gz')] },
    })
    await screen.findByText('检测到 HA 备节点不可达或未就绪', undefined, SLOW)

    // 默认 fail-closed：确认应用按钮不可用
    expect(screen.getByRole('button', { name: /确认应用到网关/ })).toBeDisabled()

    // 展开「应急降级：仅主节点生效」并打开开关
    fireEvent.click(screen.getByText('应急降级：仅主节点生效'))
    const sw = await screen.findByRole('switch', { name: '允许备机离线降级仅主节点生效' }, SLOW)
    expect(sw).toHaveAttribute('aria-checked', 'false')
    fireEvent.click(sw)

    // 降级原因为空时点击确认应用 -> 阻塞提交并给出校验提示
    fireEvent.click(screen.getByRole('button', { name: /确认应用到网关/ }))
    expect((await screen.findAllByText('开启应急降级时必须填写降级原因', undefined, SLOW)).length).toBeGreaterThan(0)
    expect(
      requestMock.mock.calls.some(([p]) => p === `/rule-packs/${packWithDownStandby.id}/apply`),
    ).toBe(false)

    // 填写降级原因并确认提交
    const textarea = screen.getByPlaceholderText(/必填：请填写应急降级原因/)
    fireEvent.change(textarea, { target: { value: '备机硬件维护断电，急需下发 0day 防护规则' } })
    fireEvent.click(screen.getByRole('button', { name: /确认应用到网关/ }))
    fireEvent.click(await screen.findByRole('button', { name: '确认应用' }, SLOW))

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(
            ([p, o]) =>
              p === `/rule-packs/${packWithDownStandby.id}/apply` &&
              o?.method === 'POST' &&
              (o.body as Record<string, unknown>)?.allow_degraded_ha === true &&
              (o.body as Record<string, unknown>)?.degraded_reason ===
                '备机硬件维护断电，急需下发 0day 防护规则',
          ),
        ).toBe(true),
      SLOW,
    )
    expect(await screen.findByText('HA 应急降级模式', undefined, SLOW)).toBeInTheDocument()
  })

  it('版本历史与一键回滚：展示历史列表、预检详情弹窗，确认回滚后轮询至 SUCCESS 并刷新规则库', async () => {
    const status = makeCurrentStatus()
    const historyPacks: RulePackItem[] = [
      status.active_pack!,
      {
        id: 'pack-prev',
        rulepack_version: '20261115.1',
        crs_version: '4.27.0',
        min_system_version: '1.19.0',
        coraza_compat: '>=3.7.0 <4.0.0',
        is_builtin: false,
        file_name: 'jiuzhang-wdsp-rulepack-20261115.1.tar.gz',
        file_size: 480000,
        file_sha256: 'e'.repeat(64),
        manifest_sha256: 'f'.repeat(64),
        status: 'SUPERSEDED',
        uploaded_at: '2026-11-15T08:00:00Z',
        applied_at: '2026-11-15T09:00:00Z',
        created_at: '2026-11-15T08:00:00Z',
        updated_at: '2026-12-01T09:00:00Z',
        can_rollback: true,
      },
      {
        id: 'pack-rejected',
        rulepack_version: '20261120.1',
        crs_version: '4.28.0',
        min_system_version: '1.19.1',
        coraza_compat: '',
        is_builtin: false,
        file_name: 'tampered.tar.gz',
        file_size: 1024,
        file_sha256: '1'.repeat(64),
        manifest_sha256: '2'.repeat(64),
        status: 'REJECTED',
        reject_reason: 'Ed25519 签名验证失败',
        uploaded_at: '2026-11-20T08:00:00Z',
        applied_at: null,
        created_at: '2026-11-20T08:00:00Z',
        updated_at: '2026-11-20T08:00:00Z',
        can_rollback: false,
      },
    ]

    let rollbackPollCount = 0
    const rollbackJobRunning: RulePackJob = {
      id: 'job-rb-1',
      job_type: 'ROLLBACK',
      target_pack_id: 'pack-prev',
      target_version: '20261115.1',
      previous_version: '20261201.1',
      status: 'PUBLISHING',
      current_step: '校验并发布回滚规则集到网关',
      progress: 55,
      allow_degraded_ha: false,
      created_at: '2026-12-15T10:00:00Z',
      node_states: [],
    }
    const rollbackJobSuccess: RulePackJob = {
      ...rollbackJobRunning,
      status: 'SUCCESS',
      current_step: '已回滚至目标规则包并完成规则库同步',
      progress: 100,
      finished_at: '2026-12-15T10:00:10Z',
      sync_report: {
        total_parsed: 3000,
        total_in_db: 3000,
        added: 0,
        updated: 5,
        unchanged: 2995,
        missing: 0,
        parse_failed: 0,
        conflicts: 0,
        failed_rules: [],
      },
    }

    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return status
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      if (method === 'GET' && path === '/rule-packs') {
        return { items: historyPacks, page: 1, page_size: 10, total: historyPacks.length }
      }
      if (method === 'GET' && path === '/rule-packs/pack-rejected') {
        return historyPacks[2]
      }
      if (method === 'POST' && path === '/rule-packs/pack-prev/rollback') {
        return rollbackJobRunning
      }
      if (method === 'GET' && path === '/rule-packs/jobs/job-rb-1') {
        rollbackPollCount += 1
        return rollbackPollCount === 1 ? rollbackJobRunning : rollbackJobSuccess
      }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })

    renderPage()
    await screen.findByText('20261201.1', undefined, SLOW)

    fireEvent.click(screen.getByRole('button', { name: /版本历史与回滚/ }))
    expect(await screen.findByText('20261115.1', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('已拒绝')).toBeInTheDocument()
    expect(screen.getByText('可回滚')).toBeInTheDocument()

    // 查看被拒绝包的预检详情弹窗
    const detailBtns = screen.getAllByRole('button', { name: /预检详情/ })
    fireEvent.click(detailBtns[2]!)
    expect(await screen.findByText('Ed25519 签名验证失败', undefined, SLOW)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '关 闭' }))

    const wafRulesCallsBefore = requestMock.mock.calls.filter(([p]) => p === '/waf-rules').length

    // 触发回滚并确认
    fireEvent.click(screen.getByRole('button', { name: /回滚到此版本/ }))
    expect(await screen.findByText('确认回滚离线规则包', undefined, SLOW)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /确认回滚/ }))

    await waitFor(
      () =>
        expect(
          requestMock.mock.calls.some(
            ([p, o]) => p === '/rule-packs/pack-prev/rollback' && o?.method === 'POST',
          ),
        ).toBe(true),
      SLOW,
    )
    expect(
      await screen.findByText(/已成功回滚至规则包 20261115\.1 并刷新网关与规则库/, undefined, SLOW),
    ).toBeInTheDocument()
    await waitFor(
      () =>
        expect(requestMock.mock.calls.filter(([p]) => p === '/waf-rules').length).toBeGreaterThan(
          wafRulesCallsBefore,
        ),
      SLOW,
    )
  })

  it('RBAC 只读用户（仅 waf_rules.read）：隐藏「更新离线规则包」「更多运维」「回滚到此版本」与漂移补齐操作，但可只读查看历史', async () => {
    useAuthStore.setState({
      user: makeUser(['waf_rules.read']),
      csrfToken: null,
      initialized: true,
    })

    const driftedStatus = makeCurrentStatus({
      drift_detected: true,
      nodes: [
        {
          node_name: 'gw-primary',
          role: 'PRIMARY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
        {
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          reachable: true,
          rulepack_ready: true,
          current_version: 'builtin-1.19.1',
          aligned: false,
        },
      ],
    })
    const historyPacks: RulePackItem[] = [
      {
        ...driftedStatus.active_pack!,
        id: 'pack-prev',
        rulepack_version: '20261115.1',
        status: 'SUPERSEDED',
        can_rollback: true,
      },
    ]

    requestMock.mockImplementation(async (path, options) => {
      const method = options?.method ?? 'GET'
      if (method === 'GET' && path === '/rule-packs/current') return driftedStatus
      if (method === 'GET' && path === '/rule-packs') {
        return { items: historyPacks, page: 1, page_size: 10, total: 1 }
      }
      if (method === 'GET' && path === '/waf-rules') return { items: [], page: 1, page_size: 20, total: 0 }
      if (method === 'GET' && path === '/waf-rules/categories') return { items: [] }
      if (method === 'GET' && path === '/waf-rules/versions') return { versions: ['4.28.0'] }
      throw new ApiError(`unexpected ${method} ${path}`, 'MOCK_MISS', 500)
    })

    renderPage()
    expect(await screen.findByText('20261201.1', undefined, SLOW)).toBeInTheDocument()

    // 隐藏需要 waf_rules.pack.manage / waf_rules.sync 的写操作入口，漂移态仅展示只读「查看节点」
    expect(screen.queryByRole('button', { name: /更新离线规则包/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /更多运维/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /补齐同步/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: '查看与补齐' })).not.toBeInTheDocument()

    // 打开漂移节点弹窗：只读视图展示备节点，但不出现「补齐同步」按钮
    const viewNodeBtns = screen.getAllByRole('button', { name: '查看节点' })
    expect(viewNodeBtns.length).toBeGreaterThanOrEqual(2)
    fireEvent.click(viewNodeBtns[0]!)
    expect(await screen.findByText('HA 节点规则包对齐状态与补齐同步', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByText('gw-standby')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /补齐同步/ })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: '关 闭' }))

    // 只读用户仍可打开版本历史查看，但不可看到「回滚到此版本」
    fireEvent.click(screen.getByRole('button', { name: /版本历史与回滚/ }))
    expect(await screen.findByText('20261115.1', undefined, SLOW)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /预检详情/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /回滚到此版本/ })).not.toBeInTheDocument()
  })

  it('硬阻塞优先于应急降级：脑裂与备机离线同时存在时，即使开启降级开关「确认应用到网关」仍保持禁用', async () => {
    const standbyDownStatus = makeCurrentStatus({
      drift_detected: true,
      nodes: [
        {
          node_name: 'gw-primary',
          role: 'PRIMARY',
          reachable: true,
          rulepack_ready: true,
          current_version: '20261201.1',
          aligned: true,
        },
        {
          node_id: 'node-standby-1',
          node_name: 'gw-standby',
          role: 'STANDBY',
          reachable: false,
          rulepack_ready: false,
          current_version: '',
          aligned: false,
          error: 'unreachable',
        },
      ],
    })
    const splitBrainPack = makeVerifiedPack({
      preview_report: {
        ...(makeVerifiedPack().preview_report as Record<string, unknown>),
        split_brain_detected: true,
        node_prechecks: standbyDownStatus.nodes,
      },
    })
    makeBaseMocks(standbyDownStatus)
    uploadMock.mockResolvedValue(splitBrainPack)

    renderPage()
    await screen.findByText('20261201.1', undefined, SLOW)
    fireEvent.click(screen.getByRole('button', { name: /更新离线规则包/ }))
    await screen.findByText(/点击或拖拽纯离线规则包/, undefined, SLOW)

    const input = document.querySelector<HTMLInputElement>('input[type="file"][accept=".tar.gz"]')!
    fireEvent.change(input, {
      target: { files: [new File(['bytes'], 'jiuzhang-wdsp-rulepack-20261215.1.tar.gz')] },
    })
    expect(
      await screen.findByText('检测到未处置的主备双主脑裂告警，禁止应用规则包', undefined, SLOW),
    ).toBeInTheDocument()

    // 即使展开应急降级并打开开关（空原因或非空原因），脑裂硬阻塞必须继续禁用提交按钮
    fireEvent.click(screen.getByText('应急降级：仅主节点生效'))
    const sw = await screen.findByRole('switch', { name: '允许备机离线降级仅主节点生效' }, SLOW)
    fireEvent.click(sw)
    expect(screen.getByRole('button', { name: /确认应用到网关/ })).toBeDisabled()
  })
})
