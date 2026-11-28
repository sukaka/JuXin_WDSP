import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { App as AntdApp, ConfigProvider } from 'antd'
import zhCN from 'antd/locale/zh_CN'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import ProtectionPoliciesPage from '../ProtectionPoliciesPage'
import { useAuthStore } from '../../../stores/auth'
import type { CurrentUser } from '../../../types'

function makeUser(permissions: string[]): CurrentUser {
  return {
    id: 'u1',
    username: 'sec',
    display_name: '安全管理员',
    status: 'ACTIVE',
    roles: [{ code: 'SECURITY_ADMIN', name: '安全管理员' }],
    permissions,
    must_change_password: false,
  }
}

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

const POLICY_ITEM = {
  id: 'pol-1',
  code: 'default-observe',
  name: '默认观察策略',
  description: '基础防护',
  is_builtin: false,
  status: 'ACTIVE',
  protection_mode: 'OBSERVE',
  paranoia_level: 1,
  inbound_anomaly_threshold: 5,
  outbound_anomaly_threshold: 4,
  request_body_access: true,
  response_body_access: false,
  blocking_status_code: 403,
  usage_count: 0,
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-01T00:00:00Z',
  version: 1,
}

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ConfigProvider locale={zhCN}>
        <AntdApp>
          <ProtectionPoliciesPage />
        </AntdApp>
      </ConfigProvider>
    </QueryClientProvider>,
  )
}

describe('ProtectionPoliciesPage 防护策略', () => {
  let detailAppIds: string[] | null
  let detailDomains: Array<{
    id: string
    application_id: string
    application_code: string
    application_name: string
    hostname: string
  }> | null
  let createCalls: unknown[]

  beforeEach(() => {
    detailAppIds = null
    detailDomains = null
    createCalls = []
    useAuthStore.setState({
      user: makeUser([
        'protection_policies.read',
        'protection_policies.create',
        'protection_policies.update',
        'protection_policies.delete',
      ]),
      csrfToken: null,
      initialized: true,
    })

    vi.stubGlobal(
      'fetch',
      vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input)
        const method = init?.method ?? 'GET'
        if (method === 'POST' && url.endsWith('/protection-policies')) {
          const body = JSON.parse(String(init?.body))
          createCalls.push(body)
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...POLICY_ITEM, ...body, id: 'pol-new' },
            }),
          )
        }
        if (method === 'GET' && url.includes('/protection-policies/pol-1/content')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                policy_id: 'pol-1',
                policy_code: 'default-observe',
                policy_name: '默认观察策略',
                protection_mode: 'OBSERVE',
                sec_rule_engine: 'DetectionOnly',
                paranoia_level: 1,
                inbound_anomaly_threshold: 5,
                outbound_anomaly_threshold: 4,
                generated_directives:
                  'SecRuleEngine DetectionOnly\nInclude /etc/caddy/rules/coraza.conf\nSecAction "id:900001,phase:1,pass,nolog,setvar:tx.blocking_paranoia_level=1,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"',
                loaded_rule_files: [
                  { order: 1, path: '/etc/caddy/rules/coraza.conf', description: 'Coraza 基础配置' },
                ],
                summary: {
                  total_rules: 2,
                  active_rules: 1,
                  disabled_by_override: 0,
                  skipped_by_pl: 1,
                  mode_off_rules: 0,
                  custom_rules_count: 1,
                  global_exceptions_count: 0,
                  overrides_count: 0,
                },
                overrides: [],
                custom_rules: [
                  {
                    rule_id: 7100001,
                    name: '阻断测试特征',
                    attack_type: 'OTHER',
                    severity: 'WARNING',
                    phase: 2,
                    action: 'BLOCK',
                    generated_rule: 'SecRule ARGS "@rx bad" "id:7100001,phase:2,deny"',
                  },
                ],
                global_exceptions: [],
                rules: [
                  {
                    rule_id: 901164,
                    name: '初始化：默认受限文件扩展名清单',
                    description: '初始化默认禁止直接访问的敏感文件扩展名清单，供规则 920440 校验。',
                    detail: {
                      rule_type: 'INTERNAL',
                      rule_type_label: '引擎内部控制规则',
                      source: 'BUILTIN',
                      source_label: '内置中文规则库',
                      summary: '初始化默认禁止直接访问的敏感文件扩展名清单，供规则 920440 校验。',
                      detection_logic: '在阶段 1 检查受限文件扩展名配置变量是否未定义；未定义时写入默认清单。',
                      risk_impact: '属于引擎变量初始化规则，不直接拦截请求，用于为扩展名限制提供默认清单。',
                      tuning_advice: '通常不应手动停用；如需放行特定扩展名请通过例外或覆盖调整规则 920440。',
                      phase_description: '阶段 1（请求头检查）：在接收完整 HTTP 请求头后执行',
                      paranoia_level: '无条件执行（引擎内部流程控制）',
                      action_behavior: '内部变量赋值（初始化或汇总引擎事务变量，不阻断、不记日志）',
                      targets: ['数量统计：受限文件扩展名配置（TX:restricted_extensions）'],
                      references: [],
                    },
                    attack_type: 'OTHER',
                    severity: 'NOTICE',
                    phase: 1,
                    rule_source: 'OWASP_CRS',
                    file_name: 'REQUEST-901-INITIALIZATION.conf',
                    paranoia_level: 0,
                    effective_status: 'ACTIVE',
                    raw_rule: 'SecRule &TX:restricted_extensions "@eq 0" "id:901164,phase:1,pass,nolog"',
                  },
                  {
                    rule_id: 942100,
                    name: 'SQL 注入检测',
                    attack_type: 'SQL_INJECTION',
                    severity: 'CRITICAL',
                    phase: 2,
                    rule_source: 'OWASP_CRS',
                    file_name: 'REQUEST-942-APPLICATION-ATTACK-SQLI.conf',
                    paranoia_level: 1,
                    effective_status: 'ACTIVE',
                    raw_rule: 'SecRule ARGS "@detectSQLi" "id:942100,phase:2,block"',
                  },
                ],
                rules_total: 2,
                page: 1,
                page_size: 20,
              },
            }),
          )
        }
        if (method === 'GET' && url.includes('/protection-policies/pol-1')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { ...POLICY_ITEM, application_ids: detailAppIds, domains: detailDomains },
            }),
          )
        }
        if (method === 'GET' && url.includes('/protection-policies')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: { items: [POLICY_ITEM], page: 1, page_size: 20, total: 1 },
            }),
          )
        }
        if (method === 'GET' && url.includes('/applications')) {
          return Promise.resolve(
            jsonResponse(200, {
              code: 'SUCCESS',
              message: 'ok',
              data: {
                items: [{ id: 'app-1', name: '商城主站', code: 'shop' }],
                page: 1,
                page_size: 100,
                total: 1,
              },
            }),
          )
        }
        return Promise.reject(new Error(`unexpected url: ${url} (${method})`))
      }),
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    useAuthStore.getState().reset()
  })

  it('新建策略表单限制入站/出站异常阈值为 1–100，越界输入被截断且合法边界可提交', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建策略/ }))

    const inboundInput = (await screen.findByLabelText(
      '入站异常阈值',
    )) as HTMLInputElement
    const outboundInput = screen.getByLabelText(
      '出站异常阈值',
    ) as HTMLInputElement

    expect(inboundInput).toHaveAttribute('aria-valuemin', '1')
    expect(inboundInput).toHaveAttribute('aria-valuemax', '100')
    expect(outboundInput).toHaveAttribute('aria-valuemin', '1')
    expect(outboundInput).toHaveAttribute('aria-valuemax', '100')
    expect(screen.getByText(/范围 1–100；请求异常评分/)).toBeInTheDocument()
    expect(screen.getByText(/范围 1–100；响应异常评分/)).toBeInTheDocument()

    // AntD InputNumber 带 min/max 时，失焦会将越界值截断到 100 / 1，不会把 >100 的值提交给后端
    fireEvent.change(inboundInput, { target: { value: '150' } })
    fireEvent.blur(inboundInput)
    await waitFor(() => expect(inboundInput.value).toBe('100'))

    fireEvent.change(outboundInput, { target: { value: '120' } })
    fireEvent.blur(outboundInput)
    await waitFor(() => expect(outboundInput.value).toBe('100'))

    fireEvent.change(screen.getByLabelText('策略编码'), {
      target: { value: 'strict-web' },
    })
    fireEvent.change(screen.getByLabelText('策略名称'), {
      target: { value: '严格防护' },
    })
    fireEvent.change(inboundInput, { target: { value: '100' } })
    fireEvent.change(outboundInput, { target: { value: '1' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => expect(createCalls).toHaveLength(1))
    expect(createCalls[0]).toMatchObject({
      code: 'strict-web',
      name: '严格防护',
      inbound_anomaly_threshold: 100,
      outbound_anomaly_threshold: 1,
    })
  })

  it('小数输入（5.5 / 1.5）失焦时由 precision=0 约束为整数，未失焦原始小数被整数校验拦截且不提交 POST', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /新建策略/ }))

    const inboundInput = (await screen.findByLabelText(
      '入站异常阈值',
    )) as HTMLInputElement
    const outboundInput = screen.getByLabelText(
      '出站异常阈值',
    ) as HTMLInputElement

    fireEvent.change(screen.getByLabelText('策略编码'), {
      target: { value: 'decimal-guard' },
    })
    fireEvent.change(screen.getByLabelText('策略名称'), {
      target: { value: '小数防护测试' },
    })

    // 1) 未失焦直接提交原始小数：Form 整数校验器拦截并显示「请输入整数」，不触发 POST /protection-policies
    fireEvent.change(inboundInput, { target: { value: '5.5' } })
    fireEvent.change(outboundInput, { target: { value: '1.5' } })
    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))

    await waitFor(() => expect(screen.getAllByText('请输入整数')).toHaveLength(2))
    expect(createCalls).toHaveLength(0)

    // 2) 失焦后 AntD InputNumber precision={0} 自动四舍五入为整数，随后可合法提交整数给后端
    fireEvent.blur(inboundInput)
    fireEvent.blur(outboundInput)
    await waitFor(() => expect(inboundInput.value).toBe('6'))
    await waitFor(() => expect(outboundInput.value).toBe('2'))

    fireEvent.click(screen.getByRole('button', { name: /确\s*定/ }))
    await waitFor(() => expect(createCalls).toHaveLength(1))
    expect(createCalls[0]).toMatchObject({
      code: 'decimal-guard',
      name: '小数防护测试',
      inbound_anomaly_threshold: 6,
      outbound_anomaly_threshold: 2,
    })
  })

  it('策略详情抽屉对 application_ids=null 安全归一化为 0 个绑定应用', async () => {
    detailAppIds = null
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    expect(await screen.findByText('绑定应用（0）')).toBeInTheDocument()
    expect(screen.getByText('暂无应用绑定该策略')).toBeInTheDocument()
  })

  it('策略详情抽屉展示已绑定的应用名称与域名列表', async () => {
    detailAppIds = ['app-1']
    detailDomains = [
      {
        id: 'dom-1',
        application_id: 'app-1',
        application_code: 'shop',
        application_name: '商城主站',
        hostname: 'jxdr.cn',
      },
    ]
    renderPage()

    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    expect(await screen.findByText('绑定应用（1）')).toBeInTheDocument()
    expect(await screen.findByText('商城主站')).toBeInTheDocument()
    expect(screen.getByText('绑定域名（1）')).toBeInTheDocument()
    expect(screen.getByText('jxdr.cn')).toBeInTheDocument()
  })

  it('策略详情抽屉可切换查看生效 SecLang 指令与生效规则清单', async () => {
    renderPage()
    fireEvent.click(await screen.findByRole('button', { name: /详\s*情/ }))
    await screen.findByText('绑定应用（0）')

    fireEvent.click(screen.getByRole('tab', { name: '生效指令（SecLang）' }))
    expect((await screen.findAllByText(/SecRuleEngine DetectionOnly/)).length).toBeGreaterThanOrEqual(2)
    expect(screen.getByText(/Include \/etc\/caddy\/rules\/coraza\.conf/)).toBeInTheDocument()
    expect(screen.getByText(/tx\.blocking_paranoia_level=1/)).toBeInTheDocument()
    expect(screen.getByText('阻断测试特征')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('tab', { name: '生效规则清单' }))
    expect(await screen.findByText('初始化：默认受限文件扩展名清单')).toBeInTheDocument()
    expect(screen.getByText('SQL 注入检测')).toBeInTheDocument()
    expect(screen.getByText('942100')).toBeInTheDocument()

    // 展开 901164 行，验证中文规则说明卡片与原始 SecRule 原文一并展示
    const expandButtons = screen.getAllByRole('button', { name: '展开行' })
    fireEvent.click(expandButtons[0])
    expect(await screen.findByText('规则中文说明')).toBeInTheDocument()
    expect(screen.getByText('引擎内部控制规则')).toBeInTheDocument()
    expect(
      screen.getByText('初始化默认禁止直接访问的敏感文件扩展名清单，供规则 920440 校验。'),
    ).toBeInTheDocument()
    expect(screen.getByText('原始 SecRule 原文')).toBeInTheDocument()
    expect(
      screen.getByText('数量统计：受限文件扩展名配置（TX:restricted_extensions）'),
    ).toBeInTheDocument()
    expect(screen.getByText(/SecRule &TX:restricted_extensions/)).toBeInTheDocument()
  })
})
