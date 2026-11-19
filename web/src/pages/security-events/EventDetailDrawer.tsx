import { useState } from 'react'
import type { CSSProperties } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  Alert,
  App as AntdApp,
  Button,
  Descriptions,
  Drawer,
  Empty,
  Input,
  List,
  Space,
  Tag,
  Tooltip,
  Typography,
} from 'antd'
import { Link } from 'react-router-dom'
import { ApiError } from '../../api/client'
import { securityEventsApi } from '../../api/securityEvents'
import RemediationCard from '../../components/RemediationCard'
import StatusTag from '../../components/StatusTag'
import VulnIdTags from '../../components/VulnIdTags'
import { useAuthStore } from '../../stores/auth'
import { useProductStore } from '../../stores/product'
import { buildEventApmTraceHref } from '../../utils/apm'
import { formatDateTime } from '../../utils/format'
import { DECISION_REASON_CODE_LABELS } from '../../utils/i18nLabels'
import { hasPermission } from '../../utils/permission'
import BlacklistFromEventModal from './BlacklistFromEventModal'
import {
  ATTACK_TYPE_META,
  DISPOSITION_STATUS_META,
  EVENT_ACTION_META,
  EVENT_SEVERITY_META,
} from '../../utils/stage4'
import {
  JWT_REASON_CODE_LABELS,
  JWT_UNVERIFIED_HINT,
  JWT_VERIFICATION_STATUS_META,
} from '../../utils/jwtTrust'
import type { FinalDecision, FinalDecisionStep, SecurityEventMatch } from '../../types'

const DISPOSITION_ACTION_META: Record<string, { color: string; label: string }> = {
  confirm_attack: { color: 'red', label: '确认攻击' },
  confirm_false_positive: { color: 'orange', label: '确认误报' },
  ignore: { color: 'default', label: '忽略' },
  resolve: { color: 'green', label: '标记已处置' },
  mark_analyzing: { color: 'processing', label: '标记分析中' },
  create_exception: { color: 'purple', label: '创建例外' },
}

/* ---------- P0-04：最终处置（final_decision，契约 S4 §2）展示元数据 ---------- */

/** 已执行安全动作（观察命中不进入 security_action） */
const FINAL_SECURITY_ACTION_META: Record<string, { color: string; label: string }> = {
  NONE: { color: 'green', label: '无安全动作' },
  BLOCK: { color: 'red', label: '阻断' },
  TEMP_BLOCK: { color: 'red', label: '临时封禁' },
  RATE_LIMIT: { color: 'orange', label: '限速' },
  MASK_RESPONSE: { color: 'gold', label: '响应脱敏' },
  CHALLENGE: { color: 'gold', label: 'Bot 挑战' },
}

/** 实际执行模块（固定枚举，S4 §2） */
const EXECUTOR_MODULE_META: Record<string, { color: string; label: string }> = {
  PROTECTED_ADDRESS: { color: 'geekblue', label: '保护地址' },
  MANUAL_BAN: { color: 'red', label: '人工临时封禁' },
  IP_ALLOWLIST: { color: 'green', label: 'IP 白名单' },
  IP_BLACKLIST: { color: 'red', label: 'IP 黑名单' },
  L7_ACL: { color: 'red', label: 'L7 访问控制' },
  AUTO_BAN: { color: 'red', label: '自动临时封禁' },
  RISK_POLICY: { color: 'orange', label: '身份风险策略' },
  LICENSE_QUOTA: { color: 'orange', label: '授权配额限速' },
  CC: { color: 'orange', label: 'CC 频率限制' },
  BOT: { color: 'gold', label: 'Bot 挑战' },
  JWT: { color: 'purple', label: 'JWT 信任链' },
  API: { color: 'purple', label: 'API 动态防护' },
  WAF: { color: 'red', label: 'WAF（Coraza/CRS）' },
  TRUNCATED: { color: 'default', label: '已截断' },
  NONE: { color: 'green', label: '无' },
  UNKNOWN: { color: 'default', label: '未知' },
}

const RESPONSE_SOURCE_META: Record<string, { color: string; label: string }> = {
  GATEWAY: { color: 'geekblue', label: '网关' },
  ORIGIN: { color: 'blue', label: '源站' },
  UNKNOWN: { color: 'default', label: '未知' },
}

const COMPLETION_STATUS_META: Record<string, { color: string; label: string }> = {
  COMPLETED: { color: 'green', label: '已完成' },
  ABORTED: { color: 'orange', label: '中断' },
  ERROR: { color: 'red', label: '错误' },
  PENDING_CORRELATION: { color: 'gold', label: '证据待关联' },
  UNKNOWN: { color: 'default', label: '未知' },
}

/** 步骤结果：区分 OBSERVED（仅观察）、EXCEPTED（因例外未执行）、SKIPPED（未运行） */
const STEP_RESULT_META: Record<string, { color: string; label: string }> = {
  EXECUTED: { color: 'red', label: '已执行' },
  OBSERVED: { color: 'gold', label: '仅观察' },
  EXCEPTED: { color: 'purple', label: '因例外未执行' },
  SKIPPED: { color: 'default', label: '未运行' },
}

/** 有界展示上限（与契约 steps ≤ 32、rule_refs ≤ 64 对齐；超出显式标注「已截断」） */
const FINAL_DECISION_STEPS_DISPLAY_LIMIT = 32
const FINAL_DECISION_RULE_REFS_DISPLAY_LIMIT = 64
const FINAL_DECISION_EVIDENCE_DISPLAY_LIMIT = 8

/** 最终处置区块（P0-04 §8 第一屏）：只展示已执行事实；API 中间决策单独一行，与最终处置区分 */
function FinalDecisionSection({ decision }: { decision: FinalDecision }) {
  const steps = decision.steps ?? []
  const shownSteps = steps.slice(0, FINAL_DECISION_STEPS_DISPLAY_LIMIT)
  const stepsTruncated = steps.length > FINAL_DECISION_STEPS_DISPLAY_LIMIT
  // API 中间决策（final_action 经步骤明细体现）：API ALLOW ≠ 最终放行（DEC 归因语义）
  const apiSteps = steps.filter((s) => s.module === 'API')
  const ruleRefs = decision.rule_refs ?? []
  const shownRuleRefs = ruleRefs.slice(0, FINAL_DECISION_RULE_REFS_DISPLAY_LIMIT)
  const ruleRefsTruncated = ruleRefs.length > FINAL_DECISION_RULE_REFS_DISPLAY_LIMIT
  const evidenceRefs = decision.evidence_refs ?? []
  const shownEvidence = evidenceRefs.slice(0, FINAL_DECISION_EVIDENCE_DISPLAY_LIMIT)

  return (
    <>
      <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
        <Descriptions.Item label="安全动作">
          <StatusTag value={decision.security_action ?? ''} map={FINAL_SECURITY_ACTION_META} />
        </Descriptions.Item>
        <Descriptions.Item label="执行模块">
          <StatusTag value={decision.executor_module ?? ''} map={EXECUTOR_MODULE_META} />
        </Descriptions.Item>
        <Descriptions.Item label="响应来源">
          <StatusTag value={decision.response_source ?? ''} map={RESPONSE_SOURCE_META} />
        </Descriptions.Item>
        <Descriptions.Item label="HTTP 状态">{decision.http_status ?? '-'}</Descriptions.Item>
        <Descriptions.Item label="完成状态">
          <StatusTag value={decision.completion_status ?? ''} map={COMPLETION_STATUS_META} />
        </Descriptions.Item>
        <Descriptions.Item label="响应已提交">
          {decision.response_committed === undefined || decision.response_committed === null
            ? '-'
            : decision.response_committed
              ? '是'
              : '否'}
        </Descriptions.Item>
        {apiSteps.length > 0 && (
          <Descriptions.Item label="API 中间决策" span={2}>
            <Space wrap size={4}>
              {apiSteps.map((s, i) => (
                <Tag key={`api-step-${i}`} color={STEP_RESULT_META[s.result ?? '']?.color}>
                  {`API ${STEP_RESULT_META[s.result ?? '']?.label ?? (s.result ?? '')}${s.detail ? `：${s.detail}` : ''}`}
                </Tag>
              ))}
            </Space>
            <div style={{ fontSize: 12, marginTop: 4 }}>
              <Typography.Text type="secondary">
                API 决策为中间结果：API 放行不等于最终放行，最终处置以本节安全动作为准
              </Typography.Text>
            </div>
          </Descriptions.Item>
        )}
        <Descriptions.Item label="原因码" span={2}>
          {(decision.reason_codes ?? []).length > 0 ? (
            <Space wrap size={4}>
              {(decision.reason_codes ?? []).map((c) => (
                <Tag key={c}>{DECISION_REASON_CODE_LABELS[c] ?? c}</Tag>
              ))}
            </Space>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="规则引用" span={2}>
          {ruleRefs.length > 0 ? (
            <>
              <Space wrap size={4}>
                {shownRuleRefs.map((r, i) => (
                  <Tag key={`${r.module ?? ''}-${r.rule_id ?? ''}-${i}`}>
                    {`${EXECUTOR_MODULE_META[r.module ?? '']?.label ?? (r.module ?? '')} ${r.rule_id ?? ''}${r.version ? `@${r.version}` : ''}`}
                  </Tag>
                ))}
              </Space>
              {ruleRefsTruncated && (
                <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
                  已截断：超出 {FINAL_DECISION_RULE_REFS_DISPLAY_LIMIT} 条规则引用未显示
                </Typography.Text>
              )}
            </>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="有效配置" span={2}>
          {decision.effective_config ? (
            <Space direction="vertical" size={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }}>
                配置指纹：{decision.effective_config.config_fingerprint || '-'}
              </Typography.Text>
              <Typography.Text style={{ fontSize: 12 }}>
                API 策略版本：{decision.effective_config.api_policy_version || '-'}
              </Typography.Text>
              {Object.entries(decision.effective_config.exception_versions ?? {}).length > 0 && (
                <Space wrap size={4}>
                  {Object.entries(decision.effective_config.exception_versions ?? {}).map(
                    ([id, v]) => (
                      <Tag key={id} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {`例外 ${id.slice(0, 8)}…:v${v}`}
                      </Tag>
                    ),
                  )}
                </Space>
              )}
            </Space>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="命中例外" span={2}>
          {(decision.matched_exceptions ?? []).length > 0 ? (
            <Space direction="vertical" size={4}>
              {(decision.matched_exceptions ?? []).map((m, i) => (
                <div key={`${m.exception_id ?? ''}-${i}`} style={{ fontSize: 12 }}>
                  <Typography.Text code>{m.exception_id ?? '-'}</Typography.Text>
                  {m.version !== undefined && <Tag>v{m.version}</Tag>}
                  {m.target && <Tag color="purple">{m.target}</Tag>}
                  {(m.rule_refs ?? []).map((r) => (
                    <Tag key={r}>{r}</Tag>
                  ))}
                  {m.scope_summary && (
                    <Typography.Text type="secondary"> {m.scope_summary}</Typography.Text>
                  )}
                  {(m.effective_from || m.effective_until) && (
                    <Typography.Text type="secondary" style={{ marginLeft: 4 }}>
                      {`（${m.effective_from ? formatDateTime(m.effective_from) : '-'} ~ ${m.effective_until ? formatDateTime(m.effective_until) : '永久'}）`}
                    </Typography.Text>
                  )}
                </div>
              ))}
            </Space>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="检测发现计数" span={2}>
          {decision.findings ? (
            <Space wrap size={4}>
              <Tag color="gold">仅观察 {decision.findings.observed ?? 0}</Tag>
              <Tag color="red">已执法 {decision.findings.enforced ?? 0}</Tag>
              <Tag color="purple">例外豁免 {decision.findings.excepted ?? 0}</Tag>
              <Tag>未运行 {decision.findings.skipped ?? 0}</Tag>
            </Space>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="证据关联" span={2}>
          {evidenceRefs.length > 0 ? (
            <>
              <Space wrap size={4}>
                {shownEvidence.map((e) => (
                  <Tag key={e} style={{ fontFamily: 'monospace', fontSize: 12 }}>
                    {e}
                  </Tag>
                ))}
              </Space>
              {evidenceRefs.length > FINAL_DECISION_EVIDENCE_DISPLAY_LIMIT && (
                <Typography.Text type="secondary" style={{ fontSize: 12, marginLeft: 8 }}>
                  已截断：超出 {FINAL_DECISION_EVIDENCE_DISPLAY_LIMIT} 条证据引用未显示
                </Typography.Text>
              )}
            </>
          ) : (
            '-'
          )}
        </Descriptions.Item>
        <Descriptions.Item label="完成时间">
          {decision.finalized_at ? formatDateTime(decision.finalized_at) : '-'}
        </Descriptions.Item>
        <Descriptions.Item label="网关节点">{decision.gateway_node || '-'}</Descriptions.Item>
      </Descriptions>
      {steps.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <Typography.Text strong style={{ fontSize: 13 }}>
            执行过程（{steps.length} 步）
          </Typography.Text>
          <div style={{ marginTop: 4, maxHeight: 240, overflow: 'auto' }}>
            {shownSteps.map((s: FinalDecisionStep, i) => (
              <div key={`step-${i}`} style={{ fontSize: 12, marginBottom: 4 }}>
                <Tag color={EXECUTOR_MODULE_META[s.module ?? '']?.color}>
                  {EXECUTOR_MODULE_META[s.module ?? '']?.label ?? (s.module ?? '-')}
                </Tag>
                <StatusTag value={s.result ?? ''} map={STEP_RESULT_META} />
                {s.detail && (
                  <Typography.Text type="secondary" style={{ marginLeft: 4 }}>
                    {s.detail}
                  </Typography.Text>
                )}
              </div>
            ))}
          </div>
          {stepsTruncated && (
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              已截断：超出 {FINAL_DECISION_STEPS_DISPLAY_LIMIT} 步未显示
            </Typography.Text>
          )}
        </div>
      )}
    </>
  )
}

/**
 * 规则匹配项渲染。
 * 安全要求：request_uri / matched_data 等攻击载荷一律作为 React 文本节点渲染
 * （React 默认转义），禁止使用 dangerouslySetInnerHTML。
 */
function MatchCard({ match }: { match: SecurityEventMatch }) {
  return (
    <div style={{ border: '1px solid #f0f0f0', borderRadius: 6, padding: 12, marginBottom: 8 }}>
      <Space wrap style={{ marginBottom: 8 }}>
        <Typography.Text code>{match.rule_id}</Typography.Text>
        <Typography.Text strong>{match.message || match.rule_name || '-'}</Typography.Text>
        <StatusTag value={match.severity} map={EVENT_SEVERITY_META} />
        <Tag>{`阶段 ${match.phase}`}</Tag>
      </Space>
      <div style={{ fontSize: 12, marginBottom: 4 }}>
        <Typography.Text type="secondary">匹配变量：</Typography.Text>
        <Typography.Text style={{ fontFamily: 'monospace' }}>
          {match.matched_variable || '-'}
        </Typography.Text>
      </div>
      <div style={{ fontSize: 12 }}>
        <Typography.Text type="secondary">匹配数据（已脱敏）：</Typography.Text>
        <pre
          style={{
            margin: '4px 0 0',
            background: '#f5f5f5',
            padding: 8,
            borderRadius: 4,
            fontSize: 12,
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}
        >
          {match.matched_data || '-'}
        </pre>
      </div>
      {(match.tags ?? []).length > 0 && (
        <Space wrap style={{ marginTop: 8 }}>
          {(match.tags ?? []).map((t) => (
            <Tag key={t}>{t}</Tag>
          ))}
        </Space>
      )}
      {/* CNNVD 兼容性 P1：命中规则标注的漏洞编号（有编号才显示；CNNVD 标签点击跳漏洞档案） */}
      {((match.cnnvd_ids ?? []).length > 0 || (match.cve_ids ?? []).length > 0) && (
        <Space wrap style={{ marginTop: 8 }} size={4}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            漏洞编号：
          </Typography.Text>
          <VulnIdTags cnnvdIds={match.cnnvd_ids} cveIds={match.cve_ids} linkCnnvd />
        </Space>
      )}
    </div>
  )
}

const preStyle: CSSProperties = {
  margin: '4px 0 0',
  background: '#f5f5f5',
  padding: 8,
  borderRadius: 4,
  fontSize: 12,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-all',
  maxHeight: 240,
  overflow: 'auto',
}

/** 头体留痕渲染：全部按纯文本渲染（React 默认转义），防 XSS */
function PayloadSection({
  title,
  headers,
  body,
  truncated,
}: {
  title: string
  headers?: Record<string, string[]> | null
  body?: string
  truncated?: boolean
}) {
  const headerEntries = Object.entries(headers ?? {}).sort(([a], [b]) => a.localeCompare(b))
  return (
    <div style={{ marginBottom: 12 }}>
      <Typography.Text strong>{title}</Typography.Text>
      {truncated && (
        <Tag color="orange" style={{ marginLeft: 8 }}>
          体已截断（64KB）
        </Tag>
      )}
      {headerEntries.length === 0 && !body ? (
        <div>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            无记录
          </Typography.Text>
        </div>
      ) : (
        <>
          {headerEntries.length > 0 && (
            <pre style={preStyle}>
              {headerEntries.map(([k, vs]) => `${k}: ${(vs ?? []).join(', ')}`).join('\n')}
            </pre>
          )}
          {body && <pre style={preStyle}>{body}</pre>}
        </>
      )}
    </div>
  )
}

export default function EventDetailDrawer({
  eventId,
  onClose,
  onSelectEvent,
}: {
  eventId: string | null
  onClose: () => void
  onSelectEvent: (id: string) => void
}) {
  const { message, modal } = AntdApp.useApp()
  const queryClient = useQueryClient()
  const permissions = useAuthStore((s) => s.user?.permissions)
  const canDispose = hasPermission(permissions, 'security_events.disposition')
  const canManageExceptions = hasPermission(permissions, 'exceptions.manage')
  const canManageAccessRules = hasPermission(permissions, 'access_rules.manage')
  const canAiAnalyze = hasPermission(permissions, 'ai.event_analysis.use')
  const canAiFp = hasPermission(permissions, 'ai.false_positive_analysis.use')
  const canNoiseReduction = hasPermission(permissions, 'ai.noise_reduction.use')
  // 「关联 Trace」跳转：需 APM 能力开启且持有 apm.traces.read（APM 设计 §17.2：事件一键打开同一 trace）
  const apmEnabled = useProductStore((s) => s.apmEnabled)
  const canApmTraces = apmEnabled && hasPermission(permissions, 'apm.traces.read')
  const [noteText, setNoteText] = useState('')
  const [blacklistOpen, setBlacklistOpen] = useState(false)

  const detailQuery = useQuery({
    queryKey: ['security-event', eventId],
    queryFn: () => securityEventsApi.get(eventId as string),
    enabled: eventId !== null,
  })

  const invalidateDetail = () => {
    void queryClient.invalidateQueries({ queryKey: ['security-event', eventId] })
    void queryClient.invalidateQueries({ queryKey: ['security-events'] })
  }

  const onError = (e: unknown) => {
    message.error(e instanceof ApiError ? e.message : '操作失败')
  }

  const dispositionMutation = useMutation({
    mutationFn: ({
      action,
      note,
    }: {
      action: 'confirm-attack' | 'confirm-false-positive' | 'ignore' | 'resolve' | 'mark-analyzing'
      note?: string
    }) => {
      const id = eventId as string
      const body = note ? { note } : {}
      const map = {
        'confirm-attack': securityEventsApi.confirmAttack,
        'confirm-false-positive': securityEventsApi.confirmFalsePositive,
        ignore: securityEventsApi.ignore,
        resolve: securityEventsApi.resolve,
        'mark-analyzing': securityEventsApi.markAnalyzing,
      } as const
      return map[action](id, body)
    },
    onSuccess: () => {
      setNoteText('')
      message.success('处置完成')
      invalidateDetail()
    },
    onError,
  })

  const noteMutation = useMutation({
    mutationFn: (note: string) => securityEventsApi.addNote(eventId as string, note),
    onSuccess: () => {
      setNoteText('')
      message.success('备注已添加')
      invalidateDetail()
    },
    onError,
  })

  const createExceptionMutation = useMutation({
    mutationFn: () => securityEventsApi.createException(eventId as string),
    onSuccess: (data) => {
      modal.success({
        title: '例外草稿已创建',
        content: (
          <div>
            <p>{data.message}</p>
            <Link to="/exceptions" onClick={onClose}>
              前往例外策略页面查看
            </Link>
          </div>
        ),
      })
      invalidateDetail()
    },
    onError,
  })

  const runDisposition = (
    action: 'confirm-attack' | 'confirm-false-positive' | 'ignore' | 'resolve' | 'mark-analyzing',
    label: string,
  ) => {
    const note = noteText.trim()
    modal.confirm({
      title: `${label}确认`,
      content: `确定将该事件${label}吗？${note ? '（附带备注）' : ''}`,
      onOk: () => dispositionMutation.mutate({ action, note: note || undefined }),
    })
  }

  const detail = detailQuery.data
  const evt = detail?.event
  // 「关联 Trace」跳转链接：携带 request_id、application_id（事件上有的话）、事件时间 ±5 分钟时间窗与站内返回地址
  // （P1-01 §5-1；occurred_at 非法时不生成链接，避免无时间窗的误导跳转）
  const apmTraceHref = evt ? buildEventApmTraceHref(evt) : null

  return (
    <Drawer
      title="安全事件详情"
      open={eventId !== null}
      onClose={onClose}
      width={720}
      destroyOnHidden={false}
    >
      {detailQuery.isLoading ? (
        <Typography.Text type="secondary">加载中...</Typography.Text>
      ) : detailQuery.isError ? (
        <Alert
          type="error"
          showIcon
          message="加载事件详情失败"
          description={detailQuery.error instanceof ApiError ? detailQuery.error.message : undefined}
        />
      ) : evt ? (
        <>
          {(canAiAnalyze || canAiFp || canNoiseReduction || (canApmTraces && apmTraceHref)) && eventId && (
            <Space style={{ marginBottom: 16 }} wrap>
              {canApmTraces && apmTraceHref && (
                <Link to={apmTraceHref} onClick={onClose}>
                  <Button>关联 Trace</Button>
                </Link>
              )}
              {canAiAnalyze && (
                <Link to={`/ai/event-analysis?event_id=${encodeURIComponent(eventId)}`} onClick={onClose}>
                  <Button type="primary">AI 事件分析</Button>
                </Link>
              )}
              {canAiFp && (
                <Link
                  to={`/ai/event-analysis?event_id=${encodeURIComponent(eventId)}&tab=fp`}
                  onClick={onClose}
                >
                  <Button>AI 误报研判</Button>
                </Link>
              )}
              {canNoiseReduction && (
                <Link to={`/ai/noise-reduction`} onClick={onClose}>
                  <Button>查看降噪簇</Button>
                </Link>
              )}
            </Space>
          )}
          <Typography.Title level={5}>事件概览</Typography.Title>
          <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="发生时间">{formatDateTime(evt.occurred_at)}</Descriptions.Item>
            <Descriptions.Item label="处置状态">
              <StatusTag value={evt.disposition_status} map={DISPOSITION_STATUS_META} />
            </Descriptions.Item>
            <Descriptions.Item label="攻击类型">
              <StatusTag value={evt.attack_type} map={ATTACK_TYPE_META} />
            </Descriptions.Item>
            <Descriptions.Item label="严重级别">
              <StatusTag value={evt.severity} map={EVENT_SEVERITY_META} />
            </Descriptions.Item>
            <Descriptions.Item label="动作">
              <StatusTag value={evt.action} map={EVENT_ACTION_META} />
            </Descriptions.Item>
            <Descriptions.Item label="异常评分">{evt.anomaly_score}</Descriptions.Item>
            <Descriptions.Item label="应用">
              {evt.application_name_snapshot || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="域名">{evt.domain || '-'}</Descriptions.Item>
            <Descriptions.Item label="客户端 IP">{evt.client_ip || '-'}</Descriptions.Item>
            <Descriptions.Item label="网关节点">{evt.gateway_node_id || '-'}</Descriptions.Item>
            <Descriptions.Item label="响应状态码">{evt.response_status || '-'}</Descriptions.Item>
            <Descriptions.Item label="规则匹配数">{evt.rule_match_count}</Descriptions.Item>
          </Descriptions>

          {/* 最终处置（WDSP P0-04 §8，第一屏）：实际执行动作/执行模块/原因/规则与有效配置版本/响应来源；
              历史事件无 final_decision（不回填）时显示空态说明，不用空图 */}
          <Typography.Title level={5}>最终处置</Typography.Title>
          {evt.final_decision ? (
            <FinalDecisionSection decision={evt.final_decision} />
          ) : (
            <div style={{ marginBottom: 16 }}>
              <Typography.Text type="secondary">
                该事件无最终处置记录（旧数据）
              </Typography.Text>
            </div>
          )}

          {/* JWT 验证信息（WDSP P0-03 §8）：历史事件无此字段时显示「当时未记录」；
              UNVERIFIED 表示策略关闭/不在校验范围，不渲染为「非法用户」 */}
          <Typography.Title level={5}>JWT 验证信息</Typography.Title>
          {evt.jwt_verification ? (
            <>
              <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
                <Descriptions.Item label="验证状态">
                  <StatusTag value={evt.jwt_verification.status} map={JWT_VERIFICATION_STATUS_META} />
                </Descriptions.Item>
                <Descriptions.Item label="原因">
                  {evt.jwt_verification.reason_code ? (
                    <Tooltip title={`原因码：${evt.jwt_verification.reason_code}`}>
                      <Typography.Text>
                        {JWT_REASON_CODE_LABELS[evt.jwt_verification.reason_code] ??
                          evt.jwt_verification.reason_code}
                      </Typography.Text>
                    </Tooltip>
                  ) : (
                    '-'
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="可信主体指纹" span={2}>
                  {evt.jwt_verification.verified_principal_id ? (
                    <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                      {evt.jwt_verification.verified_principal_id}
                    </Typography.Text>
                  ) : (
                    '-'
                  )}
                </Descriptions.Item>
                <Descriptions.Item label="策略版本">
                  {evt.jwt_verification.policy_version ?? '-'}
                </Descriptions.Item>
                <Descriptions.Item label="签发方配置">
                  {evt.jwt_verification.issuer_config_id || '-'}
                </Descriptions.Item>
                <Descriptions.Item label="密钥集版本">
                  {evt.jwt_verification.keyset_version || '-'}
                </Descriptions.Item>
                <Descriptions.Item label="验证时间">
                  {evt.jwt_verification.evaluated_at
                    ? formatDateTime(evt.jwt_verification.evaluated_at)
                    : '-'}
                </Descriptions.Item>
              </Descriptions>
              {evt.jwt_verification.status === 'UNVERIFIED' && (
                <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginTop: -8, marginBottom: 16 }}>
                  {JWT_UNVERIFIED_HINT}
                </Typography.Paragraph>
              )}
            </>
          ) : (
            <div style={{ marginBottom: 16 }}>
              <Typography.Text type="secondary">
                当时未记录 JWT 验证信息（历史事件或未启用 JWT 信任策略）
              </Typography.Text>
            </div>
          )}

          <Typography.Title level={5}>请求信息</Typography.Title>
          <Descriptions column={2} size="small" bordered style={{ marginBottom: 16 }}>
            <Descriptions.Item label="请求 ID" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12 }} copyable>
                {evt.request_id}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="方法">{evt.request_method}</Descriptions.Item>
            <Descriptions.Item label="HTTP 版本">{evt.http_version || '-'}</Descriptions.Item>
            {/* 攻击载荷字段：纯文本渲染，React 自动转义，防 XSS */}
            <Descriptions.Item label="请求 URI" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {evt.request_uri || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="查询摘要" span={2}>
              <Typography.Text style={{ fontFamily: 'monospace', fontSize: 12, wordBreak: 'break-all' }}>
                {evt.query_summary || '-'}
              </Typography.Text>
            </Descriptions.Item>
            <Descriptions.Item label="内容类型">{evt.content_type || '-'}</Descriptions.Item>
            <Descriptions.Item label="客户端端口">{evt.client_port || '-'}</Descriptions.Item>
            <Descriptions.Item label="用户代理" span={2}>
              {evt.user_agent_summary || '-'}
            </Descriptions.Item>
            <Descriptions.Item label="来源地址" span={2}>
              {evt.referer_summary || '-'}
            </Descriptions.Item>
          </Descriptions>

          <Typography.Title level={5}>请求/响应留痕</Typography.Title>
          <PayloadSection
            title="请求头"
            headers={evt.request_headers}
          />
          <PayloadSection
            title="请求体"
            body={evt.request_body}
            truncated={evt.request_body_truncated}
          />
          <PayloadSection
            title="响应头"
            headers={evt.response_headers}
          />
          <PayloadSection
            title="响应体"
            body={evt.response_body}
            truncated={evt.response_body_truncated}
          />

          <Typography.Title level={5}>规则匹配（{detail?.matches.length ?? 0}）</Typography.Title>
          {(detail?.matches ?? []).length === 0 ? (
            <Empty description="无规则匹配明细" style={{ marginBottom: 16 }} />
          ) : (
            <div style={{ marginBottom: 16, maxHeight: 360, overflow: 'auto' }}>
              {(detail?.matches ?? []).map((m, i) => (
                <MatchCard key={`${m.rule_id}-${i}`} match={m} />
              ))}
            </div>
          )}

          {eventId && <RemediationCard eventId={eventId} />}

          <Typography.Title level={5}>处置记录（{detail?.actions.length ?? 0}）</Typography.Title>
          {(detail?.actions ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无处置记录</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.actions ?? []}
              renderItem={(a) => (
                <List.Item>
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    <Space>
                      <StatusTag
                        value={a.action_type}
                        map={DISPOSITION_ACTION_META}
                      />
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {a.operator_name} · {formatDateTime(a.created_at)}
                      </Typography.Text>
                    </Space>
                    {a.detail && (
                      <Typography.Text style={{ fontSize: 12 }}>{a.detail}</Typography.Text>
                    )}
                  </Space>
                </List.Item>
              )}
            />
          )}

          <Typography.Title level={5}>备注（{detail?.notes.length ?? 0}）</Typography.Title>
          {(detail?.notes ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无备注</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.notes ?? []}
              renderItem={(n) => (
                <List.Item>
                  <Space direction="vertical" size={2} style={{ width: '100%' }}>
                    <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                      {n.username} · {formatDateTime(n.created_at)}
                    </Typography.Text>
                    <Typography.Text style={{ fontSize: 12, whiteSpace: 'pre-wrap' }}>
                      {n.note}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}

          <Typography.Title level={5}>相关事件（{detail?.related.length ?? 0}）</Typography.Title>
          {detail?.related_mode === 'attack_session' && (
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
              同一攻击会话 · 按攻击时间线排列
              {detail.related_session_id && (
                <>
                  {' · '}
                  <Link to={`/attack-sessions/${detail.related_session_id}`} onClick={onClose}>
                    查看攻击活动
                  </Link>
                </>
              )}
            </Typography.Paragraph>
          )}
          {detail?.related_mode === 'same_source_ip' && (
            <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 8 }}>
              同一来源 IP · 前后 24 小时
            </Typography.Paragraph>
          )}
          {(detail?.related ?? []).length === 0 ? (
            <Typography.Text type="secondary">暂无相关事件</Typography.Text>
          ) : (
            <List
              size="small"
              style={{ marginBottom: 16 }}
              dataSource={detail?.related ?? []}
              renderItem={(r) => (
                <List.Item
                  role="button"
                  tabIndex={0}
                  style={{ cursor: 'pointer' }}
                  onClick={() => onSelectEvent(r.id)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onSelectEvent(r.id)
                    }
                  }}
                >
                  <Space direction="vertical" size={2}>
                    <Space>
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        {formatDateTime(r.occurred_at)}
                      </Typography.Text>
                      <StatusTag value={r.attack_type} map={ATTACK_TYPE_META} />
                      <StatusTag value={r.severity} map={EVENT_SEVERITY_META} />
                      <StatusTag value={r.action} map={EVENT_ACTION_META} />
                    </Space>
                    <Typography.Text style={{ fontSize: 12, fontFamily: 'monospace' }}>
                      {r.client_ip} {r.request_method} {r.request_uri}
                    </Typography.Text>
                  </Space>
                </List.Item>
              )}
            />
          )}

          {(canDispose || canManageExceptions || canManageAccessRules) && (
            <>
              <Typography.Title level={5}>处置操作</Typography.Title>
              <Space direction="vertical" style={{ width: '100%' }}>
                <Input.TextArea
                  rows={2}
                  maxLength={1000}
                  placeholder="处置备注（可选，随处置动作一并记录；也可单独添加备注）"
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                />
                {canDispose && (
                  <Space wrap>
                    <Button
                      danger
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('confirm-attack', '确认为真实攻击')}
                    >
                      确认攻击
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('confirm-false-positive', '确认为误报')}
                    >
                      确认误报
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('ignore', '忽略')}
                    >
                      忽略
                    </Button>
                    <Button
                      type="primary"
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('resolve', '标记为已处置')}
                    >
                      标记已处置
                    </Button>
                    <Button
                      loading={dispositionMutation.isPending}
                      onClick={() => runDisposition('mark-analyzing', '标记为分析中')}
                    >
                      标记分析中
                    </Button>
                    <Button
                      loading={noteMutation.isPending}
                      onClick={() => {
                        const note = noteText.trim()
                        if (!note) {
                          message.warning('请先填写备注内容')
                          return
                        }
                        noteMutation.mutate(note)
                      }}
                    >
                      添加备注
                    </Button>
                  </Space>
                )}
                {canManageExceptions && (
                  <Button
                    loading={createExceptionMutation.isPending}
                    onClick={() =>
                      modal.confirm({
                        title: '从事件创建例外草稿',
                        content: '将基于该事件的域名、URI 与匹配规则生成例外草稿（停用前的草稿需到例外策略页面审核）。确定继续吗？',
                        onOk: () => createExceptionMutation.mutate(),
                      })
                    }
                  >
                    从事件创建例外草稿
                  </Button>
                )}
                {canManageAccessRules && evt.client_ip && (
                  <Button danger onClick={() => setBlacklistOpen(true)}>
                    加入黑名单
                  </Button>
                )}
              </Space>
            </>
          )}
        </>
      ) : null}
      <BlacklistFromEventModal
        eventId={blacklistOpen ? eventId : null}
        onClose={() => setBlacklistOpen(false)}
      />
    </Drawer>
  )
}
